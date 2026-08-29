<?php

declare(strict_types=1);

namespace Padosoft\Rebel\AiGuard\Detection;

use DateTimeInterface;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Database\DatabaseManager;
use Padosoft\Rebel\AiGuard\Enums\AnomalyType;
use Padosoft\Rebel\AiGuard\Enums\Severity;
use Padosoft\Routines\Contracts\Lifecycle\RoutineLifecycle;

/**
 * Regole deterministiche sullo stream delle ROUTINE (`routine_runs` di laravel-routines).
 *
 * Le anomalie della delega riguardano un agente che chiede autorità; queste riguardano
 * un'automazione che gira quando non c'è nessuno a guardarla — ed è una categoria di guasto
 * diversa, perché il sintomo non è un rifiuto ma il silenzio. Le quattro regole coprono i quattro
 * modi in cui quel silenzio è una brutta notizia:
 *
 * - `fire_burst`: parte troppo spesso. Una routine a cron non può superare il proprio orario, ma
 *   una innescata da evento o webhook sì: un emettitore impazzito, o consegne rigiocate che
 *   passano la firma perché ognuna ha un id di consegna diverso, e l'idempotenza — correttamente —
 *   le considera fatti distinti.
 * - `failure_loop`: fallisce sempre. Il motore ritenta con backoff dentro una singola occorrenza e
 *   poi si arrende; l'occorrenza successiva ricomincia da zero. Nessuno guarda ATTRAVERSO le
 *   occorrenze, quindi una routine che fallisce ogni ora da una settimana non lo dice a nessuno.
 * - `approval_starvation`: si è fermata a chiedere e nessuno ha risposto. È il guasto peggiore del
 *   sistema, ed è invisibile per costruzione: la routine si comporta esattamente come deve — non
 *   agisce senza permesso — e proprio per questo non produce nessun errore da nessuna parte.
 * - `mandate_probing`: continua a incontrare il confine del mandato. Anche quando le risposte
 *   arrivano, un flusso costante di pause significa che il consenso concesso non descrive più ciò
 *   che la routine fa davvero, e va rinegoziato invece che approvato una volta al giorno.
 *
 * Le tabelle appartengono a laravel-routines: se non sono in questo database le regole vengono
 * saltate in silenzio, e un'installazione rebel-only resta intatta.
 */
final readonly class RoutineRules
{
    public function __construct(
        private DatabaseManager $db,
        private Repository $config,
        private CaseWriter $cases,
    ) {}

    public function detect(DateTimeInterface $from, DateTimeInterface $to): int
    {
        $connection = $this->db->connection();
        $schema = $connection->getSchemaBuilder();
        if (! $schema->hasTable('routine_runs') || ! $schema->hasTable('routines')) {
            return 0;
        }

        return $this->fireBurst($from, $to)
            + $this->failureLoop($from, $to)
            + $this->mandateProbing($from, $to)
            + $this->approvalStarvation($to);
    }

    /** Troppi fire nella finestra, qualunque sia stato l'esito. */
    private function fireBurst(DateTimeInterface $from, DateTimeInterface $to): int
    {
        return $this->countRule(
            $from,
            $to,
            outcomes: null,
            threshold: $this->intConfig('routines.fire_burst.threshold', 200),
            type: AnomalyType::RoutineFireBurst,
            dedupePrefix: 'routine_fire_burst',
            countLabel: 'fires',
        );
    }

    /** Fallimenti ripetuti attraverso occorrenze diverse. */
    private function failureLoop(DateTimeInterface $from, DateTimeInterface $to): int
    {
        return $this->countRule(
            $from,
            $to,
            outcomes: ['failed'],
            threshold: $this->intConfig('routines.failure_loop.threshold', 10),
            type: AnomalyType::RoutineFailureLoop,
            dedupePrefix: 'routine_failure_loop',
            countLabel: 'failures',
        );
    }

    /** Pause ripetute: il mandato non copre più ciò che la routine fa. */
    private function mandateProbing(DateTimeInterface $from, DateTimeInterface $to): int
    {
        return $this->countRule(
            $from,
            $to,
            outcomes: ['paused'],
            threshold: $this->intConfig('routines.mandate_probing.threshold', 5),
            type: AnomalyType::RoutineMandateProbing,
            dedupePrefix: 'routine_mandate_probing',
            countLabel: 'pauses',
            collectActionClasses: true,
        );
    }

    /**
     * Domande senza risposta più vecchie della soglia. Non è una regola di finestra: è uno STATO
     * osservato all'istante di fine scansione, perché ciò che conta non è quando la routine si è
     * fermata ma da quanto tempo aspetta. La soglia è in ore e il conteggio parte da uno: una sola
     * domanda dimenticata da un giorno è già l'anomalia, non ne servono dieci.
     */
    private function approvalStarvation(DateTimeInterface $to): int
    {
        $hours = $this->intConfig('routines.approval_starvation.hours', 24);
        $cutoff = (new \DateTimeImmutable($to->format('Y-m-d H:i:s')))->modify("-{$hours} hours");

        $rows = $this->db->connection()->table('routine_runs as r')
            ->join('routines as t', 't.id', '=', 'r.routine_id')
            ->select('r.routine_id', 't.organization_id', 't.name', 'r.created_at', 'r.question')
            ->where('r.outcome', 'paused')
            ->whereNull('r.resolved_at')
            ->where('r.created_at', '<', $cutoff->format('Y-m-d H:i:s'))
            ->cursor();

        /** @var array<string, array{tenant: ?string, name: ?string, n: int, oldest: string, question: ?string}> $pending */
        $pending = [];

        foreach ($rows as $row) {
            $data = (array) $row;
            $routineId = is_string($data['routine_id'] ?? null) ? $data['routine_id'] : null;
            if ($routineId === null) {
                continue;
            }

            $createdAt = $this->stringOrNull($data['created_at'] ?? null) ?? $cutoff->format('Y-m-d H:i:s');

            if (! isset($pending[$routineId])) {
                $pending[$routineId] = [
                    'tenant' => $this->stringOrNull($data['organization_id'] ?? null),
                    'name' => $this->stringOrNull($data['name'] ?? null),
                    'n' => 0,
                    'oldest' => $createdAt,
                    'question' => $this->stringOrNull($data['question'] ?? null),
                ];
            }

            $pending[$routineId]['n']++;
            if ($createdAt < $pending[$routineId]['oldest']) {
                $pending[$routineId]['oldest'] = $createdAt;
                $pending[$routineId]['question'] = $this->stringOrNull($data['question'] ?? null);
            }
        }

        $opened = 0;
        foreach ($pending as $routineId => $entry) {
            $severity = $this->cases->severityFor($entry['n'], max(1, $this->intConfig('routines.approval_starvation.threshold', 3)));

            $signals = array_filter([
                'routine_id' => $routineId,
                'routine_name' => $entry['name'],
                'unanswered' => $entry['n'],
                'waiting_since' => $entry['oldest'],
                'hours_threshold' => $hours,
                // La domanda più vecchia in chiaro: chi apre il caso deve poter rispondere da lì,
                // non andare a cercare quale delle N pause fosse quella ferma da ieri.
                'oldest_question' => $entry['question'],
            ], static fn ($v): bool => $v !== null);

            if ($this->maybeAutoSuspend($routineId, $severity, AnomalyType::RoutineApprovalStarvation)) {
                $signals['auto_suspended'] = true;
            }

            $this->cases->open(
                $entry['tenant'],
                AnomalyType::RoutineApprovalStarvation,
                $severity,
                $signals,
                $entry['n'],
                'routine_approval_starvation:'.$routineId.':'.$to->format('Ymd'),
            );
            $opened++;
        }

        return $opened;
    }

    /**
     * Corpo condiviso delle regole di conteggio: raggruppa i run per routine nella finestra,
     * eventualmente filtrando sull'esito.
     *
     * Chiavi di dedupe con BUCKET GIORNALIERO sulla fine finestra, come per la delega: una routine
     * sospesa, sistemata e riattivata che ricomincia a sbagliare la settimana dopo deve aprire un
     * caso NUOVO, non rinfrescare in silenzio quello che qualcuno aveva già triageato e chiuso.
     *
     * @param  list<string>|null  $outcomes
     */
    private function countRule(DateTimeInterface $from, DateTimeInterface $to, ?array $outcomes, int $threshold, AnomalyType $type, string $dedupePrefix, string $countLabel, bool $collectActionClasses = false): int
    {
        $query = $this->db->connection()->table('routine_runs as r')
            ->join('routines as t', 't.id', '=', 'r.routine_id')
            ->select('r.routine_id', 't.organization_id', 't.name', 'r.action_class')
            ->where('r.created_at', '>=', $from->format('Y-m-d H:i:s'))
            ->where('r.created_at', '<', $to->format('Y-m-d H:i:s'));

        if ($outcomes !== null) {
            $query->whereIn('r.outcome', $outcomes);
        }

        /** @var array<string, array{tenant: ?string, name: ?string, n: int, actions: array<string, int>}> $counts */
        $counts = [];

        foreach ($query->cursor() as $row) {
            $data = (array) $row;
            $routineId = is_string($data['routine_id'] ?? null) ? $data['routine_id'] : null;
            if ($routineId === null) {
                continue;
            }

            if (! isset($counts[$routineId])) {
                $counts[$routineId] = [
                    'tenant' => $this->stringOrNull($data['organization_id'] ?? null),
                    'name' => $this->stringOrNull($data['name'] ?? null),
                    'n' => 0,
                    'actions' => [],
                ];
            }
            $counts[$routineId]['n']++;

            if ($collectActionClasses) {
                $action = $this->stringOrNull($data['action_class'] ?? null);
                if ($action !== null) {
                    $counts[$routineId]['actions'][$action] = ($counts[$routineId]['actions'][$action] ?? 0) + 1;
                }
            }
        }

        $opened = 0;
        foreach ($counts as $routineId => $entry) {
            if ($entry['n'] < $threshold) {
                continue;
            }

            $severity = $this->cases->severityFor($entry['n'], $threshold);
            $signals = array_filter([
                'routine_id' => $routineId,
                'routine_name' => $entry['name'],
                $countLabel => $entry['n'],
                'action_classes' => $collectActionClasses && $entry['actions'] !== [] ? $entry['actions'] : null,
            ], static fn ($v): bool => $v !== null);

            if ($this->maybeAutoSuspend($routineId, $severity, $type)) {
                $signals['auto_suspended'] = true;
            }

            $this->cases->open(
                $entry['tenant'],
                $type,
                $severity,
                $signals,
                $entry['n'],
                $dedupePrefix.':'.$routineId.':'.$to->format('Ymd'),
            );
            $opened++;
        }

        return $opened;
    }

    /**
     * Il lato kill-switch, SPENTO di default (`routines.auto_suspend`): rilevamento consultivo
     * finché l'operatore non decide altrimenti. Anche allora agisce solo su High/Critical, solo
     * attraverso il porto `RoutineLifecycle` dei contratti quando l'host lo ha registrato, e un
     * fallimento della sospensione non interrompe mai il rilevamento — il caso resta aperto, e un
     * umano lo vede comunque.
     */
    private function maybeAutoSuspend(string $routineId, Severity $severity, AnomalyType $type): bool
    {
        if (! in_array($severity, [Severity::High, Severity::Critical], true)) {
            return false;
        }

        if ($this->config->get('rebel-ai-guard.routines.auto_suspend') !== true) {
            return false;
        }

        if (! interface_exists(RoutineLifecycle::class) || ! app()->bound(RoutineLifecycle::class)) {
            return false;
        }

        try {
            app(RoutineLifecycle::class)->suspend($routineId, $type->value, 'rebel-ai-guard');

            return true;
        } catch (\Throwable) {
            return false;
        }
    }

    private function stringOrNull(mixed $value): ?string
    {
        return is_string($value) && $value !== '' ? $value : null;
    }

    private function intConfig(string $key, int $default): int
    {
        $value = $this->config->get("rebel-ai-guard.{$key}", $default);

        return is_int($value) ? $value : $default;
    }
}

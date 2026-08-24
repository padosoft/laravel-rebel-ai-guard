<?php

declare(strict_types=1);

namespace Padosoft\Rebel\AiGuard\Detection;

use Carbon\CarbonImmutable;
use DateTimeInterface;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Database\DatabaseManager;
use Illuminate\Database\Eloquent\Builder;
use Padosoft\Iam\Contracts\Delegation\AgentLifecycle;
use Padosoft\Iam\Contracts\Support\SubjectRef;
use Padosoft\Rebel\AiGuard\Enums\AnomalyType;
use Padosoft\Rebel\AiGuard\Enums\CaseStatus;
use Padosoft\Rebel\AiGuard\Enums\Severity;
use Padosoft\Rebel\AiGuard\Models\AnomalyCase;
use Psr\Clock\ClockInterface;

/**
 * DETERMINISTIC anomaly detection: it scans the audit log and opens anomaly cases from
 * fixed rules — the rules decide, the (optional) AI only explains later. Cases are
 * de-duplicated by a stable key so re-running the detector updates a case in place.
 */
final class AnomalyDetector
{
    public function __construct(
        private readonly DatabaseManager $db,
        private readonly ClockInterface $clock,
        private readonly Repository $config,
    ) {}

    /** Run all rules over events in [$from, $to). Returns how many cases were opened/updated. */
    public function detect(DateTimeInterface $from, DateTimeInterface $to): int
    {
        // OTP bombing: many failed email-OTP verifications targeting the same identifier.
        return $this->detectIdentifierFailures(
            $from,
            $to,
            'email_otp.failed',
            $this->intConfig('otp_bombing.threshold', 10),
            AnomalyType::OtpBombing,
            'otp_bombing',
        )
            // Delegated-access anomalies (laravel-iam-agents audit stream, when present).
            + $this->detectDelegationExchangeBurst($from, $to)
            + $this->detectDelegationScopeProbing($from, $to);
    }

    /**
     * Abnormal token velocity: one agent performing too many RFC 8693 exchanges
     * (issued or refused) in the window. A runaway loop, a stolen agent key, or an
     * orchestrator gone rogue all look like this before they look like anything else.
     */
    private function detectDelegationExchangeBurst(DateTimeInterface $from, DateTimeInterface $to): int
    {
        return $this->detectAgentEvents(
            $from,
            $to,
            ['iam.delegation.exchange.issued', 'iam.delegation.exchange.refused'],
            $this->intConfig('delegation.exchange_burst.threshold', 120),
            AnomalyType::DelegationExchangeBurst,
            'delegation_exchange_burst',
        );
    }

    /**
     * Scope probing: one agent COLLECTING refused exchanges — it keeps asking for
     * authority it does not have (missing grant, out-of-intersection scopes, revoked
     * grant retries). The refusal-reason breakdown lands in the case signals so a
     * human (or the AI explainer) sees WHAT was probed.
     */
    private function detectDelegationScopeProbing(DateTimeInterface $from, DateTimeInterface $to): int
    {
        return $this->detectAgentEvents(
            $from,
            $to,
            ['iam.delegation.exchange.refused'],
            $this->intConfig('delegation.scope_probing.threshold', 10),
            AnomalyType::DelegationScopeProbing,
            'delegation_scope_probing',
            collectReasons: true,
        );
    }

    /**
     * Shared delegation rule body: count `iam_audit_events` (stream=delegation) per
     * acting agent. The table belongs to laravel-iam-server: when it is not in this
     * database the rules are silently skipped — a rebel-only install stays untouched.
     *
     * Dedupe keys are DAY-BUCKETED (window end): a suspended-then-resumed agent that
     * misbehaves again next week must open a NEW case, not silently refresh a case
     * everyone already triaged.
     *
     * @param  list<string>  $eventTypes
     */
    private function detectAgentEvents(DateTimeInterface $from, DateTimeInterface $to, array $eventTypes, int $threshold, AnomalyType $type, string $dedupePrefix, bool $collectReasons = false): int
    {
        $connection = $this->db->connection();
        if (! $connection->getSchemaBuilder()->hasTable('iam_audit_events')) {
            return 0;
        }

        /** @var array<string, array{tenant: ?string, agent: string, n: int, reasons: array<string, int>}> $counts */
        $counts = [];

        $rows = $connection->table('iam_audit_events')
            ->select('organization_id', 'actor_agent_id', 'metadata_json')
            ->where('stream', 'delegation')
            ->whereIn('event_type', $eventTypes)
            ->where('occurred_at', '>=', $from->format('Y-m-d H:i:s'))
            ->where('occurred_at', '<', $to->format('Y-m-d H:i:s'))
            ->whereNotNull('actor_agent_id')
            ->cursor();

        foreach ($rows as $row) {
            $data = (array) $row;
            $agent = is_string($data['actor_agent_id'] ?? null) ? $data['actor_agent_id'] : null;
            if ($agent === null) {
                continue;
            }

            $tenant = is_string($data['organization_id'] ?? null) ? $data['organization_id'] : null;
            $key = ($tenant ?? '~').'|'.$agent;

            if (! isset($counts[$key])) {
                $counts[$key] = ['tenant' => $tenant, 'agent' => $agent, 'n' => 0, 'reasons' => []];
            }
            $counts[$key]['n']++;

            if ($collectReasons) {
                $reason = $this->refusalReason($data['metadata_json'] ?? null);
                if ($reason !== null) {
                    $counts[$key]['reasons'][$reason] = ($counts[$key]['reasons'][$reason] ?? 0) + 1;
                }
            }
        }

        $opened = 0;
        foreach ($counts as $entry) {
            if ($entry['n'] < $threshold) {
                continue;
            }

            $severity = $this->severityFor($entry['n'], $threshold);
            $signals = array_filter([
                'agent_id' => $entry['agent'],
                'events' => $entry['n'],
                'refusal_reasons' => $collectReasons && $entry['reasons'] !== [] ? $entry['reasons'] : null,
            ], static fn ($v): bool => $v !== null);

            if ($this->maybeAutoSuspend($entry['agent'], $severity, $type)) {
                $signals['auto_suspended'] = true;
            }

            $this->openCase(
                $entry['tenant'],
                $type,
                $severity,
                $signals,
                $entry['n'],
                $dedupePrefix.':'.$entry['agent'].':'.$to->format('Ymd'),
            );
            $opened++;
        }

        return $opened;
    }

    /**
     * The kill-switch half, OFF by default (`delegation.auto_suspend`): advisory-only
     * detection unless the operator explicitly opts in. Even then it acts only on
     * High/Critical, only through the iam-contracts AgentLifecycle port when the host
     * has it bound, and never lets a suspension failure break detection (the case
     * still opens — a human still sees it).
     */
    private function maybeAutoSuspend(string $agentId, Severity $severity, AnomalyType $type): bool
    {
        if (! in_array($severity, [Severity::High, Severity::Critical], true)) {
            return false;
        }

        if ($this->config->get('rebel-ai-guard.delegation.auto_suspend') !== true) {
            return false;
        }

        if (! interface_exists(AgentLifecycle::class)
            || ! app()->bound(AgentLifecycle::class)) {
            return false;
        }

        try {
            app(AgentLifecycle::class)->suspend(
                new SubjectRef('agent', $agentId),
                $type->value,
                'rebel-ai-guard',
            );

            return true;
        } catch (\Throwable) {
            return false; // il caso resta aperto: un umano vede comunque l'anomalia
        }
    }

    /** Estrae `refusal_reason` dal metadata_json (stringa JSON o array già decodificato). */
    private function refusalReason(mixed $raw): ?string
    {
        $decoded = is_string($raw) ? json_decode($raw, true) : $raw;
        if (! is_array($decoded)) {
            return null;
        }

        $reason = $decoded['refusal_reason'] ?? null;

        return is_string($reason) && $reason !== '' ? $reason : null;
    }

    private function detectIdentifierFailures(DateTimeInterface $from, DateTimeInterface $to, string $eventType, int $threshold, AnomalyType $type, string $dedupePrefix): int
    {
        /** @var array<string, array{tenant: ?string, hmac: string, n: int}> $counts */
        $counts = [];

        $rows = $this->db->connection()->table('rebel_auth_events')
            ->select('tenant_id', 'identifier_hmac')
            ->where('event_type', $eventType)
            ->where('created_at', '>=', $from->format('Y-m-d H:i:s'))
            ->where('created_at', '<', $to->format('Y-m-d H:i:s'))
            ->whereNotNull('identifier_hmac')
            ->cursor();

        foreach ($rows as $row) {
            $data = (array) $row;
            $hmac = is_string($data['identifier_hmac'] ?? null) ? $data['identifier_hmac'] : null;
            if ($hmac === null) {
                continue;
            }

            $tenant = is_string($data['tenant_id'] ?? null) ? $data['tenant_id'] : null;
            $key = ($tenant ?? '~').'|'.$hmac;

            if (! isset($counts[$key])) {
                $counts[$key] = ['tenant' => $tenant, 'hmac' => $hmac, 'n' => 0];
            }
            $counts[$key]['n']++;
        }

        $opened = 0;
        foreach ($counts as $entry) {
            if ($entry['n'] >= $threshold) {
                $this->openCase(
                    $entry['tenant'],
                    $type,
                    $this->severityFor($entry['n'], $threshold),
                    ['identifier_hmac' => $entry['hmac'], 'failures' => $entry['n']],
                    $entry['n'],
                    $dedupePrefix.':'.$entry['hmac'],
                );
                $opened++;
            }
        }

        return $opened;
    }

    /**
     * @param  array<string, mixed>  $signals
     */
    private function openCase(?string $tenant, AnomalyType $type, Severity $severity, array $signals, int $count, string $dedupe): void
    {
        $existing = AnomalyCase::query()
            ->withoutGlobalScopes()
            ->where('dedupe_key', $dedupe)
            ->when(
                $tenant === null,
                fn (Builder $query) => $query->whereNull('tenant_id'),
                fn (Builder $query) => $query->where('tenant_id', $tenant),
            )
            ->first();

        if ($existing !== null) {
            // Refresh the open case in place (don't reopen a closed/acknowledged one).
            $existing->severity = $severity;
            $existing->events_count = $count;
            $existing->signals = $signals;
            $existing->save();

            return;
        }

        $case = new AnomalyCase;
        $case->fill([
            'tenant_id' => $tenant,
            'type' => $type,
            'severity' => $severity,
            'status' => CaseStatus::Open,
            'dedupe_key' => $dedupe,
            'signals' => $signals,
            'events_count' => $count,
            'opened_at' => CarbonImmutable::instance($this->clock->now()),
        ]);
        $case->save();
    }

    private function severityFor(int $count, int $threshold): Severity
    {
        return match (true) {
            $count >= $threshold * 3 => Severity::Critical,
            $count >= $threshold * 2 => Severity::High,
            default => Severity::Medium,
        };
    }

    private function intConfig(string $key, int $default): int
    {
        $value = $this->config->get("rebel-ai-guard.{$key}", $default);

        return is_int($value) ? $value : $default;
    }
}

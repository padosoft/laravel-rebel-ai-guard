<?php

declare(strict_types=1);

namespace Padosoft\Rebel\AiGuard\Detection;

use Carbon\CarbonImmutable;
use Illuminate\Database\Eloquent\Builder;
use Padosoft\Rebel\AiGuard\Enums\AnomalyType;
use Padosoft\Rebel\AiGuard\Enums\CaseStatus;
use Padosoft\Rebel\AiGuard\Enums\Severity;
use Padosoft\Rebel\AiGuard\Models\AnomalyCase;
use Psr\Clock\ClockInterface;

/**
 * Come una regola diventa un caso. Estratto perché le regole vivono ormai su due sorgenti
 * diverse (lo stream delegation di IAM e il ledger delle routine) e la parte che conta —
 * de-duplicare invece di aprire un doppione, e aggiornare senza riaprire ciò che qualcuno ha già
 * chiuso — deve comportarsi identica in entrambe. Duplicarla sarebbe il modo più naturale per
 * ritrovarsi, fra sei mesi, con due semantiche di dedupe leggermente diverse.
 */
final readonly class CaseWriter
{
    public function __construct(private ClockInterface $clock) {}

    /**
     * @param  array<string, mixed>  $signals
     */
    public function open(?string $tenant, AnomalyType $type, Severity $severity, array $signals, int $count, string $dedupe): void
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

    public function severityFor(int $count, int $threshold): Severity
    {
        return match (true) {
            $count >= $threshold * 3 => Severity::Critical,
            $count >= $threshold * 2 => Severity::High,
            default => Severity::Medium,
        };
    }
}

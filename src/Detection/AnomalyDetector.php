<?php

declare(strict_types=1);

namespace Padosoft\Rebel\AiGuard\Detection;

use Carbon\CarbonImmutable;
use DateTimeInterface;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Database\DatabaseManager;
use Illuminate\Database\Eloquent\Builder;
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
        );
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

<?php

declare(strict_types=1);

use Padosoft\Rebel\AiGuard\Enums\AnomalyType;
use Padosoft\Rebel\AiGuard\Models\AnomalyCase;
use Padosoft\Rebel\Core\Clock\FakeClock;
use Psr\Clock\ClockInterface;

it('opens a case when run as the scheduled command', function (): void {
    $clock = new FakeClock(new DateTimeImmutable('2026-01-01 09:30:00'));
    app()->instance(ClockInterface::class, $clock);
    config()->set('rebel-ai-guard.otp_bombing.threshold', 5);
    config()->set('rebel-ai-guard.detect.lookback_minutes', 60); // events fall inside [now-60m, now)

    for ($i = 0; $i < 6; $i++) {
        recordOtpFailure('hmac-victim');
    }

    $clock->set(new DateTimeImmutable('2026-01-01 10:00:00')); // events are now 30 min in the past

    $this->artisan('rebel:detect-anomalies')
        ->expectsOutputToContain('Anomaly detection: 1 case(s) opened/updated over the last 60 min.')
        ->assertOk();

    $case = AnomalyCase::query()->firstOrFail();
    expect($case->type)->toBe(AnomalyType::OtpBombing)
        ->and($case->events_count)->toBe(6);
});

it('honours the --lookback option', function (): void {
    $clock = new FakeClock(new DateTimeImmutable('2026-01-01 09:59:30'));
    app()->instance(ClockInterface::class, $clock);
    config()->set('rebel-ai-guard.otp_bombing.threshold', 5);
    config()->set('rebel-ai-guard.detect.lookback_minutes', 1440);

    for ($i = 0; $i < 6; $i++) {
        recordOtpFailure('hmac-victim');
    }

    $clock->set(new DateTimeImmutable('2026-01-01 10:00:00')); // events are 30s in the past

    // A 1-minute window ending "now" still contains the just-recorded events, and the printed
    // window must reflect the --lookback override, not the config default (1440).
    $this->artisan('rebel:detect-anomalies', ['--lookback' => '1'])
        ->expectsOutputToContain('over the last 1 min.')
        ->assertOk();

    expect(AnomalyCase::query()->count())->toBe(1);
});

it('reports zero cases when nothing crosses the threshold', function (): void {
    app()->instance(ClockInterface::class, new FakeClock(new DateTimeImmutable('2026-01-01 10:00:00')));
    config()->set('rebel-ai-guard.otp_bombing.threshold', 5);

    recordOtpFailure('hmac-lonely'); // below threshold

    $this->artisan('rebel:detect-anomalies')
        ->expectsOutputToContain('Anomaly detection: 0 case(s) opened/updated')
        ->assertOk();

    expect(AnomalyCase::query()->count())->toBe(0);
});

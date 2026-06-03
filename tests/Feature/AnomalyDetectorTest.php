<?php

declare(strict_types=1);

use Padosoft\Rebel\AiGuard\Detection\AnomalyDetector;
use Padosoft\Rebel\AiGuard\Enums\AnomalyType;
use Padosoft\Rebel\AiGuard\Enums\Severity;
use Padosoft\Rebel\AiGuard\Models\AnomalyCase;
use Padosoft\Rebel\Core\Clock\FakeClock;
use Psr\Clock\ClockInterface;

function window(): array
{
    return [new DateTimeImmutable('2026-01-01 09:00:00'), new DateTimeImmutable('2026-01-01 11:00:00')];
}

it('opens an OTP-bombing case when failures exceed the threshold', function (): void {
    app()->instance(ClockInterface::class, new FakeClock(new DateTimeImmutable('2026-01-01 10:00:00')));
    config()->set('rebel-ai-guard.otp_bombing.threshold', 5);

    for ($i = 0; $i < 6; $i++) {
        recordOtpFailure('hmac-victim');
    }
    recordOtpFailure('hmac-other'); // below threshold → no case

    expect(app(AnomalyDetector::class)->detect(...window()))->toBe(1);

    $case = AnomalyCase::query()->firstOrFail();
    expect($case->type)->toBe(AnomalyType::OtpBombing)
        ->and($case->severity)->toBe(Severity::Medium)
        ->and($case->events_count)->toBe(6)
        ->and($case->signals['identifier_hmac'])->toBe('hmac-victim');
});

it('is idempotent: re-detecting updates the case in place', function (): void {
    app()->instance(ClockInterface::class, new FakeClock(new DateTimeImmutable('2026-01-01 10:00:00')));
    config()->set('rebel-ai-guard.otp_bombing.threshold', 5);

    for ($i = 0; $i < 6; $i++) {
        recordOtpFailure('hmac-victim');
    }

    $detector = app(AnomalyDetector::class);
    $detector->detect(...window());
    $detector->detect(...window());

    expect(AnomalyCase::query()->count())->toBe(1);
});

it('escalates severity with volume', function (): void {
    app()->instance(ClockInterface::class, new FakeClock(new DateTimeImmutable('2026-01-01 10:00:00')));
    config()->set('rebel-ai-guard.otp_bombing.threshold', 5);

    for ($i = 0; $i < 16; $i++) { // >= 3× threshold ⇒ critical
        recordOtpFailure('hmac-victim');
    }

    app(AnomalyDetector::class)->detect(...window());

    expect(AnomalyCase::query()->firstOrFail()->severity)->toBe(Severity::Critical);
});

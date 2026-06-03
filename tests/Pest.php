<?php

declare(strict_types=1);

use Padosoft\Rebel\AiGuard\Tests\CronFrequencyTestCase;
use Padosoft\Rebel\AiGuard\Tests\TestCase;
use Padosoft\Rebel\Core\Audit\AuditEvent;
use Padosoft\Rebel\Core\Contracts\AuditLogger;

uses(TestCase::class)->in('Feature');

// Boot the package with a raw cron expression in config (set before boot) so the schedule
// assertions in this folder see the configured frequency drive the registered event.
uses(CronFrequencyTestCase::class)->in('Schedule');

/** Record a failed email-OTP event for a given (hashed) identifier. */
function recordOtpFailure(string $identifierHmac): void
{
    app(AuditLogger::class)->record(new AuditEvent(
        type: 'email_otp.failed',
        identifierHmac: $identifierHmac,
        keyVersion: 1,
    ));
}

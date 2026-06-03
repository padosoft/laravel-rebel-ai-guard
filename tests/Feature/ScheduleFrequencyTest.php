<?php

declare(strict_types=1);

use Illuminate\Console\Scheduling\Event;
use Illuminate\Console\Scheduling\Schedule;
use Padosoft\Rebel\AiGuard\Support\ScheduleFrequency;

/** Find the scheduled `rebel:detect-anomalies` event, if any. */
function detectScheduledEvent(): ?Event
{
    /** @var Schedule $schedule */
    $schedule = app(Schedule::class);

    foreach ($schedule->events() as $event) {
        if (str_contains((string) $event->command, 'rebel:detect-anomalies')) {
            return $event;
        }
    }

    return null;
}

it('schedules the command hourly by default', function (): void {
    $event = detectScheduledEvent();

    expect($event)->not->toBeNull()
        ->and($event->expression)->toBe('0 * * * *')
        // The scheduled invocation passes the configured lookback explicitly.
        ->and($event->command)->toContain('--lookback=');
});

it('applies a whitelisted cadence from config', function (): void {
    config()->set('rebel-ai-guard.detect.frequency', 'everyFiveMinutes');

    $event = app(Schedule::class)->command('rebel:detect-anomalies');
    ScheduleFrequency::apply($event, 'everyFiveMinutes');

    expect($event->expression)->toBe('*/5 * * * *');
});

it('applies a raw cron expression from config', function (): void {
    $event = app(Schedule::class)->command('rebel:detect-anomalies');
    ScheduleFrequency::apply($event, '*/15 9-17 * * 1-5');

    expect($event->expression)->toBe('*/15 9-17 * * 1-5');
});

it('matches cadence method names case-insensitively', function (): void {
    $event = app(Schedule::class)->command('rebel:detect-anomalies');
    ScheduleFrequency::apply($event, 'EVERYTENMINUTES');

    expect($event->expression)->toBe('*/10 * * * *');
});

it('falls back to hourly on an unknown frequency', function (): void {
    $event = app(Schedule::class)->command('rebel:detect-anomalies');
    ScheduleFrequency::apply($event, 'not-a-real-cadence');

    expect($event->expression)->toBe('0 * * * *');
});

it('never invokes an arbitrary (non-whitelisted) method', function (): void {
    // "everyMinute" is whitelisted, but a method like "withoutOverlapping" must NOT be reachable
    // via the frequency string — an unknown value falls back to hourly, leaving overlap default.
    $event = app(Schedule::class)->command('rebel:detect-anomalies');
    ScheduleFrequency::apply($event, 'withoutOverlapping');

    expect($event->expression)->toBe('0 * * * *');
});

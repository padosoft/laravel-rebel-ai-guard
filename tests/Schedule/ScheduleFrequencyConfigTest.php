<?php

declare(strict_types=1);

use Illuminate\Console\Scheduling\Event;
use Illuminate\Console\Scheduling\Schedule;

it('drives the registered schedule from the configured raw cron expression', function (): void {
    /** @var Schedule $schedule */
    $schedule = app(Schedule::class);

    $match = null;
    foreach ($schedule->events() as $event) {
        if ($event instanceof Event && str_contains((string) $event->command, 'rebel:detect-anomalies')) {
            $match = $event;
            break;
        }
    }

    expect($match)->not->toBeNull()
        ->and($match->expression)->toBe('*/15 * * * *');
});

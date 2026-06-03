<?php

declare(strict_types=1);

return [

    // OTP bombing: open a case when this many failed email-OTP verifications target one
    // identifier within the scan window.
    'otp_bombing' => [
        'threshold' => (int) env('REBEL_AIGUARD_OTP_BOMBING_THRESHOLD', 10),
    ],

    // Automatic detection: the package registers the `rebel:detect-anomalies` command and,
    // when `schedule` is true, runs it on the configured `frequency` via Laravel's scheduler —
    // so anomaly cases appear on their own without the app calling the detector manually. Set
    // `schedule` to false to opt out (you can still run the command by hand or wire your own
    // schedule). `lookback_minutes` is the default scan window (ending "now"); the command's
    // `--lookback` option (or `--from`/`--to`) overrides it for a single run.
    //
    // `frequency` controls how often the scheduled command runs. Use one of the whitelisted
    // cadence names — everyMinute, everyTwoMinutes, everyThreeMinutes, everyFourMinutes,
    // everyFiveMinutes, everyTenMinutes, everyFifteenMinutes, everyThirtyMinutes, hourly,
    // daily, weekly, monthly — or a raw 5-field cron expression (e.g. "*/15 * * * *"), which is
    // applied via the scheduler's ->cron() method. Anything unrecognised falls back to hourly.
    'detect' => [
        'schedule' => (bool) env('REBEL_AIGUARD_SCHEDULE', true),
        'frequency' => (string) env('REBEL_AIGUARD_FREQUENCY', 'hourly'),
        'lookback_minutes' => (int) env('REBEL_AIGUARD_LOOKBACK', 1440),
    ],

];

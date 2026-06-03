<?php

declare(strict_types=1);

return [

    // OTP bombing: open a case when this many failed email-OTP verifications target one
    // identifier within the scan window.
    'otp_bombing' => [
        'threshold' => (int) env('REBEL_AIGUARD_OTP_BOMBING_THRESHOLD', 10),
    ],

    // Automatic detection: the package registers the `rebel:detect-anomalies` command and,
    // when `schedule` is true, runs it hourly via Laravel's scheduler — so anomaly cases
    // appear on their own without the app calling the detector manually. Set `schedule` to
    // false to opt out (you can still run the command by hand or wire your own schedule).
    // `lookback_minutes` is the default scan window (ending "now"); the command's
    // `--lookback` option overrides it for a single run.
    'detect' => [
        'schedule' => (bool) env('REBEL_AIGUARD_SCHEDULE', true),
        'lookback_minutes' => (int) env('REBEL_AIGUARD_LOOKBACK', 1440),
    ],

];

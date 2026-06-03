<?php

declare(strict_types=1);

return [

    // OTP bombing: open a case when this many failed email-OTP verifications target one
    // identifier within the scan window.
    'otp_bombing' => [
        'threshold' => (int) env('REBEL_AIGUARD_OTP_BOMBING_THRESHOLD', 10),
    ],

];

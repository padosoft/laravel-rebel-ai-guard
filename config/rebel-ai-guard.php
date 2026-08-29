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
    // IAM delegated-access anomalies (laravel-iam-agents): the rules read the server's
    // `iam_audit_events` table (stream=delegation) when it exists in the same database —
    // absent table = rules silently skipped (rebel-only installs stay untouched).
    // - exchange_burst: one agent performing >= threshold token exchanges (issued OR refused)
    //   in the scan window — abnormal token velocity.
    // - scope_probing: one agent COLLECTING >= threshold REFUSED exchanges — it keeps asking
    //   for authority it does not have (grant probing, scope probing, revoked-grant retries).
    // `auto_suspend` (default false = advisory-only): when true, a High/Critical case also
    // suspends the agent through the iam-contracts AgentLifecycle port, when bound. The
    // suspension is idempotent server-side and every transition is audited by IAM itself.
    'delegation' => [
        'exchange_burst' => [
            'threshold' => (int) env('REBEL_AIGUARD_DGR_BURST_THRESHOLD', 120),
        ],
        'scope_probing' => [
            'threshold' => (int) env('REBEL_AIGUARD_DGR_PROBING_THRESHOLD', 10),
        ],
        'auto_suspend' => (bool) env('REBEL_AIGUARD_DGR_AUTO_SUSPEND', false),
    ],

    // Scheduled-routine anomalies (laravel-routines): the rules read the `routine_runs` ledger
    // when it exists in the same database — absent table = rules silently skipped. Where the
    // delegation rules watch an agent ASKING for authority, these watch an automation running
    // with nobody looking, which fails in ways that produce no error anywhere:
    // - fire_burst: >= threshold fires for one routine in the window (a runaway event emitter, or
    //   replayed webhook deliveries that each carry a distinct delivery id).
    // - failure_loop: >= threshold FAILED runs. The engine retries within one occurrence and then
    //   gives up; nothing looks ACROSS occurrences, so a routine failing hourly for a week is
    //   silent.
    // - mandate_probing: >= threshold PAUSED runs — the granted consent no longer describes what
    //   the routine actually does, and needs renegotiating rather than approving daily.
    // - approval_starvation: paused runs UNANSWERED for longer than `hours`. Not a window rule but
    //   a state observed at scan end: what matters is how long the question has been waiting. It
    //   opens from the first one; `threshold` only grades the severity.
    // `auto_suspend` (default false = advisory-only): when true, a High/Critical case also
    // suspends the routine through the routines-contracts RoutineLifecycle port, when bound.
    // Suspending never blocks answering the questions already pending — those live on the run.
    'routines' => [
        'fire_burst' => [
            'threshold' => (int) env('REBEL_AIGUARD_ROUTINE_BURST_THRESHOLD', 200),
        ],
        'failure_loop' => [
            'threshold' => (int) env('REBEL_AIGUARD_ROUTINE_FAILURE_THRESHOLD', 10),
        ],
        'mandate_probing' => [
            'threshold' => (int) env('REBEL_AIGUARD_ROUTINE_PROBING_THRESHOLD', 5),
        ],
        'approval_starvation' => [
            'hours' => (int) env('REBEL_AIGUARD_ROUTINE_STARVATION_HOURS', 24),
            'threshold' => (int) env('REBEL_AIGUARD_ROUTINE_STARVATION_THRESHOLD', 3),
        ],
        'auto_suspend' => (bool) env('REBEL_AIGUARD_ROUTINE_AUTO_SUSPEND', false),
    ],

    'detect' => [
        'schedule' => (bool) env('REBEL_AIGUARD_SCHEDULE', true),
        'frequency' => (string) env('REBEL_AIGUARD_FREQUENCY', 'hourly'),
        'lookback_minutes' => (int) env('REBEL_AIGUARD_LOOKBACK', 1440),
    ],

];

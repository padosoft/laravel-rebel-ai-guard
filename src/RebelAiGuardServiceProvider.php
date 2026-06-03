<?php

declare(strict_types=1);

namespace Padosoft\Rebel\AiGuard;

use Illuminate\Console\Scheduling\Schedule;
use Illuminate\Contracts\Config\Repository;
use Padosoft\Rebel\AiGuard\Console\DetectAnomaliesCommand;
use Padosoft\Rebel\AiGuard\Contracts\AiClient;
use Padosoft\Rebel\AiGuard\Detection\AnomalyDetector;
use Padosoft\Rebel\AiGuard\Support\PromptSanitizer;
use Padosoft\Rebel\AiGuard\Support\ScheduleFrequency;
use Spatie\LaravelPackageTools\Package;
use Spatie\LaravelPackageTools\PackageServiceProvider;

/**
 * Anomaly detection + AI security copilot for Laravel Rebel: deterministic rules open
 * anomaly cases; the optional AI only explains them (sanitized prompts, advisory output).
 */
final class RebelAiGuardServiceProvider extends PackageServiceProvider
{
    public function configurePackage(Package $package): void
    {
        $package
            ->name('laravel-rebel-ai-guard')
            ->hasConfigFile('rebel-ai-guard')
            ->hasMigration('create_rebel_anomaly_cases_table')
            ->hasCommand(DetectAnomaliesCommand::class);
    }

    public function packageBooted(): void
    {
        // Auto-run detection so cases appear on their own: schedule the command on the
        // configured cadence. Only wire this in console (where the scheduler runs) and when the
        // app opted in, so it never errors in HTTP/test contexts.
        if (! $this->app->runningInConsole()) {
            return;
        }

        $config = $this->app->make(Repository::class);
        if ($config->get('rebel-ai-guard.detect.schedule', true) !== true) {
            return;
        }

        $frequency = $config->get('rebel-ai-guard.detect.frequency', ScheduleFrequency::DEFAULT_FREQUENCY);
        $frequency = is_string($frequency) && $frequency !== '' ? $frequency : ScheduleFrequency::DEFAULT_FREQUENCY;

        $lookback = $config->get('rebel-ai-guard.detect.lookback_minutes', 1440);
        $lookback = is_int($lookback) ? max(1, $lookback) : 1440;

        $this->app->booted(function () use ($frequency, $lookback): void {
            if (! $this->app->bound(Schedule::class)) {
                return;
            }

            $schedule = $this->app->make(Schedule::class);

            // Pass the configured lookback explicitly so a scheduled (cron) run and a manual run
            // scan exactly the same window.
            $event = $schedule->command('rebel:detect-anomalies --lookback='.$lookback);

            ScheduleFrequency::apply($event, $frequency);
        });
    }

    public function packageRegistered(): void
    {
        $this->app->singleton(PromptSanitizer::class);
        $this->app->singleton(AnomalyDetector::class);

        $this->app->singleton(AiExplainer::class, function (): AiExplainer {
            return new AiExplainer(
                $this->app->make(PromptSanitizer::class),
                $this->app->bound(AiClient::class) ? $this->app->make(AiClient::class) : null,
            );
        });
    }
}

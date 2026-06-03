<?php

declare(strict_types=1);

namespace Padosoft\Rebel\AiGuard;

use Padosoft\Rebel\AiGuard\Contracts\AiClient;
use Padosoft\Rebel\AiGuard\Detection\AnomalyDetector;
use Padosoft\Rebel\AiGuard\Support\PromptSanitizer;
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
            ->hasMigration('create_rebel_anomaly_cases_table');
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

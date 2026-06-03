<?php

declare(strict_types=1);

namespace Padosoft\Rebel\AiGuard;

use Spatie\LaravelPackageTools\Package;
use Spatie\LaravelPackageTools\PackageServiceProvider;

/**
 * Skeleton iniziale di padosoft/laravel-rebel-ai-guard. Implementazione in arrivo.
 */
final class RebelAiGuardServiceProvider extends PackageServiceProvider
{
    public function configurePackage(Package $package): void
    {
        $package->name('laravel-rebel-ai-guard');
    }
}

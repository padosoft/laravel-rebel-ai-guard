<?php

declare(strict_types=1);

namespace Padosoft\Rebel\AiGuard\Tests;

use Illuminate\Foundation\Application;

/**
 * A package TestCase variant that sets a raw cron expression in `detect.frequency` BEFORE the
 * app boots, so tests can assert the configured frequency drives the actually-registered
 * scheduled event (the schedule is wired during boot).
 */
class CronFrequencyTestCase extends TestCase
{
    /**
     * @param  Application  $app
     */
    protected function defineEnvironment($app): void
    {
        parent::defineEnvironment($app);

        $app['config']->set('rebel-ai-guard.detect.frequency', '*/15 * * * *');
    }
}

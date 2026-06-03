<?php

declare(strict_types=1);

namespace Padosoft\Rebel\AiGuard\Console;

use Carbon\CarbonImmutable;
use Illuminate\Console\Command;
use Illuminate\Contracts\Config\Repository;
use Padosoft\Rebel\AiGuard\Detection\AnomalyDetector;
use Psr\Clock\ClockInterface;

/**
 * Runs the deterministic anomaly detection over a lookback window ending "now", so anomaly
 * cases appear on their own. Meant to be scheduled (hourly by default); can also be run by
 * hand. The window is built from the injected PSR-20 clock for testability.
 */
final class DetectAnomaliesCommand extends Command
{
    /** @var string */
    protected $signature = 'rebel:detect-anomalies {--lookback= : Lookback window in minutes (defaults to config rebel-ai-guard.detect.lookback_minutes)}';

    /** @var string */
    protected $description = 'Scan recent auth events and open/update anomaly cases (deterministic rules).';

    public function handle(AnomalyDetector $detector, ClockInterface $clock, Repository $config): int
    {
        $lookback = $this->lookbackMinutes($config);

        $to = CarbonImmutable::instance($clock->now());
        $from = $to->subMinutes($lookback);

        $opened = $detector->detect($from, $to);

        $this->info("Anomaly detection: {$opened} case(s) opened/updated over the last {$lookback} min.");

        return self::SUCCESS;
    }

    private function lookbackMinutes(Repository $config): int
    {
        $option = $this->option('lookback');
        if (is_string($option) && $option !== '') {
            return max(1, (int) $option);
        }

        $configured = $config->get('rebel-ai-guard.detect.lookback_minutes', 1440);

        return is_int($configured) ? max(1, $configured) : 1440;
    }
}

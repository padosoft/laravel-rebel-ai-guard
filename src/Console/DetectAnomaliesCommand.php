<?php

declare(strict_types=1);

namespace Padosoft\Rebel\AiGuard\Console;

use Carbon\CarbonImmutable;
use Illuminate\Console\Command;
use Illuminate\Contracts\Config\Repository;
use Padosoft\Rebel\AiGuard\Detection\AnomalyDetector;
use Psr\Clock\ClockInterface;
use Throwable;

/**
 * Runs the deterministic anomaly detection over a window so anomaly cases appear on their own.
 * Meant to be scheduled (the cadence is configurable, hourly by default), but can also be run by
 * hand — including to simulate a cron run over any window.
 *
 * The window is, in order of precedence:
 *   1. an explicit `--from`/`--to` pair (ISO-8601 datetimes); when both are given they override
 *      the lookback;
 *   2. a `--lookback=<minutes>` window ending "now";
 *   3. the config default `rebel-ai-guard.detect.lookback_minutes`, ending "now".
 *
 * "Now" is taken from the injected PSR-20 clock for testability.
 */
final class DetectAnomaliesCommand extends Command
{
    /** @var string */
    protected $signature = 'rebel:detect-anomalies
        {--lookback= : Lookback window in minutes ending "now" (defaults to config rebel-ai-guard.detect.lookback_minutes)}
        {--from= : Window start as an ISO-8601 datetime (overrides --lookback when --to is also given)}
        {--to= : Window end as an ISO-8601 datetime (defaults to "now" when only --from is given)}';

    /** @var string */
    protected $description = 'Scan recent auth events and open/update anomaly cases (deterministic rules).';

    public function handle(AnomalyDetector $detector, ClockInterface $clock, Repository $config): int
    {
        $now = CarbonImmutable::instance($clock->now());

        $window = $this->resolveWindow($config, $now);
        if ($window === null) {
            // resolveWindow already printed the specific error.
            return self::FAILURE;
        }

        [$from, $to] = $window;

        $opened = $detector->detect($from, $to);

        $this->info(sprintf(
            'Anomaly detection: %d case(s) opened/updated over %s.',
            $opened,
            $this->describeWindow($from, $to),
        ));

        return self::SUCCESS;
    }

    /**
     * Resolve the scan window from the options/config, or null (after printing an error) on
     * invalid input.
     *
     * @return array{0: CarbonImmutable, 1: CarbonImmutable}|null
     */
    private function resolveWindow(Repository $config, CarbonImmutable $now): ?array
    {
        $fromOption = $this->stringOption('from');
        $toOption = $this->stringOption('to');

        // Explicit window: at least --from is given. --to defaults to "now".
        if ($fromOption !== null || $toOption !== null) {
            if ($fromOption === null) {
                $this->error('The --from option is required when --to is given.');

                return null;
            }

            $from = $this->parseDateTime($fromOption, '--from');
            if ($from === null) {
                return null;
            }

            if ($toOption === null) {
                $to = $now;
            } else {
                $parsedTo = $this->parseDateTime($toOption, '--to');
                if ($parsedTo === null) {
                    return null;
                }
                $to = $parsedTo;
            }

            if ($to <= $from) {
                $this->error('The --to datetime must be after --from.');

                return null;
            }

            return [$from, $to];
        }

        // Lookback window ending "now".
        $lookback = $this->lookbackMinutes($config);

        return [$now->subMinutes($lookback), $now];
    }

    /** Parse an ISO-8601 (or otherwise strtotime-parseable) datetime, or null on failure. */
    private function parseDateTime(string $value, string $label): ?CarbonImmutable
    {
        if (strtotime($value) === false) {
            $this->error("The {$label} value is not a valid datetime: {$value}");

            return null;
        }

        try {
            return CarbonImmutable::parse($value);
        } catch (Throwable) {
            $this->error("The {$label} value is not a valid datetime: {$value}");

            return null;
        }
    }

    private function lookbackMinutes(Repository $config): int
    {
        $option = $this->stringOption('lookback');
        if ($option !== null) {
            return max(1, (int) $option);
        }

        $configured = $config->get('rebel-ai-guard.detect.lookback_minutes', 1440);

        return is_int($configured) ? max(1, $configured) : 1440;
    }

    /** Return a non-empty string option value, or null when absent/empty. */
    private function stringOption(string $name): ?string
    {
        $value = $this->option($name);

        return is_string($value) && $value !== '' ? $value : null;
    }

    private function describeWindow(CarbonImmutable $from, CarbonImmutable $to): string
    {
        // When the window was derived from a lookback ending "now" we report the round minute
        // span; otherwise we report the explicit ISO-8601 bounds.
        if ($this->stringOption('from') === null && $this->stringOption('to') === null) {
            $minutes = (int) round(($to->getTimestamp() - $from->getTimestamp()) / 60);

            return "the last {$minutes} min";
        }

        return sprintf('[%s, %s)', $from->toIso8601String(), $to->toIso8601String());
    }
}

<?php

declare(strict_types=1);

namespace Padosoft\Rebel\AiGuard\Support;

use Illuminate\Console\Scheduling\Event;

/**
 * Resolves a configured cadence (a whitelisted method name like "everyFiveMinutes" or a raw
 * 5-field cron expression) into a call against a scheduled {@see Event}. Never invokes an
 * arbitrary method: only the names in {@see self::METHODS} are allowed; anything else that is
 * not a valid cron expression falls back to {@see self::DEFAULT_FREQUENCY}.
 */
final class ScheduleFrequency
{
    public const DEFAULT_FREQUENCY = 'hourly';

    /**
     * Whitelisted scheduler cadence methods (no-argument frequency helpers on {@see Event}).
     *
     * @var list<string>
     */
    private const METHODS = [
        'everyMinute',
        'everyTwoMinutes',
        'everyThreeMinutes',
        'everyFourMinutes',
        'everyFiveMinutes',
        'everyTenMinutes',
        'everyFifteenMinutes',
        'everyThirtyMinutes',
        'hourly',
        'daily',
        'weekly',
        'monthly',
        'quarterly',
        'yearly',
    ];

    /**
     * Apply the configured frequency to the given scheduled event and return it.
     *
     * Resolution order:
     *  1. a whitelisted cadence method name (case-insensitive) → call it;
     *  2. a valid 5-field cron expression → {@see Event::cron()};
     *  3. otherwise → the default cadence ("hourly").
     */
    public static function apply(Event $event, string $frequency): Event
    {
        $frequency = trim($frequency);

        $method = self::matchMethod($frequency);
        if ($method !== null) {
            /** @var Event $result */
            $result = $event->{$method}();

            return $result;
        }

        if (self::isCronExpression($frequency)) {
            return $event->cron($frequency);
        }

        /** @var Event $result */
        $result = $event->{self::DEFAULT_FREQUENCY}();

        return $result;
    }

    /**
     * Return the canonical whitelisted method name matching $frequency (case-insensitive),
     * or null when it is not a known cadence.
     */
    private static function matchMethod(string $frequency): ?string
    {
        foreach (self::METHODS as $method) {
            if (strcasecmp($method, $frequency) === 0) {
                return $method;
            }
        }

        return null;
    }

    /** A 5-field cron expression: five whitespace-separated tokens of cron-allowed characters. */
    private static function isCronExpression(string $value): bool
    {
        if ($value === '') {
            return false;
        }

        $fields = preg_split('/\s+/', $value);
        if ($fields === false || count($fields) !== 5) {
            return false;
        }

        foreach ($fields as $field) {
            if (preg_match('#^[0-9*,/\-]+$#', $field) !== 1) {
                return false;
            }
        }

        return true;
    }
}

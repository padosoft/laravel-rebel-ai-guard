<?php

declare(strict_types=1);

namespace Padosoft\Rebel\AiGuard\Support;

/**
 * Scrubs anything that could be PII or a secret out of text BEFORE it is sent to an
 * external LLM: email addresses, phone numbers, long digit runs (OTPs/codes), and bearer
 * tokens. Defence in depth — anomaly cases already carry only hashes, but free-text or
 * future inputs must never leak.
 */
final class PromptSanitizer
{
    public function sanitize(string $text): string
    {
        // Order matters: emails and tokens are redacted before the generic digit rules.
        // Unicode digits (\p{Nd}, /u) are covered so non-ASCII OTPs can't slip through.
        $patterns = [
            '/[\w.+-]+@[\w-]+\.[\w.-]+/u' => '[email]',
            '/\bBearer\s+[A-Za-z0-9._\-]+/i' => '[token]',
            '/\bBasic\s+[A-Za-z0-9+\/=]{16,}/i' => '[token]',
            '/\b(?:sk|ghp|ghs|xox[bp])[-_][A-Za-z0-9_\-]{10,}/' => '[token]',
            '/\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+/' => '[token]',
            '/\+?\p{Nd}[\p{Nd}\s().\-]{6,}\p{Nd}/u' => '[phone]',
            '/\p{Nd}{4,}/u' => '[redacted]',
        ];

        foreach ($patterns as $pattern => $replacement) {
            $text = preg_replace($pattern, $replacement, $text) ?? $text;
        }

        return $text;
    }
}

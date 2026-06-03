<?php

declare(strict_types=1);

namespace Padosoft\Rebel\AiGuard\Testing;

use Padosoft\Rebel\AiGuard\Contracts\AiClient;

/**
 * Deterministic {@see AiClient} for tests: records what it was asked and echoes the user
 * prompt back, so assertions can verify the prompt was sanitized before it left the app.
 */
final class FakeAiClient implements AiClient
{
    public ?string $lastSystemPrompt = null;

    public ?string $lastUserPrompt = null;

    public function complete(string $systemPrompt, string $userPrompt): string
    {
        $this->lastSystemPrompt = $systemPrompt;
        $this->lastUserPrompt = $userPrompt;

        return 'Explanation of: '.$userPrompt;
    }
}

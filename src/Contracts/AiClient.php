<?php

declare(strict_types=1);

namespace Padosoft\Rebel\AiGuard\Contracts;

/**
 * A minimal LLM client. The application binds its own (OpenAI, Anthropic, a local model…);
 * the AI guard only ever sends it **sanitized** prompts and treats the output as advisory.
 */
interface AiClient
{
    public function complete(string $systemPrompt, string $userPrompt): string;
}

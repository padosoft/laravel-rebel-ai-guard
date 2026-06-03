<?php

declare(strict_types=1);

use Padosoft\Rebel\AiGuard\AiExplainer;
use Padosoft\Rebel\AiGuard\Enums\AnomalyType;
use Padosoft\Rebel\AiGuard\Enums\CaseStatus;
use Padosoft\Rebel\AiGuard\Enums\Severity;
use Padosoft\Rebel\AiGuard\Models\AnomalyCase;
use Padosoft\Rebel\AiGuard\Support\PromptSanitizer;
use Padosoft\Rebel\AiGuard\Testing\FakeAiClient;

function makeCase(array $signals): AnomalyCase
{
    $case = new AnomalyCase;
    $case->fill([
        'type' => AnomalyType::OtpBombing,
        'severity' => Severity::High,
        'status' => CaseStatus::Open,
        'dedupe_key' => 'otp_bombing:x',
        'signals' => $signals,
        'events_count' => 12,
        'opened_at' => new DateTimeImmutable('2026-01-01 10:00:00'),
    ]);
    $case->save();

    return $case;
}

it('returns null when no AI client is configured', function (): void {
    $explainer = app(AiExplainer::class);

    expect($explainer->isAvailable())->toBeFalse()
        ->and($explainer->explain(makeCase(['identifier_hmac' => 'abc'])))->toBeNull();
});

it('explains a case via the AI client with a sanitized prompt', function (): void {
    $fake = new FakeAiClient;
    $explainer = new AiExplainer(new PromptSanitizer, $fake);

    // A case whose signals accidentally carry PII must be scrubbed before reaching the AI.
    $case = makeCase(['note' => 'victim mario@example.it phone +393331234567 code 123456']);
    $result = $explainer->explain($case);

    expect($result)->toBeString()
        ->and($fake->lastUserPrompt)->not->toContain('mario@example.it')
        ->and($fake->lastUserPrompt)->not->toContain('393331234567')
        ->and($fake->lastUserPrompt)->not->toContain('123456')
        ->and($fake->lastSystemPrompt)->toContain('never decide');
});

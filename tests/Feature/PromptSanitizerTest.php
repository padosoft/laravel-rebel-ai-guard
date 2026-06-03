<?php

declare(strict_types=1);

use Padosoft\Rebel\AiGuard\Support\PromptSanitizer;

it('redacts emails, phones, codes, and token formats', function (): void {
    $sanitizer = new PromptSanitizer;

    $out = $sanitizer->sanitize(
        'user mario@example.it phone +39 333 1234567 code 482913 '.
        'auth Bearer abc.def.ghijkl jwt eyJ0eXAiOiJKV1Q.eyJzdWIiOiJ4.SflKxwRJ key sk-ABCDEFGHIJ1234'
    );

    expect($out)->not->toContain('mario@example.it')
        ->not->toContain('1234567')
        ->not->toContain('482913')
        ->not->toContain('Bearer abc')
        ->not->toContain('eyJ0eXAi')
        ->not->toContain('sk-ABCDEFGHIJ');
});

it('redacts non-ASCII (Unicode) digit runs', function (): void {
    $sanitizer = new PromptSanitizer;

    // Full-width digits "４８２９１３" must not survive.
    $out = $sanitizer->sanitize('code ４８２９１３ here');

    expect($out)->not->toContain('４８２９１３');
});

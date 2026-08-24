<?php

declare(strict_types=1);

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;
use Padosoft\Iam\Contracts\Delegation\AgentLifecycle;
use Padosoft\Iam\Contracts\Support\SubjectRef;
use Padosoft\Rebel\AiGuard\Detection\AnomalyDetector;
use Padosoft\Rebel\AiGuard\Enums\AnomalyType;
use Padosoft\Rebel\AiGuard\Enums\Severity;
use Padosoft\Rebel\AiGuard\Models\AnomalyCase;
use Padosoft\Rebel\Core\Clock\FakeClock;
use Psr\Clock\ClockInterface;

function delegationWindow(): array
{
    return [new DateTimeImmutable('2026-01-01 09:00:00'), new DateTimeImmutable('2026-01-01 11:00:00')];
}

/** Minimal mirror of the iam-server audit table — only the columns the rules read. */
function createIamAuditTable(): void
{
    Schema::create('iam_audit_events', function (Blueprint $t): void {
        $t->id();
        $t->string('stream');
        $t->string('event_type');
        $t->string('actor_agent_id')->nullable();
        $t->string('organization_id')->nullable();
        $t->json('metadata_json')->nullable();
        $t->timestamp('occurred_at');
    });
}

function recordExchange(string $agentId, bool $issued, ?string $refusalReason = null, string $at = '2026-01-01 10:00:00'): void
{
    app('db')->table('iam_audit_events')->insert([
        'stream' => 'delegation',
        'event_type' => $issued ? 'iam.delegation.exchange.issued' : 'iam.delegation.exchange.refused',
        'actor_agent_id' => $agentId,
        'metadata_json' => json_encode(array_filter(['refusal_reason' => $refusalReason])),
        'occurred_at' => $at,
    ]);
}

beforeEach(function (): void {
    app()->instance(ClockInterface::class, new FakeClock(new DateTimeImmutable('2026-01-01 10:30:00')));
});

it('skips the delegation rules silently when the iam_audit_events table is absent', function (): void {
    expect(app(AnomalyDetector::class)->detect(...delegationWindow()))->toBe(0);
});

it('opens an exchange-burst case per agent, day-bucketed dedupe key', function (): void {
    createIamAuditTable();
    config()->set('rebel-ai-guard.delegation.exchange_burst.threshold', 5);

    for ($i = 0; $i < 5; $i++) {
        recordExchange('agt_busy', issued: true);
    }
    recordExchange('agt_calm', issued: true); // below threshold

    expect(app(AnomalyDetector::class)->detect(...delegationWindow()))->toBe(1);

    $case = AnomalyCase::query()->firstOrFail();
    expect($case->type)->toBe(AnomalyType::DelegationExchangeBurst)
        ->and($case->signals['agent_id'])->toBe('agt_busy')
        ->and($case->events_count)->toBe(5)
        ->and($case->dedupe_key)->toBe('delegation_exchange_burst:agt_busy:20260101');
});

it('opens a scope-probing case on refused exchanges with the refusal-reason breakdown', function (): void {
    createIamAuditTable();
    config()->set('rebel-ai-guard.delegation.scope_probing.threshold', 3);
    config()->set('rebel-ai-guard.delegation.exchange_burst.threshold', 100);

    recordExchange('agt_probe', issued: false, refusalReason: 'delegation_grant_missing');
    recordExchange('agt_probe', issued: false, refusalReason: 'delegation_grant_missing');
    recordExchange('agt_probe', issued: false, refusalReason: 'empty_scope_intersection');

    expect(app(AnomalyDetector::class)->detect(...delegationWindow()))->toBe(1);

    $case = AnomalyCase::query()->where('type', AnomalyType::DelegationScopeProbing->value)->firstOrFail();
    expect($case->signals['refusal_reasons'])->toBe(['delegation_grant_missing' => 2, 'empty_scope_intersection' => 1]);
});

it('does NOT auto-suspend by default, even on a Critical case (advisory-only)', function (): void {
    createIamAuditTable();
    config()->set('rebel-ai-guard.delegation.scope_probing.threshold', 2);
    config()->set('rebel-ai-guard.delegation.exchange_burst.threshold', 100);

    $suspended = [];
    app()->instance(AgentLifecycle::class, new class($suspended) implements AgentLifecycle
    {
        /** @var list<array{string, string, string}> */
        public array $calls;

        /** @param  list<array{string, string, string}>  $calls */
        public function __construct(array &$calls)
        {
            $this->calls = &$calls;
        }

        public function suspend(SubjectRef $agent, string $reason, string $actor): void
        {
            $this->calls[] = [$agent->id, $reason, $actor];
        }
    });

    for ($i = 0; $i < 6; $i++) { // 3× threshold ⇒ Critical
        recordExchange('agt_probe', issued: false, refusalReason: 'delegation_grant_missing');
    }

    app(AnomalyDetector::class)->detect(...delegationWindow());

    expect(AnomalyCase::query()->firstOrFail()->severity)->toBe(Severity::Critical)
        ->and($suspended)->toBe([]); // auto_suspend default false → mai chiamato
});

it('auto-suspends through the AgentLifecycle port when opted in and the case is High+', function (): void {
    createIamAuditTable();
    config()->set('rebel-ai-guard.delegation.scope_probing.threshold', 2);
    config()->set('rebel-ai-guard.delegation.exchange_burst.threshold', 100);
    config()->set('rebel-ai-guard.delegation.auto_suspend', true);

    $suspended = [];
    app()->instance(AgentLifecycle::class, new class($suspended) implements AgentLifecycle
    {
        /** @var list<array{string, string, string}> */
        public array $calls;

        /** @param  list<array{string, string, string}>  $calls */
        public function __construct(array &$calls)
        {
            $this->calls = &$calls;
        }

        public function suspend(SubjectRef $agent, string $reason, string $actor): void
        {
            $this->calls[] = [$agent->id, $reason, $actor];
        }
    });

    for ($i = 0; $i < 4; $i++) { // 2× threshold ⇒ High
        recordExchange('agt_probe', issued: false, refusalReason: 'delegation_grant_missing');
    }

    app(AnomalyDetector::class)->detect(...delegationWindow());

    expect($suspended)->toBe([['agt_probe', 'delegation_scope_probing', 'rebel-ai-guard']])
        ->and(AnomalyCase::query()->firstOrFail()->signals['auto_suspended'] ?? null)->toBeTrue();
});

it('auto-suspend opted in but Medium severity ⇒ no suspension (humans triage first)', function (): void {
    createIamAuditTable();
    config()->set('rebel-ai-guard.delegation.scope_probing.threshold', 3);
    config()->set('rebel-ai-guard.delegation.exchange_burst.threshold', 100);
    config()->set('rebel-ai-guard.delegation.auto_suspend', true);

    $suspended = [];
    app()->instance(AgentLifecycle::class, new class($suspended) implements AgentLifecycle
    {
        /** @var list<array{string, string, string}> */
        public array $calls;

        /** @param  list<array{string, string, string}>  $calls */
        public function __construct(array &$calls)
        {
            $this->calls = &$calls;
        }

        public function suspend(SubjectRef $agent, string $reason, string $actor): void
        {
            $this->calls[] = [$agent->id, $reason, $actor];
        }
    });

    for ($i = 0; $i < 3; $i++) { // exactly threshold ⇒ Medium
        recordExchange('agt_probe', issued: false, refusalReason: 'delegation_grant_missing');
    }

    app(AnomalyDetector::class)->detect(...delegationWindow());

    expect($suspended)->toBe([])
        ->and(AnomalyCase::query()->count())->toBe(1);
});

it('a suspension failure never breaks detection: the case still opens', function (): void {
    createIamAuditTable();
    config()->set('rebel-ai-guard.delegation.scope_probing.threshold', 2);
    config()->set('rebel-ai-guard.delegation.exchange_burst.threshold', 100);
    config()->set('rebel-ai-guard.delegation.auto_suspend', true);

    app()->instance(AgentLifecycle::class, new class implements AgentLifecycle
    {
        public function suspend(SubjectRef $agent, string $reason, string $actor): void
        {
            throw new RuntimeException('iam down');
        }
    });

    for ($i = 0; $i < 4; $i++) {
        recordExchange('agt_probe', issued: false, refusalReason: 'delegation_grant_missing');
    }

    expect(app(AnomalyDetector::class)->detect(...delegationWindow()))->toBe(1);
    expect(AnomalyCase::query()->firstOrFail()->signals)->not->toHaveKey('auto_suspended');
});

<?php

declare(strict_types=1);

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;
use Padosoft\Rebel\AiGuard\Detection\AnomalyDetector;
use Padosoft\Rebel\AiGuard\Enums\AnomalyType;
use Padosoft\Rebel\AiGuard\Enums\CaseStatus;
use Padosoft\Rebel\AiGuard\Enums\Severity;
use Padosoft\Rebel\AiGuard\Models\AnomalyCase;
use Padosoft\Rebel\Core\Clock\FakeClock;
use Padosoft\Routines\Contracts\Lifecycle\RoutineLifecycle;
use Psr\Clock\ClockInterface;

/** @return array{DateTimeImmutable, DateTimeImmutable} */
function routineWindow(): array
{
    return [new DateTimeImmutable('2026-01-01 09:00:00'), new DateTimeImmutable('2026-01-01 11:00:00')];
}

/** Minimal mirror of the laravel-routines tables — only the columns the rules read. */
function createRoutineTables(): void
{
    Schema::create('routines', function (Blueprint $t): void {
        $t->string('id')->primary();
        $t->string('name');
        $t->string('organization_id')->nullable();
    });

    Schema::create('routine_runs', function (Blueprint $t): void {
        $t->id();
        $t->string('routine_id');
        $t->string('outcome')->nullable();
        $t->string('action_class')->nullable();
        $t->text('question')->nullable();
        $t->timestamp('resolved_at')->nullable();
        $t->timestamp('created_at');
    });
}

function makeRoutine(string $id, string $name = 'Nightly reminders', ?string $org = null): void
{
    app('db')->table('routines')->insert(['id' => $id, 'name' => $name, 'organization_id' => $org]);
}

function recordRun(string $routineId, ?string $outcome = 'succeeded', string $at = '2026-01-01 10:00:00', ?string $actionClass = null, ?string $resolvedAt = null, ?string $question = null): void
{
    app('db')->table('routine_runs')->insert([
        'routine_id' => $routineId,
        'outcome' => $outcome,
        'action_class' => $actionClass,
        'question' => $question,
        'resolved_at' => $resolvedAt,
        'created_at' => $at,
    ]);
}

/** Records every suspension the detector asks for, so a test can assert on absence too. */
function fakeRoutineLifecycle(array &$calls): void
{
    app()->instance(RoutineLifecycle::class, new class($calls) implements RoutineLifecycle
    {
        /** @var list<array{string, string, string}> */
        public array $calls;

        /** @param  list<array{string, string, string}>  $calls */
        public function __construct(array &$calls)
        {
            $this->calls = &$calls;
        }

        public function suspend(string $routineId, string $reason, string $actor): void
        {
            $this->calls[] = [$routineId, $reason, $actor];
        }
    });
}

beforeEach(function (): void {
    app()->instance(ClockInterface::class, new FakeClock(new DateTimeImmutable('2026-01-01 10:30:00')));
});

it('skips the routine rules silently when the routines tables are absent', function (): void {
    expect(app(AnomalyDetector::class)->detect(...routineWindow()))->toBe(0);
});

it('opens a fire-burst case per routine, day-bucketed dedupe key', function (): void {
    createRoutineTables();
    config()->set('rebel-ai-guard.routines.fire_burst.threshold', 4);

    makeRoutine('rt_busy', 'Webhook ingest', 'org_1');
    makeRoutine('rt_calm');

    for ($i = 0; $i < 4; $i++) {
        recordRun('rt_busy');
    }
    recordRun('rt_calm'); // below threshold

    expect(app(AnomalyDetector::class)->detect(...routineWindow()))->toBe(1);

    $case = AnomalyCase::query()->firstOrFail();
    expect($case->type)->toBe(AnomalyType::RoutineFireBurst)
        ->and($case->tenant_id)->toBe('org_1')
        ->and($case->signals['routine_id'])->toBe('rt_busy')
        ->and($case->signals['routine_name'])->toBe('Webhook ingest')
        ->and($case->signals['fires'])->toBe(4)
        ->and($case->events_count)->toBe(4)
        ->and($case->dedupe_key)->toBe('routine_fire_burst:rt_busy:20260101');
});

it('counts only failures for the failure-loop rule', function (): void {
    createRoutineTables();
    config()->set('rebel-ai-guard.routines.fire_burst.threshold', 100);
    config()->set('rebel-ai-guard.routines.failure_loop.threshold', 3);

    makeRoutine('rt_broken');
    for ($i = 0; $i < 3; $i++) {
        recordRun('rt_broken', outcome: 'failed');
    }
    // Successes in the same window must not push a healthy routine over the line.
    for ($i = 0; $i < 10; $i++) {
        recordRun('rt_broken', outcome: 'succeeded');
    }

    expect(app(AnomalyDetector::class)->detect(...routineWindow()))->toBe(1);

    $case = AnomalyCase::query()->firstOrFail();
    expect($case->type)->toBe(AnomalyType::RoutineFailureLoop)
        ->and($case->signals['failures'])->toBe(3);
});

it('breaks mandate-probing pauses down by action class', function (): void {
    createRoutineTables();
    config()->set('rebel-ai-guard.routines.fire_burst.threshold', 100);
    config()->set('rebel-ai-guard.routines.mandate_probing.threshold', 3);

    makeRoutine('rt_probe');
    recordRun('rt_probe', outcome: 'paused', actionClass: 'invoice.write_off', resolvedAt: '2026-01-01 10:05:00');
    recordRun('rt_probe', outcome: 'paused', actionClass: 'invoice.write_off', resolvedAt: '2026-01-01 10:06:00');
    recordRun('rt_probe', outcome: 'paused', actionClass: 'invoice.refund', resolvedAt: '2026-01-01 10:07:00');

    expect(app(AnomalyDetector::class)->detect(...routineWindow()))->toBe(1);

    $case = AnomalyCase::query()->firstOrFail();
    expect($case->type)->toBe(AnomalyType::RoutineMandateProbing)
        ->and($case->signals['action_classes'])->toBe(['invoice.write_off' => 2, 'invoice.refund' => 1]);
});

it('opens a starvation case from the FIRST unanswered question, and names the oldest one', function (): void {
    createRoutineTables();
    config()->set('rebel-ai-guard.routines.fire_burst.threshold', 100);
    config()->set('rebel-ai-guard.routines.mandate_probing.threshold', 100);
    config()->set('rebel-ai-guard.routines.approval_starvation.hours', 24);

    makeRoutine('rt_waiting');
    recordRun('rt_waiting', outcome: 'paused', at: '2025-12-29 08:00:00', question: 'Chiudere la fattura INV-003?');
    recordRun('rt_waiting', outcome: 'paused', at: '2025-12-30 08:00:00', question: 'E la INV-004?');

    expect(app(AnomalyDetector::class)->detect(...routineWindow()))->toBe(1);

    $case = AnomalyCase::query()->firstOrFail();
    expect($case->type)->toBe(AnomalyType::RoutineApprovalStarvation)
        ->and($case->signals['unanswered'])->toBe(2)
        ->and($case->signals['oldest_question'])->toBe('Chiudere la fattura INV-003?')
        ->and($case->signals['waiting_since'])->toContain('2025-12-29');
});

it('ignores paused runs that were answered, and those still inside the grace window', function (): void {
    createRoutineTables();
    config()->set('rebel-ai-guard.routines.fire_burst.threshold', 100);
    config()->set('rebel-ai-guard.routines.mandate_probing.threshold', 100);
    config()->set('rebel-ai-guard.routines.approval_starvation.hours', 24);

    makeRoutine('rt_answered');
    // Old but answered.
    recordRun('rt_answered', outcome: 'paused', at: '2025-12-29 08:00:00', resolvedAt: '2025-12-29 09:00:00');
    // Unanswered but only an hour old — a human is plausibly still asleep, not absent.
    recordRun('rt_answered', outcome: 'paused', at: '2026-01-01 10:00:00');

    expect(app(AnomalyDetector::class)->detect(...routineWindow()))->toBe(0)
        ->and(AnomalyCase::query()->count())->toBe(0);
});

it('does NOT auto-suspend by default, even on a Critical case (advisory-only)', function (): void {
    createRoutineTables();
    config()->set('rebel-ai-guard.routines.fire_burst.threshold', 2);

    $suspended = [];
    fakeRoutineLifecycle($suspended);

    makeRoutine('rt_runaway');
    for ($i = 0; $i < 6; $i++) { // 3× threshold ⇒ Critical
        recordRun('rt_runaway');
    }

    app(AnomalyDetector::class)->detect(...routineWindow());

    expect(AnomalyCase::query()->firstOrFail()->severity)->toBe(Severity::Critical)
        ->and($suspended)->toBe([]);
});

it('auto-suspends through the RoutineLifecycle port when opted in and the case is High+', function (): void {
    createRoutineTables();
    config()->set('rebel-ai-guard.routines.fire_burst.threshold', 2);
    config()->set('rebel-ai-guard.routines.auto_suspend', true);

    $suspended = [];
    fakeRoutineLifecycle($suspended);

    makeRoutine('rt_runaway');
    for ($i = 0; $i < 4; $i++) { // 2× threshold ⇒ High
        recordRun('rt_runaway');
    }

    app(AnomalyDetector::class)->detect(...routineWindow());

    expect($suspended)->toBe([['rt_runaway', 'routine_fire_burst', 'rebel-ai-guard']])
        ->and(AnomalyCase::query()->firstOrFail()->signals['auto_suspended'])->toBeTrue();
});

it('still opens the case when the suspension throws', function (): void {
    createRoutineTables();
    config()->set('rebel-ai-guard.routines.fire_burst.threshold', 2);
    config()->set('rebel-ai-guard.routines.auto_suspend', true);

    app()->instance(RoutineLifecycle::class, new class implements RoutineLifecycle
    {
        public function suspend(string $routineId, string $reason, string $actor): void
        {
            throw new RuntimeException('routines service unreachable');
        }
    });

    makeRoutine('rt_runaway');
    for ($i = 0; $i < 4; $i++) {
        recordRun('rt_runaway');
    }

    app(AnomalyDetector::class)->detect(...routineWindow());

    $case = AnomalyCase::query()->firstOrFail();
    expect($case->type)->toBe(AnomalyType::RoutineFireBurst)
        // Nessun `auto_suspended`: il caso non deve dire di aver fatto qualcosa che non ha fatto.
        ->and($case->signals)->not->toHaveKey('auto_suspended');
});

it('refreshes an open case in place instead of opening a second one', function (): void {
    createRoutineTables();
    config()->set('rebel-ai-guard.routines.fire_burst.threshold', 2);

    makeRoutine('rt_busy');
    recordRun('rt_busy');
    recordRun('rt_busy');

    app(AnomalyDetector::class)->detect(...routineWindow());
    recordRun('rt_busy');
    app(AnomalyDetector::class)->detect(...routineWindow());

    expect(AnomalyCase::query()->count())->toBe(1)
        ->and(AnomalyCase::query()->firstOrFail()->events_count)->toBe(3)
        ->and(AnomalyCase::query()->firstOrFail()->status)->toBe(CaseStatus::Open);
});

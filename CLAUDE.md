# CLAUDE.md

Vedi **`AGENTS.md`** per le regole operative complete (branching, Definition of Done, loop locale + gate GitHub, guardrail, README didattici, design-lock).

All'avvio di ogni sessione, in quest'ordine:
1. Leggi `docs/LESSON.md` (knowledge accumulato — vale per te e per ogni subagent).
2. Leggi `docs/PROGRESS.md` (dove eravamo rimasti).
3. Leggi `docs/IMPLEMENTATION-PLAN.md` (piano completo) e `AGENTS.md` (regole).

Promemoria chiave:
- **`copilot` solo con `-p`** (altrimenti si blocca).
- **Una PR per macro-task**; sotto-task = commit locali con loop locale (test + Playwright se UI + review Copilot locale).
- **README didattici e prolissi** con molti esempi: l'accessibilità per junior è un requisito.
- Aggiorna `PROGRESS.md` ad ogni sotto-task e `LESSON.md` quando impari qualcosa.

---

# AI working guide for `padosoft/laravel-rebel-ai-guard`

> Working on this package with an AI agent (Claude Code, Cursor, Copilot, Codex)? Read this.
> It's the "batteries" that make vibe-coding here land on the first try. Plain Markdown — every
> tool can read it.

## What this package is
Anomaly detection + AI security copilot for Laravel Rebel: deterministic rules detect anomaly cases;
the optional AI only explains/suggests (sanitized prompts, no PII/OTP, human review).

Part of the **Laravel Rebel** suite — an enterprise authentication control plane over Laravel
Fortify. The shared language (value objects, contracts, the audit trail) lives in
`padosoft/laravel-rebel-core`; this package builds on it.

## Non-negotiable conventions
- `declare(strict_types=1);` in every PHP file; `final` classes; constructor property promotion.
- **PHPStan level max** must stay green. Do NOT add `@phpstan-ignore`, baseline entries, or
  `assert()`/inline `@var` to silence errors — fix the root cause. Common recipes:
  - narrow `mixed` before casting: `is_scalar($x) ? (string) $x : null`;
  - `json_decode($s, true)` is `array<array-key, mixed>`;
  - the container's `make('request')` is already typed `Illuminate\Http\Request`;
  - use `cursor()` for large scans, `withoutGlobalScopes()` for cross-tenant admin reads;
  - nested Eloquent `where(fn ($q) => …)` closures receive `Illuminate\Database\Eloquent\Builder`.
- **Tests:** Pest, Testbench. Cover happy path, auth/fail-closed, tenant-scoping, empty state.
- **Style:** Pint (`composer pint`). **Docs/comments in English.**
- Package wiring uses `spatie/laravel-package-tools` (`configurePackage`).

## Security & telemetry rules (suite-wide)
- Never store PII in cleartext: identifiers, IPs and User-Agents are **keyed HMACs** (core
  `KeyedHasher`). Never log OTPs/secrets (the `Redactor` sanitizes audit metadata).
- The AI **explains, never decides**: the LLM only ever sees **sanitized** prompts (via
  `src/Support/PromptSanitizer.php` — no PII, no OTPs, no tokens) and its output is advisory.
  Destructive actions stay manual / human-reviewed.
- **Telemetry completeness:** if this package is a channel/driver/bridge/provider, it MUST capture
  everything that fills the admin panel. Record through the core `AuditLogger` contract — it persists
  to `rebel_auth_events` (never session), **configurable sync|queue** (Horizon-ready). Surface an
  honest empty state — never fake data.

## How to extend it
- Add a deterministic rule to `src/Detection/AnomalyDetector.php`; rules open `AnomalyCase`s
  (`src/Models/AnomalyCase.php`) from the audit log. New anomaly kinds go in
  `src/Enums/AnomalyType.php`, with `src/Enums/Severity.php` / `src/Enums/CaseStatus.php`.
- The `rebel:detect-anomalies` command (`src/Console/DetectAnomaliesCommand.php`) is scheduled
  (`src/Support/ScheduleFrequency.php`) — wire new detection passes through it.
- The optional explainer is `src/AiExplainer.php` behind the `src/Contracts/AiClient.php` contract;
  test against `src/Testing/FakeAiClient.php`. Anything sent to the AI must pass through
  `PromptSanitizer` first.

## Definition of Done (per change)
1. Red→green with Pest; `composer phpstan` (max) + `composer pint -- --test` clean.
2. One feature branch, one PR to `main`. CI matrix **PHP 8.3/8.4/8.5 × Laravel 12/13** must be green.
3. Update `README.md` + `CHANGELOG.md`. Squash-merge.
4. **Release:** `git tag vX.Y.Z && git push origin vX.Y.Z` + `gh release create`. Stay in `0.1.x`
   (Composer `^0.1` excludes `0.2.0` and would break dependents).

## Skills
This repo ships invocable skills under `.claude/skills/` — at least `rebel-package-dev` (the dev
loop + PHPStan-max recipes). Invoke it before non-trivial work.

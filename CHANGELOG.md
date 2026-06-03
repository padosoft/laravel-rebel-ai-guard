# Changelog

All notable changes to `padosoft/laravel-rebel-ai-guard` are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.2] - 2026-06-03

### Added
- **Configurable schedule frequency** — new `detect.frequency` config (env
  `REBEL_AIGUARD_FREQUENCY`, default `hourly`) drives how often the scheduled
  `rebel:detect-anomalies` command runs. Accepts a whitelisted cadence name (`everyMinute`,
  `everyFiveMinutes`, `everyTenMinutes`, `everyThirtyMinutes`, `hourly`, `daily`, …) **or** a
  raw 5-field cron expression (e.g. `*/15 * * * *`), applied via the scheduler's `->cron()`.
  Only whitelisted names are ever called as methods; an unrecognised, non-cron value falls back
  to `hourly` — never an arbitrary method call.
- **`--from` / `--to` command options** — run detection over an explicit ISO-8601 window
  (overrides `--lookback` when both are given; `--to` defaults to "now" when only `--from` is
  passed). Lets you simulate a cron run over any past window or backfill. Invalid datetimes, or
  a `--to` not after `--from`, print an error and exit non-zero.

### Changed
- The scheduled invocation now passes the configured lookback explicitly
  (`rebel:detect-anomalies --lookback=<minutes>`) so a cron run and a manual run scan the same
  window.

## [0.1.1] - 2026-06-03

### Added
- **`rebel:detect-anomalies` command** — runs `AnomalyDetector::detect()` over a lookback
  window ending "now" (PSR-20 clock), prints how many cases were opened/updated, and exits 0.
  Default lookback is `rebel-ai-guard.detect.lookback_minutes` (1440 = 24h); `--lookback=<min>`
  overrides it for a single run.
- **Automatic detection** — the service provider schedules the command **hourly** so anomaly
  cases appear on their own, no manual call needed. Scheduling is registered only in console
  context and is gated behind `rebel-ai-guard.detect.schedule` (default `true`); set it to
  `false` (env `REBEL_AIGUARD_SCHEDULE=false`) to opt out.
- Config `detect` section (`schedule`, `lookback_minutes`).

## [0.1.0] - 2026-06-03

### Added
- **`AnomalyDetector`** (deterministic): scans `rebel_auth_events` and opens **anomaly
  cases** from fixed rules — v0.1.0 ships OTP-bombing (failed email-OTP verifications per
  identifier), with severity escalating by volume. Cases are de-duplicated by a stable key
  (idempotent re-runs) and tenant-aware.
- **AI explainer (advisory only)**: `AiExplainer` asks an optional, app-provided `AiClient`
  to *explain* a case — never to decide. Prompts are **sanitized** first (`PromptSanitizer`
  scrubs emails, phones, OTP/digit runs incl. Unicode, and Bearer/Basic/JWT/key tokens) and
  the system prompt carries anti-injection instructions. With no `AiClient` bound, it returns null.
- `AnomalyCase` model + migration (ULID), enums, `FakeAiClient` for tests, config.
- CI matrix (PHP 8.3/8.4/8.5 × Laravel 12/13), Pest suite, PHPStan level max, Pint.

[Unreleased]: https://github.com/padosoft/laravel-rebel-ai-guard/compare/v0.1.2...HEAD
[0.1.2]: https://github.com/padosoft/laravel-rebel-ai-guard/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/padosoft/laravel-rebel-ai-guard/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/padosoft/laravel-rebel-ai-guard/releases/tag/v0.1.0

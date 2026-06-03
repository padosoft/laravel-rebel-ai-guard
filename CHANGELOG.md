# Changelog

All notable changes to `padosoft/laravel-rebel-ai-guard` are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
[Semantic Versioning](https://semver.org/).

## [Unreleased]

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

[Unreleased]: https://github.com/padosoft/laravel-rebel-ai-guard/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/padosoft/laravel-rebel-ai-guard/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/padosoft/laravel-rebel-ai-guard/releases/tag/v0.1.0

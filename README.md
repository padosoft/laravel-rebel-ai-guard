# Laravel Rebel — AI Guard

> **Deterministic anomaly detection, with an AI that explains — never decides.** Fixed rules open anomaly cases (e.g. OTP bombing) from your audit log; an optional LLM can then describe a case in plain language. The AI only ever sees **sanitized** prompts (no PII, no OTPs, no tokens) and its output is advisory — humans review, destructive actions stay manual. Part of the `padosoft/laravel-rebel-*` suite.

<p align="center">
  <img src="resources/screenshoots/Laravel-Rebel-banner.png" alt="Laravel Rebel" width="100%">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Laravel-12%20%7C%2013-FF2D20?style=flat-square&logo=laravel&logoColor=white" alt="Laravel 12|13">
  <img src="https://img.shields.io/badge/PHP-8.3%20%7C%208.4%20%7C%208.5-777BB4?style=flat-square&logo=php&logoColor=white" alt="PHP 8.3+">
  <img src="https://img.shields.io/badge/PHPStan-max-2A6FDB?style=flat-square" alt="PHPStan max">
  <img src="https://img.shields.io/badge/tests-Pest%204-22C55E?style=flat-square" alt="Pest 4">
  <img src="https://img.shields.io/badge/AI-explains%2C%20never%20decides-8B5CF6?style=flat-square" alt="AI explains">
  <img src="https://img.shields.io/badge/license-MIT-blue?style=flat-square" alt="MIT">
</p>

---

## Table of contents

- [What it is](#what-it-is)
- [The golden rule](#the-golden-rule)
- [Why this package](#why-this-package)
- [Rebel AI Guard vs the alternatives](#rebel-ai-guard-vs-the-alternatives)
- [Installation](#installation)
- [Usage](#usage)
- [Security notes](#security-notes)
- [`.env.example`](#envexample)
- [Testing & License](#testing--license)

---

## What it is

Two things, deliberately separated:

1. **Deterministic anomaly detection** — `AnomalyDetector` scans `rebel_auth_events` and opens
   **anomaly cases** from fixed, auditable rules (v0.1.0: OTP bombing; more rules to come).
   No black box decides anything.
2. **An AI explainer (optional)** — `AiExplainer` can ask an LLM you provide to *describe* a
   case for an operator. It is advisory only, sees only sanitized input, and is absent unless
   you bind an `AiClient`.

Depends on [`padosoft/laravel-rebel-core`](https://github.com/padosoft/laravel-rebel-core).

---

## The golden rule

> **The rules decide. The AI explains. Humans approve anything destructive.**

The AI never opens, closes, or mitigates a case. It turns a case's signals into a sentence.
Everything that *acts* is deterministic and auditable.

---

## Why this package

| ★ | What | In short |
|---|---|---|
| ★★★ | **Deterministic, auditable detection** | Cases come from fixed rules you can read and test — not a model's whim. |
| ★★★ | **AI input is sanitized** | Emails, phones, OTP/digit runs (incl. Unicode) and Bearer/Basic/JWT/key tokens are scrubbed before any prompt leaves the app. |
| ★★★ | **AI is advisory + injection-resistant** | The system prompt forbids deciding and treats case data as opaque (no prompt injection). |
| ★★ | **Optional AI** | No `AiClient` bound? Detection still works; the explainer just returns null. |
| ★★ | **Idempotent + tenant-aware** | Cases de-duplicate by a stable key; re-runs update in place; rows are tenant-scoped. |
| ★★ | **Bring your own model** | Bind OpenAI, Anthropic, or a local model behind a one-method contract. |

---

## Rebel AI Guard vs the alternatives

| Capability | **Rebel AI Guard** | Shopify | "AI fraud" black boxes | DIY log scripts |
|---|:---:|:---:|:---:|:---:|
| Deterministic, testable rules you own | ✅ | ❌ | ❌ | ➖ |
| AI **explains**, never decides | ✅ | ❌ | ❌ | n/a |
| Prompt sanitization (no PII/secret leak to LLM) | ✅ | ❌ | ❌ | n/a |
| Prompt-injection-resistant system prompt | ✅ | ❌ | ➖ | n/a |
| Works with NO AI configured | ✅ | ➖ | ❌ | ✅ |
| Idempotent, de-duplicated cases | ✅ | ➖ | ➖ | ❌ |
| Self-hosted over your own audit log | ✅ | ❌ | ❌ | ✅ |
| Tenant-aware + audit-native (your app) | ✅ | ❌ | ❌ | ❌ |

> Legend: ✅ built-in · ➖ partial / hosted-only / not exposed to you · ❌ not available.
>
> Note: Shopify is a hosted, closed commerce platform — it runs its own opaque fraud scoring on its checkout, but never gives you a deterministic anomaly engine, a sanitized explain-not-decide AI, or rules you can read, test, and self-host over your own audit log.

---

## Installation

```bash
composer require padosoft/laravel-rebel-ai-guard
php artisan vendor:publish --tag="rebel-ai-guard-migrations"
php artisan migrate
```

---

## Usage

**Run detection** (schedule it, e.g. every few minutes):

```php
use Padosoft\Rebel\AiGuard\Detection\AnomalyDetector;

$opened = app(AnomalyDetector::class)->detect(
    now()->subHour(),
    now(),
); // returns how many cases were opened/updated
```

**Explain a case** (optional AI):

```php
use Padosoft\Rebel\AiGuard\AiExplainer;
use Padosoft\Rebel\AiGuard\Models\AnomalyCase;

$explainer = app(AiExplainer::class);
$case = AnomalyCase::query()->findOrFail($id);

$text = $explainer->explain($case); // null if no AiClient is bound
```

**Bring your own model** — implement and bind the contract:

```php
use Padosoft\Rebel\AiGuard\Contracts\AiClient;

$this->app->singleton(AiClient::class, MyOpenAiClient::class);
```

---

## Security notes

- **No PII/secret to the LLM**: `PromptSanitizer` scrubs emails, phone numbers, 4+ digit
  runs (incl. Unicode), and Bearer/Basic/JWT/`sk-`/`ghp_`/`xox*` tokens before sending.
- **No decisions by AI**: the system prompt forbids deciding/recommending destructive actions
  and instructs the model to treat case data as opaque (prompt-injection resistant).
- **Deterministic core**: cases come from fixed rules; the audit log already stores only
  HMAC'd identifiers, so cases carry hashes, not raw PII.
- **Tenant-scoped, idempotent**: re-running the detector updates open cases instead of
  duplicating them.

---

## `.env.example`

```dotenv
REBEL_AIGUARD_OTP_BOMBING_THRESHOLD=10
```

---

## Testing & License

```bash
composer test      # Pest (detection, idempotency, severity, sanitizer, AI explainer)
composer phpstan   # static analysis, level max
composer pint      # code style
```

**License:** MIT — see [LICENSE](LICENSE). Part of the [`padosoft/laravel-rebel`](https://github.com/padosoft) suite.

# Copilot Instructions — code-audit

## What This Product Is

A **confidence engine for beginner Vibe Coders** — people who build software with AI (Copilot, ChatGPT, Cursor) and want to know: *"Is this okay? Will this blow up later? What should I fix first?"*

This is **not** a linter, static analysis dashboard, or developer toolbox. The AST-based analysis engine is invisible machinery. The product surface speaks in **signals, vibes, and next actions** — never in compiler language.

## Target User Mental Model

Vibe Coders value **confidence, momentum, and clarity** over technical purity. They don't ask "Is my cyclomatic complexity too high?" — they ask "Am I doing something stupid?" Every UX decision flows from this.

## Architecture (Three Layers)

```
src/code_audit/
├─ core/             # AST engine: discover, parse, fingerprints, registry, runner
├─ analyzers/        # built-in analysis modules (complexity, exceptions, security, etc.)
├─ model/            # internal: RawIssue, Finding, RunResult, enums
├─ config/           # loads toml/yaml, merges defaults + overrides
├─ insights/         # THE PRODUCT LAYER — translates findings → signals
│  ├─ translator.py  # engine findings → beginner-friendly signals
│  ├─ confidence.py  # overall vibe score (green/yellow/red)
│  └─ next_action.py # "what to do next" recommender
├─ outputs/          # JSON, SARIF, Markdown serializers
├─ api/              # public.py — stable API: run_scan(), explain(), diff()
├─ ui/               # Rich TUI (presentation only)
└─ gpt/              # optional GPT tool-call adapter
```

### Layer boundaries (critical)

- **Engine** (`core/` + `analyzers/`): produces `RawIssue` → `Finding` → `RunResult`. Never talks to users.
- **Insight layer** (`insights/`): translates engine output into product-facing signals. This is where the product IP lives.
- **Clients** (`ui/`, `gpt/`, `api/`): consume insight-layer output. Never call analyzers directly.

## Signal Translation (Engine → Product)

Engine findings must **never** be shown raw. The insight layer translates:

| Engine Output | Product Signal |
|---|---|
| High cyclomatic complexity | "This function is doing too much. AI wrote it fast, but humans will struggle." |
| Bare/broad except | "Errors might disappear silently. This makes bugs very hard to debug." |
| Hardcoded secret | "If this code leaks, someone could access your stuff." |
| Global mutable state | "Multiple things can change this at once. That causes spooky bugs." |
| Unused code detected | "This code isn't doing anything. Safe to clean up when you're ready." |

### Three-tier signal model (maximum for user-facing output)

- 🟢 **Safe** — "You don't need to do anything right now"
- 🟡 **Clean up** — "You should clean this up when you get a chance"
- 🔴 **Risky** — "This can bite you later"

Never show more than three severity levels to the user. Internal `CRITICAL/HIGH/MEDIUM/LOW/INFO` maps down to these three.

## Canonical Analyzer → Confidence Impact Mapping

Spec for `insights/confidence.py` and `insights/translator.py`. Each analyzer answers one question: **How does this affect a beginner's willingness to keep building?**

### Summary

| Analyzer | Impact | Penalty | Max | Red? | Shown by Default | Beginner Framing |
|---|---|---:|---:|---|---|---|
| Complexity | Mild − | −4/hotspot | −10 | ❌ | Only if severe | "Works now, harder later" |
| Exceptions | High − | −12/signal | −25 | ✅ | Yes | "Errors can disappear" |
| Security | Very high − | −20 | −30 | ✅ | Yes | "Risk if this code is shared" |
| Safety | High − | −15 | −20 | ✅ | Yes | "Needs guardrails" |
| Global State | Medium − | −6 | −12 | ❌ | Conditional | "Can cause weird bugs later" |
| Dead Code | Neutral | 0 | 0 | ❌ | No | "Safe cleanup" |

### Per-analyzer spec

**1. Complexity** — *"This works, but I'm scared to touch it."*
- Risk type: fragility anxiety, AI-code uncertainty
- Recovery: low. Fix urgency: low.
- UX: never shown as urgent, never blocks confidence, always paired with "AI often writes code like this"

**2. Exceptions** — *"If something breaks, I won't know why."*
- Risk type: loss of control, debugging dread
- Recovery: very high. Fix urgency: high.
- UX: prime candidate for "Fix this first", always presented as *easy peace-of-mind win*

**3. Security** — *"I might accidentally expose myself or get hacked."*
- Risk type: exposure panic, shame/recklessness fear
- Recovery: medium. Fix urgency: immediate (contextual by repo visibility).
- UX: severity contextualized by repo visibility, calm language (never alarmist), one-step fix guidance

**4. Safety** — *"I didn't realize this could cause real-world harm."*
- Risk type: responsibility shock, moral fear (not technical fear)
- Recovery: medium. Fix urgency: guided.
- UX: never blame or shame, always paired with explanation, treated as *learning moment* not failure

**5. Global State** — *"Sometimes it works, sometimes it doesn't."*
- Risk type: unpredictability anxiety, "spooky bugs"
- Recovery: low. Fix urgency: medium.
- UX: suppressed unless multiple mutation sites, never top priority unless paired with exceptions

**6. Dead Code** — *"Did I mess up… or is this just extra?"*
- Risk type: self-doubt, fear of deleting the wrong thing
- Recovery: positive. Fix urgency: optional.
- UX: hidden by default, shown as optional tidying, reward confident deferral or deletion

### Compound confidence effects

Some combinations **multiply fear** — the insight layer must merge these into **one narrative signal**, never separate bullets:

| Combination | Merged story |
|---|---|
| Complexity + swallowed exceptions | "I don't understand it AND errors vanish" → 🔴 |
| Global state + exceptions | "Random bugs I can't debug" → 🔴 |
| Safety + complexity | "Dangerous and I don't understand it" → 🔴 |

### Non-negotiable rule

> **If an analyzer does not meaningfully change a beginner's confidence, it must not surface by default.**

Analyzers are *inputs to confidence*, not features.

## Canonical UI Copy (`insights/translator.py`)

Production-ready copy for each analyzer. Five layers per signal — beginners need different tones at different depths:

1. **Signal Title** — what they scan with their eyes
2. **One-line Summary** — emotional reassurance first
3. **Why This Matters** — no jargon
4. **What To Do Next** — single action
5. **Reassurance Footer** — keeps confidence intact

### Complexity → 🟡

- **Title**: "This code is doing a lot at once"
- **Summary**: It works right now, but it might be hard to change later.
- **Why**: When a function gets big, small changes can accidentally break things. This is very common in AI-generated code — you didn't cause this.
- **Action** (optional): If you ever need to change this, consider breaking it into smaller pieces. You can safely ignore this for now.
- **Footer**: ✅ Totally fine to leave as-is while you're building.

### Exceptions → 🔴

- **Title**: "Errors might disappear silently"
- **Summary**: If something breaks here, you might never see the error.
- **Why**: When errors are caught too broadly, bugs can hide instead of telling you what happened. That makes problems much harder to debug later.
- **Action** (recommended, easy win): Add logging or re-raise the error so you can see what happened.
- **Footer**: 🛠️ This is a small change that gives you a lot more peace of mind.

### Security → 🔴

- **Title**: "Sensitive info is hard-coded here"
- **Summary**: If this code is shared, someone else could access your account or service.
- **Why**: Hard-coded keys can be copied by anyone who sees the code. This is one of the most common beginner mistakes — and very fixable.
- **Action** (important): Move this value to an environment variable.
- **Footer**: 🔒 Once this is moved out, the risk is completely gone.

### Safety → 🔴

- **Title**: "This code controls something real and needs guardrails"
- **Summary**: This function affects real-world behavior and should fail safely.
- **Why**: When code controls physical actions or important systems, it's important to be explicit about safety. This isn't about blame — it's about protecting users and yourself.
- **Action** (recommended): Add the safety annotation or checks so unsafe actions can't happen accidentally.
- **Footer**: 🧠 You're catching this early — that's a good sign.

### Global State → 🟡

- **Title**: "This value can change from different places"
- **Summary**: This can lead to confusing bugs that are hard to track down.
- **Why**: When many parts of the code can change the same value, behavior can feel random. These bugs aren't obvious — even experienced developers hit them.
- **Action** (optional): If things start acting strangely, consider passing this value explicitly instead.
- **Footer**: 🧪 If nothing feels flaky right now, totally fine to leave for now.

### Dead Code → 🟢

- **Title**: "Some code might not be used anymore"
- **Summary**: This code doesn't appear to be called anywhere.
- **Why**: Unused code can make projects harder to understand, but it's not dangerous.
- **Action** (optional): You can delete it if you're confident — or leave it until later.
- **Footer**: ✅ Leaving unused code won't break anything.

### Compound signal copy (merged stories)

**Complexity + Exceptions** → "This code is hard to change and hides errors"
- Summary: If this breaks, it may be hard to understand why.
- Action: Start by making errors visible — that alone improves things a lot.

**Global State + Exceptions** → "This can cause random-feeling bugs"
- Summary: Values can change unexpectedly, and errors may not explain why.
- Action: Fix error handling first — it gives you clarity immediately.

### Copy design rules (non-negotiable)

1. **Never use jargon** — no "cyclomatic," "mutation," "scope"
2. **Always reassure first**, then explain
3. **Only one action per signal**
4. **"Later" is a valid choice**
5. **No shame, ever**

Sanity check: if a beginner reads a card and thinks *"Okay, I understand this, and I'm not screwed"* — the copy is right.

## Action Button Microcopy

Three buttons on every signal card. Every click must feel like a smart, safe choice.

### Button layout (always this order, left → right)

```
[ Fix now ]   [ Later ]   [ I get it ]
```

Action → Permission → Understanding. Mirrors beginner mental flow. Never reverse.

### Core buttons

**Fix now** — emotional intent: relief, control, momentum
- Tooltip: "Takes just a few minutes"
- Shows on: high-confidence issues with clear, small fixes
- Internal meaning: active resolution → strong positive confidence signal
- Contextual variants: "Secure this now" (security), "Make errors visible" (exceptions), "Add guardrails" (safety), "Let's fix this" (extra soft)

**Later** — emotional intent: permission, reduced anxiety, autonomy
- Tooltip: "Totally okay to come back to this"
- Shows on: always available, especially for complexity and global state
- Internal meaning: confident deferral → small positive confidence signal
- Contextual variants: "Later is fine" (non-urgent), "Not now" (optional cleanup), "Ship first" (early MVP)
- **"Later" is NOT dismissal.** Never use "Ignore", "Skip", or "Dismiss" — those feel like mistakes.

**I get it** — emotional intent: understanding, closure, reduced confusion. **Most important button for beginners.**
- Tooltip: "Thanks — this makes sense now"
- Shows on: after explanation text, on every signal card
- Internal meaning: user gained clarity → strong confidence lift even without a fix
- Contextual variants: "That makes sense" (longer explanations), "Got it" (mobile/compact), "Okay, understood" (accessibility)

### Subtext by risk level

| Button | 🔴 High risk | 🟡 Medium risk | 🟢 Low risk |
|---|---|---|---|
| Fix now | "Quick win for peace of mind" | "Optional improvement" | "Optional cleanup" |
| Later | "If this isn't urgent right now" | "Safe to leave for now" | "No rush at all" |
| I get it | "I understand the risk" | "I see why this matters" | "Okay, that's clear" |

### Post-click micro-feedback

- After **Fix now**: ✅ "Nice — you're making this better."
- After **Later**: 👍 "No worries — it'll be here when you're ready."
- After **I get it**: 💡 "Cool — now you know."

### Confidence scoring hook

| Button | Effect |
|---|---|
| Fix now | +High |
| I get it | +Medium |
| Later | +Low but positive |
| No interaction | 0 |

Never punish a user for choosing "Later."

### Forbidden button labels

Never use: ❌ Ignore, ❌ Dismiss, ❌ Skip, ❌ Not important, ❌ False positive. These imply blame or error.

### Design principle

> **Every button should feel like a smart, safe choice.** If clicking something makes a beginner wonder "Did I just do something wrong?" — the copy failed.

## Confidence Scoring Algorithm (`insights/confidence.py`)

Returns: `confidence_score` (0–100), `vibe_tier` (green/yellow/red), `top_concern`, `next_best_action`, `confidence_lift` (after − before).

### Formula

```
score = clamp(base − risk_penalty − overwhelm_penalty + recovery_bonus, 0, 100)
```

- `base = 78` (start optimistic — beginners need reassurance)
- `risk_penalty = Σ [ weight(type) × severity_factor × volume_factor × confidence_factor × interaction_factor ]`
- `recovery_bonus = Σ [ action_bonus(user_action, fix_effort, type) ]`
- `overwhelm_penalty = 1.5 × max(0, total_signals − 5) + 0.15 × max(0, total_findings − 20)`

### Parameter tables

**Severity factor** — maps internal severity to multiplier:

| Severity | Factor |
|---|---:|
| INFO | 0.3 |
| LOW | 0.6 |
| MEDIUM | 1.0 |
| HIGH | 1.4 |
| CRITICAL | 2.0 |

**Type weights** — how scary each category is for beginners:

| Signal type | Weight |
|---|---:|
| secrets | 14 |
| exceptions | 11 |
| safety | 10 |
| global_state | 6 |
| complexity | 4 |
| dead_code | 1 |

**Volume factor** — diminishing returns: `1 + 0.35 × ln(1 + count)`

**Confidence factor** — calibrates for heuristic detectors: `0.6 + 0.4 × detector_confidence`

**Interaction factor** — compound fear amplification between signal types:

| Combination | Factor |
|---|---:|
| exceptions + complexity | 1.15 |
| exceptions + global_state | 1.20 |
| safety + complexity | 1.15 |
| all others | 1.0 |

### Default detector confidence values

| Rule type | Confidence |
|---|---:|
| Complexity metrics | 0.95 |
| Bare except | 0.95 |
| Swallowed exception classification | 0.85 |
| Global state mutation inference | 0.75 |
| Secrets regex | 0.70 |
| Safety indicator string match | 0.65 |
| Dead code heuristic | 0.55 |

### Recovery bonus (drives CLR upward)

Rewards *understanding and progress*, not perfect code:

| User action | Easy fix | Medium | Hard |
|---|---:|---:|---:|
| Fixed | +14 | +10 | +7 |
| Acknowledged ("I get it") | +6 | +5 | +4 |
| Deferred ("later") | +4 | +3 | +2 |
| Ignored / none | 0 | 0 | 0 |

Type multiplier on bonus: secrets ×1.2, exceptions ×1.1, safety ×1.1, others ×1.0.

### Fix effort heuristic

- **Easy**: bare `except:`, obvious hardcoded secret, missing decorator (count ≤ 2)
- **Medium**: broad except patterns across file, global state with multiple mutation sites
- **Hard**: complexity hotspots with cyclomatic ≥ 25, systemic issues across many files

### Vibe tier thresholds

| Tier | Score range |
|---|---|
| 🟢 Green | ≥ 75 |
| 🟡 Yellow | 55–74 |
| 🔴 Red | < 55 |

**Hard-stop red triggers** (regardless of score): any HIGH/CRITICAL secrets signal, any CRITICAL safety signal, any CRITICAL exceptions signal. Prevents false comfort.

## Product-Facing Output Schema

The API returns signals, not findings. Shape:

```json
{
  "project_id": "abc123",
  "scan_id": "scan_2026_02_10",
  "overall_vibe": "yellow",
  "confidence_score": 72,
  "summary": {
    "status": "You're mostly fine, but there's one risky area.",
    "primary_concern": "Error handling could hide real bugs."
  },
  "signals": [
    {
      "id": "sig_001",
      "level": "warning",
      "title": "Errors may be swallowed",
      "why_it_matters": "If something breaks, you might never know.",
      "where": "src/app/core.py",
      "suggested_action": "Add logging or re-raise the exception",
      "difficulty": "easy",
      "can_wait": true
    }
  ],
  "what_to_do_next": {
    "recommendation": "Fix the error handling first",
    "estimated_time_minutes": 10,
    "confidence_boost": "+15%"
  }
}
```

## Engine Internals (for contributors working below the insight layer)

### Data flow
```
Analyzers emit RawIssue → RuleCatalog defines policy → Runner normalizes to Finding → insights/ translates to Signal
```

### Analyzer contract
```python
class Analyzer(Protocol):
    id: str
    version: str
    produced_rules: tuple[str, ...]
    def run(self, ctx: ScanContext) -> Iterable[RawIssue]: ...
```

### Adding a new analyzer
1. Create module in `analyzers/` implementing the `Analyzer` protocol
2. Register rules in `core/registry.py` via `RuleCatalog.add()`
3. Add signal translation mapping in `insights/translator.py`
4. Runner auto-discovers registered analyzers

### Engine conventions
- **Stable finding IDs**: `sha256(rule_id | relative_path | symbol | normalized_snippet)`
- **Rule IDs are namespaced**: `CATEGORY-SUBCATEGORY-NNN` (e.g., `EXC-BARE-001`)
- **Heuristic results must set `confidence` < 1.0**
- **All thresholds configurable** via `code_audit.toml`
- **File discovery** respects `.gitignore`; vendored/generated code excluded by default

## North-Star Metric: Confidence Lift Rate (CLR)

> **"We measure success by how often beginner developers leave our product feeling confident enough to keep building."**

If a feature doesn't improve CLR, it doesn't ship.

### Definition

```
CLR = scans where confidence_after > confidence_before / total scans
```

### Confidence acknowledgement events (what counts as a "lift")

- Clicking **"Looks good for now"**
- Clicking **"I'll fix this later"** (confident deferral)
- Completing a recommended fix
- Dismissing an issue with understanding ("I get why this matters")

Deciding **not** to fix something confidently is still success. Fixing nothing can be a win.

### Confidence Signal Components

| Component | Measures | How |
|---|---|---|
| Reassurance | "Am I okay?" | System explicitly says "you're safe enough" |
| Clarity | "What should I do next?" | User clicks/acknowledges next action |
| Momentum | "I can handle this" | User fixes something or defers confidently |
| Trust | "I believe this advice" | User returns after a previous scan |

### Supporting metrics (guardrails against gaming CLR)

- **Return Rate After Reassurance**: % of users who scan again within 7 days after "you're okay" — detects fake reassurance
- **Fix Follow-Through Rate**: % of recommended "easy fixes" actually completed — validates clarity
- **Overwhelm Rate**: % of users who abandon a scan without interacting — detects when product is scaring people
- **False Comfort Rate**: % of users who get 🟢 then immediately hit 🔴 — detects over-reassurance

### Critical boundary

The analysis engine must **never** directly affect CLR. The metric lives above the engine:

```
Engine → raw risk signals → Product (insights/) → story + prioritization → User → confidence response
```

## Product Principles

- **Reassurance first**: first scan message should often be "Good news: nothing here will explode immediately"
- **Next Best Action**: every scan ends with ONE recommendation, not a list of 30 issues
- **Nudge, don't enforce**: never block deploys or fail builds — Vibe Coders need encouragement, not gates
- **Track improvement**: "You fixed 3 risky patterns this week" — gamification without shame
- **AI-awareness**: detect likely AI-generated patterns and say "This looks AI-generated. That's okay — just watch these spots"

## Tone & Voice Guide

### Core belief

> **People learn faster when they feel safe.**

If copy makes a user anxious, defensive, or ashamed, it is wrong — even if technically accurate.

### Internal mantra

> **"We help beginners feel safe enough to keep building."**

If copy doesn't serve that, it doesn't ship.

### Voice pillars (never violate)

1. **Reassuring, not alarmist** — calm first, explain second. Yes: "This is common." No: "This is dangerous."
2. **Plain language, never jargon** — if a beginner wouldn't say the word, don't use it. "cyclomatic complexity" → "doing a lot at once". "global mutable state" → "can change from different places". "exception handling" → "what happens when something goes wrong"
3. **Empowering, not prescriptive** — suggest, don't command. Yes: "You might want to…" No: "You must…"
4. **Honest, not falsely comforting** — never lie to make someone feel good. Yes: "This can cause issues later." No: "Everything is fine!" (when it's not)
5. **Friendly, not flippant** — warm, human, calm. Never jokey about risk. No sarcasm, no memes.

### Tone by situation

| Situation | Tone | Example |
|---|---|---|
| 🟢 Things are okay | Calm confidence | "Good news — nothing here looks risky right now. You're safe to keep building." |
| 🟡 Could be better | Supportive guidance | "This works, but it might be harder to change later. Totally fine to leave it for now." |
| 🔴 Real risk | Serious but steady | "If this code is shared, someone could access your account. This is fixable, and we'll walk you through it." |
| 🧠 Teaching | Curious mentor | "Here's why this matters — once you see it, it'll make a lot of sense." |

### Preferred words

okay, common, safe, simple, clear, optional, later, guide, help, understand

### Forbidden words

bad, wrong, sloppy, dangerous (without context), failed, failure, error-prone, incorrect, must, ignore, false positive, invalid

> **Note:** `wrong` and `ignore` are forbidden even in natural phrases like "went wrong" or "safe to ignore." Rewrite: "what happened" / "safe to leave for now." See `scripts/copy_lint_vibe_saas.py` config for the canonical list.

### Sentence rules

- One idea per sentence. No stacked warnings. No wall-of-text.
- Good: "This code works. It might be hard to change later."
- Bad: "Although this function currently executes correctly, its cyclomatic complexity may introduce long-term maintainability issues."

### Emotional safety checklist (run on every piece of copy)

1. Would this make a beginner feel stupid? → rewrite
2. Would this make someone afraid to continue? → soften
3. Does this explain *why* without shaming? → add context if not
4. Is there a clear next step or permission to stop? → add one if not

### Golden rule

> **If a user closes the app feeling calmer than when they opened it, the copy succeeded.** That is more important than technical precision.

## Copy Lint Rules (CI-enforceable)

Machine-checkable rules. If violated, copy does not ship.

### Hard rules (fail the lint)

**A1. Forbidden words** — copy must not contain (case-insensitive): `bad`, `wrong`, `sloppy`, `dangerous`, `failed`, `failure`, `incorrect`, `must`, `ignore`, `false positive`, `error-prone`, `invalid`

**A2. No imperative commands** — copy must not start sentences with: `Fix this`, `You must`, `You should`, `Do this`, `Remove this`, `Delete this`. Rewrite as suggestion: "A simple improvement is to remove this when you're ready."

**A3. Jargon blacklist** — beginner-facing UI must not contain: `cyclomatic`, `mutation`, `global state`, `side effects`, `race condition`, `refactor`, `polymorphism`, `stack trace`, `exception handling`. Allowed only in advanced/hidden views.

**A4. Required reassurance** — any 🔴 or 🟡 signal must include ≥1 reassurance phrase: "this is common", "you didn't do anything wrong", "it's okay to leave this for now", "this is fixable", "you're catching this early", "we'll help you", "totally okay", "no rush"

**A5. Action safety** — every signal card must offer at least one non-punitive exit (Later or I get it). Showing only "Fix now" is a lint error.

### Soft rules (warn-level, block merge without justification)

**B1. Sentence length** — warn >20 words, error >30 words per sentence. Beginners skim when anxious.

**B2. One action per card** — each signal card recommends only one action. Multiple verbs in "What to do next" = warn.

**B3. Emotion-first ordering** — reassurance appears before explanation. "This is common and fixable. Right now, errors could be hidden." not the reverse.

**B4. Neutral tone** — copy must not imply user fault. Warn on: "you caused", "you forgot", "you failed to", "this happened because you"

### Button label allowlist (strict)

Any label not in these sets = lint error:

- **Primary**: "Fix now", "Let's fix this", "Secure this now", "Add guardrails", "Make errors visible"
- **Secondary**: "Later", "Not now", "Later is fine", "Ship first"
- **Tertiary**: "I get it", "That makes sense", "Got it", "Okay, understood"
- **Forbidden**: "Ignore", "Dismiss", "Skip", "Not important", "False positive"

### Lint config (`copy_lint.yaml`)

```yaml
copy_lint:
  forbidden_words:
    - bad
    - wrong
    - sloppy
    - dangerous
    - must
    - ignore
    - failed
    - failure
    - incorrect
    - false positive
    - error-prone
    - invalid
  jargon_blacklist:
    - cyclomatic
    - mutation
    - global state
    - exception handling
    - race condition
    - refactor
    - polymorphism
    - stack trace
    - side effects
  required_reassurance:
    risk_levels: [yellow, red]
    phrases:
      - "this is common"
      - "this is fixable"
      - "you didn't do anything wrong"
      - "it's okay to leave this for now"
      - "you're catching this early"
      - "we'll help you"
      - "totally okay"
      - "no rush"
  sentence_length:
    warn: 20
    error: 30
  allowed_buttons:
    primary: ["Fix now", "Let's fix this", "Secure this now", "Add guardrails", "Make errors visible"]
    secondary: ["Later", "Not now", "Later is fine", "Ship first"]
    tertiary: ["I get it", "That makes sense", "Got it", "Okay, understood"]
```

### PR copy review gate (manual, mandatory)

Every PR with copy changes must answer four yes/no questions:
1. Would this make a beginner feel stupid?
2. Would this make someone afraid to keep building?
3. Is there permission to stop or defer?
4. Is the next step clear but optional?

If any answer is wrong, copy must be revised.

### Final lint gate

> **If copy is technically accurate but emotionally unsafe, it fails.** Accuracy without confidence is a bug.

### Reference implementation

**Prose linter** — `scripts/copy_lint.py` enforces rules on Markdown and text files:

```bash
python scripts/copy_lint.py lint ./src --format text
python scripts/copy_lint.py lint ./src --format json
```

**Schema-aware JSON linter** — `scripts/copy_lint_vibe_saas.py` enforces the same rules on canonical i18n JSON files. It walks exact JSON pointers (e.g., `i18n/en/signals.json#/signals/exceptions/summary`) and applies field-specific rules per type:

```bash
python scripts/copy_lint_vibe_saas.py lint i18n/en/                        # lint all JSON in directory
python scripts/copy_lint_vibe_saas.py lint i18n/en/signals.json            # lint one file
python scripts/copy_lint_vibe_saas.py lint i18n/en/ --format json          # JSON output for CI
python scripts/copy_lint_vibe_saas.py init-config > copylint.json          # generate editable config
python scripts/copy_lint_vibe_saas.py lint i18n/en/ --config copylint.json # use custom config
```

Exit codes: 0 = clean, 1 = errors found, 2 = config error.

**What it validates per file:**

| File | Root key | Validates |
|---|---|---|
| `signals.json` | `signals` | `signals.*.{risk_level, title, summary, why, action.text, action.urgency, footer, footer_icon}` |
| `compounds.json` | `compounds` | Same signal shape as above, plus `trigger` and `penalty_modifier` |
| `buttons.json` | `buttons` | Labels + tooltips + `subtext_by_risk.*.{primary, secondary, tertiary}` |
| `feedback.json` | `feedback` | `feedback.*.{icon, text}` |
| `summaries.json` | `summaries` | `vibe_status.{green, yellow, red}`, `empty_state`, `first_scan_celebration` |

**Errors (fail CI):** forbidden words, jargon, imperative starts, missing required fields, invalid `risk_level`, invalid `action.urgency` (must be `optional`/`recommended`/`important`), button labels not in allowlist, yellow/red summaries missing reassurance phrase.

**Warnings:** long sentences, long titles, multi-step actions, missing permission language in optional/yellow footers.

## Canonical Copy Source: `i18n/en/`

All user-facing copy lives in **structured JSON files** under `i18n/en/`. These are the single source of truth — `insights/translator.py` reads from these files, never from hardcoded strings.

### File map

| File | Root key | Contains | Used by |
|---|---|---|---|
| `signals.json` | `signals` | Per-analyzer signal copy (risk_level, title, summary, why, action, footer, footer_icon) | `insights/translator.py` |
| `compounds.json` | `compounds` | Compound signal copy — same shape plus `trigger[]` and `penalty_modifier` | `insights/translator.py` |
| `buttons.json` | `buttons` | Button labels/tooltips by tier (primary, secondary, tertiary) + `subtext_by_risk` | UI layer, signal cards |
| `feedback.json` | `feedback` | Post-click micro-feedback — each entry has `icon` + `text` | UI layer |
| `summaries.json` | `summaries` | `vibe_status.{green,yellow,red}` strings, `empty_state` string, `first_scan_celebration` string | `insights/confidence.py`, UI |

### Schema conventions

**Signal shape** (`signals.json` and `compounds.json`):
- Required: `risk_level` (green|yellow|red), `title`, `summary`, `why`, `action` (object: `text` + `urgency`), `footer`, `footer_icon`
- `action.urgency` must be one of: `optional`, `recommended`, `important`
- Yellow/red signals require a reassurance phrase in `summary`
- Compounds additionally carry `trigger` (array of analyzer keys) and `penalty_modifier` (float)

**Buttons shape** (`buttons.json`):
- `buttons.{primary,secondary,tertiary}.*` — each variant has `label` + `tooltip`
- `buttons.subtext_by_risk.{red,yellow,green}` — each has `primary`, `secondary`, `tertiary` subtext strings
- All labels validated against the allowlist

**Feedback shape** (`feedback.json`):
- `feedback.*` — flat entries, each with `icon` (emoji string) + `text` (copy string)

**Summaries shape** (`summaries.json`):
- `summaries.vibe_status.{green,yellow,red}` — plain strings
- `summaries.empty_state` — plain string
- `summaries.first_scan_celebration` — plain string

### Adding copy for a new analyzer

1. Add a new key in `i18n/en/signals.json` with the full signal shape
2. Add compound entries in `i18n/en/compounds.json` if the new analyzer interacts with existing ones
3. Run `python scripts/copy_lint_vibe_saas.py lint i18n/en/` — must pass with 0 errors
4. Update `insights/translator.py` to reference the new key
5. PR must pass the four-question copy review gate

### Localization

To add a language: copy `i18n/en/` to `i18n/{locale}/`, translate values, run the linter against the new locale. Keys and structure must be identical across locales.

## CI Integration

### GitHub Actions

```yaml
# .github/workflows/copy-lint.yml
name: Copy Lint
on:
  pull_request:
    paths:
      - 'i18n/**'
      - 'src/**/copy/**'
      - 'scripts/copy_lint*'
jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - name: Lint prose copy
        run: python scripts/copy_lint.py lint src/ --format text
      - name: Lint i18n JSON copy
        run: python scripts/copy_lint_vibe_saas.py lint i18n/en/ --format text
```

### npm / package.json scripts (optional)

```jsonc
// package.json (if using a JS/TS frontend alongside)
{
  "scripts": {
    "lint:copy":      "python scripts/copy_lint.py lint src/ --format text",
    "lint:copy:json": "python scripts/copy_lint_vibe_saas.py lint i18n/en/ --format text",
    "lint:copy:ci":   "python scripts/copy_lint_vibe_saas.py lint i18n/en/ --format json",
    "lint:copy:all":  "npm run lint:copy && npm run lint:copy:json"
  }
}
```

### Makefile (if Python-only)

```makefile
.PHONY: lint-copy
lint-copy:
	python scripts/copy_lint.py lint src/ --format text
	python scripts/copy_lint_vibe_saas.py lint i18n/en/ --format text
```

## PR Governance — CBSP21 Patch Manifest

Every pull request uses the **CBSP21 patch manifest** flow for structured change governance.

### Artifacts (in `cbsp21/`)

| File | Purpose |
|------|---------|
| `patch_input.schema.json` | JSON Schema (v1) — the single source of truth for field names, types, and enums |
| `patch_input.template.json` | Blank template — copy to `patch_input.json` in your branch and fill in |
| `patch_input.json.example` | Fully worked example scoped to this repo |
| `README.md` | Quick-start instructions |

### Workflow

1. Branch from `main`.
2. Copy `cbsp21/patch_input.template.json` → `patch_input.json` (repo root).
3. Fill in `patch_id`, `scope`, `diff_articulation`, `verification`, and `risk_level`.
4. Run verification commands and record them in `verification.commands_run`.
5. Open a PR — the `.github/PULL_REQUEST_TEMPLATE.md` auto-populates checklists that reference the manifest.
6. Reviewer validates: scope matches diff, risk classification is reasonable, verification evidence is real.

### Required fields (schema-enforced)

`schema_version` · `patch_id` · `title` · `intent` · `change_type` · `behavior_change` · `risk_level` · `scope` · `diff_range` · `changed_files_count` · `diff_articulation` · `verification` · `file_context_coverage_percent`

### Enums

- **change_type**: `code` · `docs` · `config` · `ci` · `refactor` · `test` · `security`
- **behavior_change**: `compatible` · `breaking` · `unknown`
- **risk_level**: `low` · `medium` · `high`

### AI agent rule

When generating a PR or committing changes, always create a `patch_input.json` from the template and populate it accurately. Never skip governance fields or leave them empty.

## Data Model — Hybrid Snapshot

The engine persists scan results as **immutable snapshots** that downstream layers can re-interpret without re-scanning. Three JSON Schema contracts define the boundaries.

All schemas live in `schemas/` and use **JSON Schema draft 2020-12** with `additionalProperties: false`.

### 1. RunResult (`run_result_v1`)

The **immutable artifact** written once per scan. It contains:

| Section | Purpose |
|---|---|
| `run` | Metadata — `run_id`, `project_id`, `created_at`, tool/engine/signal-logic/copy versions, scan config |
| `summary` | Quick glance — `vibe_tier` (green/yellow/red), `confidence_score` (0–100), counts by severity and type |
| `signals_snapshot` | The signal cards shown to the user at scan time, including i18n copy-key references and evidence pointers |
| `findings_raw` | Full engine findings with `finding_id`, severity, confidence, location, fingerprint, and optional snippet |
| `artifacts` | Privacy controls — `redactions_applied`, `snippet_policy` (full/truncated/omitted) |

**Core rule:** A RunResult is **never overwritten**. Re-interpretation creates a new SignalsLatest, not a mutation.

### 2. SignalsLatest (`signals_latest_v1`)

A **derived, recomputed view** of signals that can change without a new scan. Used for:

- A/B experiments on signal wording or ranking
- Copy version upgrades (new i18n strings, same engine findings)
- Compound-signal merges

Key fields: `run_id` (links back to the snapshot), `computed_at`, `signal_logic_version`, `copy_version`, optional `experiment` block (`id` + `variant`), and a `signals` array with copy-key references.

### 3. UserEvents (`user_event_v1`)

An **append-only event stream** for CLR tracking. Each event records a user interaction with a signal:

| Event type | Button mapping | Meaning |
|---|---|---|
| `signal_fixed` | Primary (🟢) | User fixed the issue |
| `signal_deferred` | Secondary (🟡) | User chose to address later |
| `signal_acknowledged` | Tertiary (🔵) | User saw and acknowledged |

Each event carries `ts`, `type`, `signal_id`, and a `meta` bag (e.g., which button was pressed).

### Versioning & Storage Strategy

- **Schema versions**: only the **versioned-envelope** schemas carry a `schema_version` `const` — the ones whose *instances* include a `schema_version` field: `run_result` (`"run_result_v1"`), `signals_latest` (`"signals_latest_v1"`), `user_event` (`"user_event_v1"`), `debt_snapshot`, `rule_registry`. Consumers match on this field for forward compatibility.
  - **Non-envelope schemas do NOT have `schema_version`** and must not be given one: `release_bom`, `release_gate_envelope`, `finding`, `contracts_versions`, `schema_graph_bundle`, `rules_registry`, and the `openapi_*`/`release_*` gate-result schemas describe payloads that carry no `schema_version` field. **Never add a `schema_version` const to these to make `test_schema_version_freeze` pass** — that test enforces the envelope-only invariant of `src/code_audit/data/schemas/` (a runtime *subset*), not a requirement that every schema be versioned. If a non-envelope schema is failing that gate, it is in the wrong directory (see `src/code_audit/data/schemas/README.md`), not missing a field.
- **Storage layout** (recommended): `{project}/.code-audit/snapshots/{run_id}/run_result.json`, with `signals_latest.json` and `events.json` alongside.
- **Snippet policy**: The `snippet_policy` field in RunResult controls code exposure — `"full"`, `"truncated"`, or `"omitted"`. Default is `"truncated"`.

### Schema references

- `schemas/run_result.schema.json` — RunResult schema
- `schemas/signals_latest.schema.json` — SignalsLatest schema
- `schemas/user_event.schema.json` — UserEvents schema
- `schemas/*.example.json` — canonical example instances (validated in CI)

## What NOT to Do

- Don't expose engine terms (`cyclomatic complexity`, `bare except`, `mutable global`) in user-facing output
- Don't show more than three signal levels to users
- Don't auto-delete or auto-fix anything — suggest, never act
- Don't couple analysis logic to `ui/` or `gpt/` — those consume `insights/` output
- Don't add runtime-tracing (sys.settrace, objgraph) to the automated suite
- Don't optimize for "number of scans," "issues found," or "fixes applied" — those measure activity, not confidence
- Don't let the engine shape the metric — CLR is a product-layer measurement
- Don't use forbidden words or jargon in any user-facing surface
- Don't make any button feel like a mistake — every click is a smart, safe choice
- **Don't make a failing CI gate green by changing what it checks or fabricating the data it inspects** — fix the underlying cause, not the symptom. A gate exists to detect a real condition; satisfying it with fake data (e.g. adding a `schema_version` const to a schema that has none, editing a manifest hash by hand, weakening an assertion) makes the check *lie*. If a gate seems wrong, say so and stop — do not defeat it. A dishonest green is worse than an honest red.
- **Don't bulk-sync, mirror, or "reconcile" directories to make their contents match** (e.g. copying `schemas/` into `src/code_audit/data/schemas/`) — those layouts are intentional subsets, not mirrors. See `src/code_audit/data/schemas/README.md`.

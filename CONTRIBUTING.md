# Contributing to code-analysis-tool

This repository treats **user-facing copy as product logic**, not decoration. Please read this document before changing any text that users see.

## Why this matters

This project is designed for **beginner Vibe Coders**.
The wording, tone, and structure of messages directly affect user confidence, learning, and retention.

To keep the experience safe, calm, and consistent, we enforce **strict rules** around copy via:

* a fixed i18n file structure
* a schema-aware copy linter
* lightweight governance manifests for changes

---

## 🌍 i18n structure (do not change)

All user-facing copy lives in locale-specific JSON files:

```
i18n/
└─ en/
   ├─ signals.json      # per-analyzer signal copy
   ├─ compounds.json    # combined / co-firing signals
   ├─ feedback.json     # post-click & scan feedback
   ├─ buttons.json      # button labels, tooltips, subtext
   └─ summaries.json    # scan-level summaries & empty states
```

**Path convention**

```
i18n/{locale}/{file}.json
```

Rules:

* All locales must share **identical keys and structure**
* Only values are translated
* Do not merge or split these files
* Do not move copy into code or the database without discussion

This structure is intentional and supports:

* deterministic linting
* future internationalization
* safe product evolution

---

## 🧠 Copy is linted (and CI-enforced)

All i18n files are validated by a custom linter:

```
scripts/copy_lint_vibe_saas.py
```

The linter enforces:

* no shaming or judgmental language
* no jargon in beginner-facing copy
* required reassurance for higher-risk messages
* allowed button labels only
* sentence length limits
* schema correctness

If CI fails due to copy lint errors, **fix the copy** — do not bypass the linter.

> If the linter flags something, it's because the copy could make a beginner feel unsafe, confused, or blamed.

---

## 🧩 Governance for non-trivial changes (cbsp21)

For any change that affects:

* user-facing behavior
* copy semantics
* analysis output shape
* risk classification
* confidence scoring
* i18n structure

You must include a **patch manifest** from:

```
cbsp21/
└─ patch_input.template.json
```

### How to use it

1. Copy `cbsp21/patch_input.template.json` to `patch_input.json` in your branch root
2. Fill it out for your change
3. Commit it alongside your PR

The manifest explains:

* what changed
* why it matters
* what files are in scope
* how the change was verified

This is not bureaucracy — it's how we keep the system understandable as it grows.

See `cbsp21/patch_input.json.example` for a fully worked reference.

---

## 🚦 What *not* to do

Please **do not**:

* introduce new copy outside `i18n/`
* add ad-hoc strings in code
* change button labels arbitrarily
* weaken or disable copy lint rules
* add locale-specific structural differences
* store static copy in the database

If you think one of these is necessary, open an issue first.

---

## 🧭 Guiding principle

> **If a user closes the app feeling calmer and more confident than when they opened it, the change was good.**

When in doubt, optimize for:

* clarity over cleverness
* reassurance over urgency
* permission over pressure

---

## 🛠️ Quick commands

```bash
make install         # install dev dependencies
make test            # run pytest (includes copy + schema checks)
make lint            # run all linters
make lint-copy       # schema-aware copy linter only
make lint-copy-prose # prose copy linter only
make lint-schema     # validate cbsp21 schema example
make lint-parity     # check locale key parity
```

---

If you're unsure whether a change needs a manifest, lint adjustment, or discussion — ask.
We care more about doing this *right* than doing it *fast*.

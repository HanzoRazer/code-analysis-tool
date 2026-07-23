# Unverified Store-Shape Predicate

> A filter or reader accesses persisted or indexed data at a field location inferred from the write-site signature, the in-memory type, or the schema — never confirmed against a real round-trip. Serialization and indexing routinely relocate, nest, drop, or alias fields, so the predicate silently matches nothing (or the wrong rows) while every declared contract still looks satisfied. Establish the true stored shape empirically with a seed-and-read probe, then funnel the read and the comparison through one canonical accessor so every call site agrees.

## Problem

Code that queries a store reads a field — `record["category"]`, `meta.tool_kind`,
`row["status"]` — at a location it *assumes* the field lives. The assumption comes from the
place the value was written: the constructor accepts `category=`, the model exposes
`.category`, the schema lists `category`. So the predicate reads `record["category"]` and
trusts it.

But the value the writer accepted and the value the store *persisted or indexed* are two
different contracts, joined by a serialization or index-extraction step that almost nobody
re-reads. That step can:

- **relocate** the field (top-level on the model → nested under `meta` in the index),
- **drop** it (never copied into the lightweight index at all),
- **alias** it (leaks into a neighbouring column like `mode`/`tool_id`), or
- **normalize** it (one written value becomes several stored spellings over time).

**The three contracts that are silently assumed equal:**

| What the writer *accepts* | What the store *persists/indexes* | What the predicate *reads* |
|:---|:---|:---|
| `store(category=...)` | index row: `{..., "meta": {"category": ...}}` | `row["category"]`  ← **absent** |

The predicate reads a key that the stored shape never contains. Nothing errors at the type
level — the model still has `.category`; the write still succeeds. The read just resolves to
"missing" for every row, so the filter matches nothing, or (worse) is written to
"pass through when absent" and silently matches *everything*.

**Symptom:** a query that "obviously should return rows" returns none, or returns unfiltered
results, with **no exception raised**; a field that is "right there on the model" appears
missing at read time; two modules that both filter on "the same" field disagree about where
it lives or what its values mean — and only one of them is right. In the loud variant the
store rejects the keyword outright (`TypeError: unexpected keyword argument`) because the read
path never grew the parameter the write path advertised.

## Solution

Do not reason about the stored shape — **observe it**, then encode the observation once.

1. **Ground-truth with a seed-and-read probe, not an assumption or a print.** Point the store
   at a scratch location, write real records spanning the interesting values (present, absent,
   empty, and each spelling), trigger whatever index/serialize step the store actually uses,
   then read the *raw* persisted form back and assert **where the field actually lands**. This
   is the "gate" — a committed test, so the ground truth is frozen, not a one-off console
   check.

2. **Read through one canonical accessor** that encodes the confirmed location (checks the
   nested path the probe revealed, falls back to the legacy top-level). Every call site calls
   this function instead of subscripting the record directly.

3. **Compare through one canonical comparator**, so normalization, synonyms, and
   absent-is-lenient rules live in exactly one place. Divergent call sites cannot disagree
   about whether two stored spellings are "the same kind" if they all route through it.

4. **Keep the probe as a regression.** If a later change to the serializer/indexer moves the
   field again, the frozen assertion fails loudly at the source instead of silently emptying
   a query in production.

```python
# The store's index-extraction is the real contract — and it nests `category` under `meta`,
# it does NOT copy it to the top level, even though the model exposes `record.category`.
def _extract_index_meta(record):
    return {"id": record.id, "status": record.status, "meta": record.meta}  # category lives in meta

# 1. GROUND-TRUTH GATE (committed test): seed real records, read the raw index back, assert shape.
def test_where_category_actually_lands(tmp_store):
    tmp_store.put(make_record(category="a"))
    tmp_store.rebuild_index()
    row = next(iter(tmp_store.read_raw_index().values()))
    assert "category" not in row                    # NOT top-level (the assumption was wrong)
    assert row["meta"]["category"] == "a"           # the verified location

# 2. CANONICAL ACCESSOR: the one place that knows the confirmed shape.
def index_category(row):
    meta = row.get("meta") or row.get("index_meta") or {}
    return meta.get("category") or row.get("category")   # nested first, legacy top-level fallback

# 3. CANONICAL COMPARATOR: the one place that knows the value rules.
def category_matches(stored, requested):
    if not requested:            return True          # no filter → everything
    if not stored:               return True          # absent → lenient, don't silently drop
    return _normalize(stored) == _normalize(requested)

# Every filter/count/tree call site now reads via index_category() and compares via
# category_matches() — never `row["category"] == requested`.
```

Reading `row["category"]` directly is the defect; it was never a key of the stored shape.

## Why This Works

1. **The stored contract is observed, not guessed** — the probe reads what the store really
   wrote, so the predicate targets a location that exists.
2. **Drift fails loudly at the source** — the frozen assertion turns a future serialization
   change into a red test, not a mystery empty result three layers away.
3. **Call sites cannot diverge** — one accessor and one comparator mean every query, count,
   and view agree on where the field is and what its values mean.
4. **The probe documents the real shape** — the seed-and-read test *is* the specification of
   the persisted form, in executable form, where prose can't drift from it.

## When to Apply

- A predicate reads a field from store/query/index results by subscript or attribute, and the
  location is "known" only from the write-site signature, the model, or the schema.
- A store has a distinct **index-extraction / serialization / projection** step between write
  and read (a lightweight index, a denormalized row, a DTO) — that step is where shape drifts.
- A query "that should return rows" returns none or returns everything, with no error.
- Two or more modules filter on the same conceptual field; before trusting either, confirm
  they read the *same* verified location and share value semantics.
- A store call raises `unexpected keyword argument` for a field the writer clearly accepts —
  the read and write paths grew apart.

## How a Checker Could Detect It

A static rule targeting this family looks for **reads of store-shaped records at a key the
store's own projection never writes at that level**:

- locate the projection/index-extraction/serializer function and collect the keys it emits at
  each level (top-level vs nested maps like `meta`/`index_meta`);
- find predicates/accessors that subscript or `.get()` a *store-returned* record with a key
  that appears only nested (or not at all) in that projection;
- and, cross-module, flag the **same** conceptual field read via *different* paths in
  different files (`row["x"]` here, `row["meta"]["x"]` there) — at most one matches the
  projection.

High-signal shape: a `== field` / `row[field]` comparison on the result of a known store/query
function, where `field` is absent from the projection's top-level key set. Report as *possible
unverified store-shape access* (warning, not error) — some stores genuinely do keep the field
top-level, so this is a prompt to run the seed-and-read gate, not a certainty.

## Alternatives Considered

| Approach | Pros | Cons |
|----------|------|------|
| Trust the model/schema for the read shape | No probe to write | The defect — the persisted shape can differ from the declared one |
| One-off `print`/debugger check while coding | Fast | Not frozen; the next serializer change re-breaks it silently |
| **Seed-and-read gate + canonical accessor/comparator** | **Observes the real shape, freezes it, and centralizes read + compare so sites can't diverge** | A probe test and two small helpers to maintain |
| Validate/normalize at every read site | Localized | Repeated, easily forgotten, and the sites drift apart — the very disagreement this prevents |
| Make the index carry the field top-level to match the model | Read becomes trivial | Larger store change; still needs a probe to prove the new shape and guard it |

## Origin

Distilled from a real occurrence: a run store's index-extraction persisted a `tool_kind` tag
only inside a nested `meta` map — not as the top-level field the model exposed, and it also
leaked into neighbouring columns — while three separate call sites filtered on it, disagreeing
about both its location and whether two of its spellings meant the same kind. A filter written
against the assumed top-level key matched nothing; another path rejected the keyword outright.
An empirical seed-and-read probe established where the tag actually landed (and that "missing"
had to stay lenient), and a single canonical reader plus comparator replaced the scattered
direct reads. That incident is one instance; the family — a predicate over persisted data that
trusts the declared shape instead of the verified one — is the reusable concept documented
here.

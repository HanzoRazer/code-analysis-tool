# Incomplete State-Invariant Enforcement

> A model, dataclass, or record validates a coupling rule in only one direction, leaving a contradictory state legal and constructible. Enforce every direction the invariant implies — for two coupled fields, that means the biconditional, not a single implication.

## Problem

An object's validity depends on a relationship *between* two or more of its fields —
"if this flag is set, that value must be zero," "if the list is empty, the status must be
`EMPTY`," "a total of 0 must mean the cart is marked empty." The constructor or validator
enforces the relationship as a **single implication** (`A ⇒ B`) and stops there.

The problem is that a coupling rule almost never means just one implication. If the two
fields are genuinely coupled, the *inverse* is also part of the invariant. Checking only
`A ⇒ B` leaves the state `¬A ∧ B` unguarded — a value that satisfies every explicit check
yet contradicts the concept the type is supposed to model.

**The state space, for two coupled boolean-ish fields:**

| `A` (flag) | `B` (the coupled condition) | Guard `A ⇒ B` | Guard `A ⇔ B` |
|:---:|:---:|:---:|:---:|
| true | true | legal | legal |
| true | false | **rejected** | rejected |
| false | false | legal | legal |
| false | true | **legal (the leak)** | **rejected** |

The row `false / true` is the defect. The one-directional guard admits it. The object is
now in a state its own domain rules forbid, but nothing raised — so the contradiction
travels downstream and surfaces far from its cause, as a confusing failure in code that
*trusted* the type.

**Symptom:** a "can't happen" branch happens; a value that "should have been rejected at
construction" is found deep in the system; two fields that are supposed to move together
disagree, and no validation error was ever raised.

## Solution

Enforce **every** direction the invariant implies, at the construction/validation
boundary, so an illegal object cannot be built in the first place.

1. **Name the invariant as a biconditional (or full equivalence), not a sentence.** Write
   it as `A ⇔ B`, not "if A then B." The word "if" in a spec is a trap — coupled fields
   usually mean "exactly when."

2. **Add one guard per direction.** `A ⇒ B` and `B ⇒ A` are two checks. Each catches a
   distinct illegal state and deserves its own error message naming *which* rule was
   violated.

3. **Guard at the boundary, not at the call site.** Put the checks in the constructor /
   `__post_init__` / validator so no consumer can observe an illegal instance. Downstream
   code should be free to trust the type.

4. **For N coupled fields, enforce the full equivalence class.** Two fields → a
   biconditional. More than two (e.g. an enum tag that must match a payload shape) → every
   tag maps to exactly one legal shape and vice versa; a `match`/dispatch with an
   `assert_never`/`else: raise` default closes the space.

```python
from dataclasses import dataclass

@dataclass(frozen=True)
class Position:
    is_open: bool
    offset: float  # measured relative to the effective origin

    def __post_init__(self) -> None:
        # Forward: A ⇒ B  (the direction people usually remember)
        if self.is_open and self.offset != 0.0:
            raise ValueError("an open position must have offset 0.0")
        # Inverse: B ⇒ A  (the direction that's usually forgotten — the leak)
        if self.offset == 0.0 and not self.is_open:
            raise ValueError("offset 0.0 must be marked is_open=True")
        # Together these two guards make the invariant biconditional: offset 0.0 ⇔ is_open
```

Without the second guard, `Position(is_open=False, offset=0.0)` constructs cleanly — a
legal object in an illegal state.

## Why This Works

1. **Illegal states become unrepresentable at the boundary** — the contradiction fails
   loudly at construction instead of silently at some distant read.
2. **Each direction gets its own diagnostic** — the error names the specific rule broken,
   so the fix is obvious.
3. **Downstream code can trust the type** — "can't happen" branches genuinely can't,
   because the type system + constructor jointly forbid the state.
4. **It documents the real invariant** — the pair of guards *is* the specification, in
   executable form, where it can't drift from the prose.

## When to Apply

- A type has two or more fields whose validity depends on each other (a flag + a value, a
  tag + a payload, a status enum + a collection's emptiness).
- A validator or constructor checks a coupling with a single `if A: require B` and no
  mirror check.
- A "sentinel" value (0, empty, `None`, `""`) is supposed to be equivalent to a flag, but
  only one side is enforced.
- Reviewing invariant/validation code: for every `A ⇒ B` you find, ask "is `¬A ∧ B` also
  illegal?" If yes and it's unguarded, that's this gap.

## How a Checker Could Detect It

A static rule targeting this family looks for **asymmetric coupling guards** in
constructors/validators:

- a guard that references field `A` and field `B` together (an implication), where
- no sibling guard in the same constructor references the *inverse* condition, and
- both fields are assigned/accepted by that same constructor (i.e. genuinely coupled).

High-signal shape: a boolean field and a companion field compared against a sentinel
(`== 0`, `is None`, `== ""`, `len(...) == 0`) appear together in exactly one guard. Report
it as *possible incomplete invariant* (warning, not error) — the inverse is sometimes
deliberately legal, so this is a review prompt, not a certainty.

## Alternatives Considered

| Approach | Pros | Cons |
|----------|------|------|
| Check one direction only | Less code | The defect — leaves `¬A ∧ B` legal |
| **Enforce the biconditional at the boundary** | **Illegal state can't be built; each direction self-documents** | Two guards instead of one |
| Validate at every read site | Localized | Repeated, easily forgotten, trusts nothing |
| Encode in the type (make the sentinel unrepresentable) | Strongest — no runtime check needed | Not always expressible; larger refactor |

## Origin

Distilled from a real occurrence: a spatial-position value type enforced
`is_open_string ⇒ relative_semitone_position == 0.0` but not the inverse, so
`is_open_string=False` with `relative_semitone_position == 0.0` was a legal, constructible
contradiction. The fix added the mirror guard, making the coupling biconditional
(`relative 0.0 ⇔ is_open_string`). That incident is one instance; the family — a validator
that enforces a coupling in one direction only — is the reusable concept documented here.

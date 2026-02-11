"""
UI-facing helpers.

These functions are intentionally *pure* (no filesystem, no network) so they can be used
by:
  - a future web app
  - a CLI preview mode
  - tests / experiments
"""

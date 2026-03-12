"""Import all checker modules so that ``__init_subclass__`` auto-registration fires."""

# v2 improved checkers
from . import vue_checker      # noqa: F401
from . import python_checks    # noqa: F401
from . import css_checker      # noqa: F401
from . import duplicate_checker  # noqa: F401
from . import magic_number     # noqa: F401

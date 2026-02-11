# Good import
import os
from pathlib import Path


# Bad import — banned pattern
from app._experimental.ai_core import ModelRunner  # noqa


def process():
    """Use the banned import."""
    runner = ModelRunner()
    return runner

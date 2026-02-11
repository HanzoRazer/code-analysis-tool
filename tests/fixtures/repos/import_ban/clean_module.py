# Clean file with no banned imports
import json
from datetime import datetime


def get_timestamp():
    return datetime.now().isoformat()

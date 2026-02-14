"""
Security clean fixture — no security vulnerability patterns.

Used for testing that SecurityAnalyzer produces no false positives.
"""

import os
import subprocess
import json
import yaml


def get_config():
    """Get configuration from environment variables."""
    return {
        "api_key": os.getenv("API_KEY"),
        "password": os.getenv("PASSWORD"),
        "secret": os.environ.get("SECRET"),
        "debug": os.getenv("DEBUG", "false").lower() == "true",
    }


def run_command_safely(args: list[str]) -> str:
    """Run a command safely without shell injection risk."""
    # Using list form, no shell=True
    result = subprocess.run(args, capture_output=True, text=True)
    return result.stdout


def get_user_safely(cursor, user_id: int):
    """Get user using parameterized query."""
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    return cursor.fetchone()


def insert_user_safely(cursor, name: str, email: str):
    """Insert user using parameterized query."""
    cursor.execute(
        "INSERT INTO users (name, email) VALUES (?, ?)",
        (name, email)
    )


def parse_yaml_safely(content: str) -> dict:
    """Parse YAML safely using safe_load."""
    return yaml.safe_load(content)


def parse_yaml_with_loader(content: str) -> dict:
    """Parse YAML with explicit SafeLoader."""
    return yaml.load(content, Loader=yaml.SafeLoader)


def serialize_data(data: dict) -> str:
    """Serialize data safely using JSON."""
    return json.dumps(data)


def deserialize_data(content: str) -> dict:
    """Deserialize data safely using JSON."""
    return json.loads(content)


class Calculator:
    """Simple calculator without security issues."""

    def __init__(self):
        self.history = []

    def add(self, a: float, b: float) -> float:
        result = a + b
        self.history.append(f"{a} + {b} = {result}")
        return result

    def multiply(self, a: float, b: float) -> float:
        result = a * b
        self.history.append(f"{a} * {b} = {result}")
        return result


# Module-level constants (not secrets)
VERSION = "1.0.0"
MAX_RETRIES = 3
DEFAULT_TIMEOUT = 30


# Empty string assignments (not flagged)
empty_password = ""
placeholder_key = ""

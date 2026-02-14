"""
Security hot fixture — contains all 6 security vulnerability patterns.

Used for testing SecurityAnalyzer detection.
"""

import os
import subprocess
import pickle
import yaml


# SEC_HARDCODED_SECRET_001 — hardcoded password
password = "supersecret123"
api_key = "sk-1234567890abcdef"


# SEC_EVAL_001 — eval/exec usage
def dangerous_eval(user_input):
    return eval(user_input)


def dangerous_exec(code):
    exec(code)


# SEC_SUBPROCESS_SHELL_001 — shell injection risk
def run_command(cmd):
    subprocess.run(cmd, shell=True)


def legacy_system(cmd):
    os.system(cmd)


# SEC_SQL_INJECTION_001 — SQL injection
def get_user(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return query


def delete_record(table, id):
    query = "DELETE FROM {} WHERE id = {}".format(table, id)
    return query


# SEC_PICKLE_LOAD_001 — unsafe deserialization
def load_data(filepath):
    with open(filepath, "rb") as f:
        return pickle.load(f)


def deserialize(data):
    return pickle.loads(data)


# SEC_YAML_UNSAFE_001 — unsafe YAML loading
def parse_yaml(content):
    return yaml.load(content)


def parse_yaml_unsafe(content):
    return yaml.unsafe_load(content)


# Clean function for contrast
def safe_function(x, y):
    """This function has no security issues."""
    return x + y

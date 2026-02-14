> **⚠ HISTORICAL ARTIFACT — Do not treat as current.**
> Generated against `repo/src` which no longer exists in the current layout.
> Archived on 2026-02-14. See `src/code_audit/` for the live codebase.

# Rescue Plan

Generated: 2026-02-14T00:19:17.183669
Scanned: `C:\Users\thepr\Downloads\code-analysis-tool\repo\src`

## Summary

- **Total Issues**: 72
- **Estimated Effort**: 27.6 hours
- **Plans Generated**: 72

---

## Plan 1: God Class

**Location**: `code_audit\analyzers\security.py:127`
**Severity**: MEDIUM
**Time**: ~45 minutes

### Steps

#### Step 1: ANALYZE

Open code_audit\analyzers\security.py and identify logical groups of methods in SecurityAnalyzer

Source: `code_audit\analyzers\security.py`

```python
# Look for methods that:
# 1. Share a common prefix (get_user_*, validate_*, process_*)
# 2. Access the same subset of instance variables
# 3. Are called together in sequence
# 4. Handle the same domain concept (auth, data, ui)
```

#### Step 2: CREATE

Create new module: code_audit\analyzers/securityanalyzer_helpers.py

Target: `code_audit\analyzers/securityanalyzer_helpers.py`

```python
"""
Helper functions extracted from SecurityAnalyzer

This module contains extracted helper functions that were previously
methods of the SecurityAnalyzer class. They are now standalone functions
that accept the necessary data as parameters.
"""
from typing import Any


# Paste extracted functions here
```

#### Step 3: EXTRACT

Move helper methods (methods that don't use 'self' much) to new module

Source: `code_audit\analyzers\security.py`
Target: `code_audit\analyzers/securityanalyzer_helpers.py`

```python
# FOR EACH helper method:
# 1. Copy the method to the new file
# 2. Remove 'self' parameter if not needed
# 3. Add any needed parameters that were self.xxx
# 4. Update imports in new file
# 5. In original class, replace method body with:
#
#    def old_method(self, args):
#        from .class_helpers import old_method
#        return old_method(self.data, args)
```

#### Step 4: TEST

Run tests to verify extraction didn't break anything


```python
pytest -xvs -k securityanalyzer
```

#### Step 5: OPTIONAL

If class is still >200 lines, consider splitting into multiple classes


```python
# Options:
# 1. SecurityAnalyzerCore - essential state + core methods
# 2. SecurityAnalyzerIO - file/network operations
# 3. SecurityAnalyzerValidator - validation logic
# 4. SecurityAnalyzerRenderer - display/formatting logic
```

**Rollback**: `git checkout -- code_audit\analyzers\security.py`
**Test**: `pytest -xvs -k securityanalyzer`

---

## Plan 2: God Class

**Location**: `code_audit\strangler\debt_detector.py:103`
**Severity**: MEDIUM
**Time**: ~31 minutes

### Steps

#### Step 1: ANALYZE

Open code_audit\strangler\debt_detector.py and identify logical groups of methods in DebtDetector

Source: `code_audit\strangler\debt_detector.py`

```python
# Look for methods that:
# 1. Share a common prefix (get_user_*, validate_*, process_*)
# 2. Access the same subset of instance variables
# 3. Are called together in sequence
# 4. Handle the same domain concept (auth, data, ui)
```

#### Step 2: CREATE

Create new module: code_audit\strangler/debtdetector_helpers.py

Target: `code_audit\strangler/debtdetector_helpers.py`

```python
"""
Helper functions extracted from DebtDetector

This module contains extracted helper functions that were previously
methods of the DebtDetector class. They are now standalone functions
that accept the necessary data as parameters.
"""
from typing import Any


# Paste extracted functions here
```

#### Step 3: EXTRACT

Move helper methods (methods that don't use 'self' much) to new module

Source: `code_audit\strangler\debt_detector.py`
Target: `code_audit\strangler/debtdetector_helpers.py`

```python
# FOR EACH helper method:
# 1. Copy the method to the new file
# 2. Remove 'self' parameter if not needed
# 3. Add any needed parameters that were self.xxx
# 4. Update imports in new file
# 5. In original class, replace method body with:
#
#    def old_method(self, args):
#        from .class_helpers import old_method
#        return old_method(self.data, args)
```

#### Step 4: TEST

Run tests to verify extraction didn't break anything


```python
pytest -xvs -k debtdetector
```

#### Step 5: OPTIONAL

If class is still >200 lines, consider splitting into multiple classes


```python
# Options:
# 1. DebtDetectorCore - essential state + core methods
# 2. DebtDetectorIO - file/network operations
# 3. DebtDetectorValidator - validation logic
# 4. DebtDetectorRenderer - display/formatting logic
```

**Rollback**: `git checkout -- code_audit\strangler\debt_detector.py`
**Test**: `pytest -xvs -k debtdetector`

---

## Plan 3: God Function

**Location**: `code_audit\__main__.py:197`
**Severity**: HIGH
**Time**: ~115 minutes

### Steps

#### Step 1: ANALYZE

Read _build_parser and mark logical blocks with comments

Source: `code_audit\__main__.py`

```python
# Add comments like:
# --- BLOCK 1: Input validation ---
# --- BLOCK 2: Data transformation ---
# --- BLOCK 3: Business logic ---
# --- BLOCK 4: Output formatting ---
```

#### Step 2: EXTRACT

Extract the first logical block to a helper function

Source: `code_audit\__main__.py`

```python
def __build_parser_validate_input(args):
    '''Extracted from _build_parser: input validation'''
    # Paste block 1 code here
    # Return validated data

def _build_parser(original_args):
    # Replace block 1 with:
    validated = __build_parser_validate_input(original_args)
    # ... rest of function
```

#### Step 3: TEST

Run tests to verify first extraction


```python
pytest -x
```

#### Step 4: REPEAT

Repeat extraction for each remaining block


```python
# Pattern for each block:
# 1. Create helper: _funcname_blockname(data) -> result
# 2. Move block code to helper
# 3. In main function, call helper
# 4. Test after each extraction

# Final function should look like:
def {func_name}(args):
    validated = _validate_input(args)
    transformed = _transform_data(validated)
    result = _apply_business_logic(transformed)
    return _format_output(result)
```

#### Step 5: OPTIONAL

If >5 helper functions, consider making a class


```python
class BuildParserProcessor:
    def __init__(self, config):
        self.config = config

    def validate(self, data): ...
    def transform(self, data): ...
    def process(self, data): ...
    def format(self, result): ...

    def run(self, data):
        '''Main entry point (replaces original function)'''
        validated = self.validate(data)
        transformed = self.transform(validated)
        result = self.process(transformed)
        return self.format(result)
```

**Rollback**: `git checkout -- code_audit\__main__.py`
**Test**: `pytest -xvs -k _build_parser`

---

## Plan 4: God Function

**Location**: `code_audit\__main__.py:777`
**Severity**: MEDIUM
**Time**: ~10 minutes

### Steps

#### Step 1: ANALYZE

Read _handle_fence and mark logical blocks with comments

Source: `code_audit\__main__.py`

```python
# Add comments like:
# --- BLOCK 1: Input validation ---
# --- BLOCK 2: Data transformation ---
# --- BLOCK 3: Business logic ---
# --- BLOCK 4: Output formatting ---
```

#### Step 2: EXTRACT

Extract the first logical block to a helper function

Source: `code_audit\__main__.py`

```python
def __handle_fence_validate_input(args):
    '''Extracted from _handle_fence: input validation'''
    # Paste block 1 code here
    # Return validated data

def _handle_fence(original_args):
    # Replace block 1 with:
    validated = __handle_fence_validate_input(original_args)
    # ... rest of function
```

#### Step 3: TEST

Run tests to verify first extraction


```python
pytest -x
```

#### Step 4: REPEAT

Repeat extraction for each remaining block


```python
# Pattern for each block:
# 1. Create helper: _funcname_blockname(data) -> result
# 2. Move block code to helper
# 3. In main function, call helper
# 4. Test after each extraction

# Final function should look like:
def {func_name}(args):
    validated = _validate_input(args)
    transformed = _transform_data(validated)
    result = _apply_business_logic(transformed)
    return _format_output(result)
```

#### Step 5: OPTIONAL

If >5 helper functions, consider making a class


```python
class HandleFenceProcessor:
    def __init__(self, config):
        self.config = config

    def validate(self, data): ...
    def transform(self, data): ...
    def process(self, data): ...
    def format(self, result): ...

    def run(self, data):
        '''Main entry point (replaces original function)'''
        validated = self.validate(data)
        transformed = self.transform(validated)
        result = self.process(transformed)
        return self.format(result)
```

**Rollback**: `git checkout -- code_audit\__main__.py`
**Test**: `pytest -xvs -k _handle_fence`

---

## Plan 5: God Function

**Location**: `code_audit\__main__.py:829`
**Severity**: MEDIUM
**Time**: ~15 minutes

### Steps

#### Step 1: ANALYZE

Read _handle_governance and mark logical blocks with comments

Source: `code_audit\__main__.py`

```python
# Add comments like:
# --- BLOCK 1: Input validation ---
# --- BLOCK 2: Data transformation ---
# --- BLOCK 3: Business logic ---
# --- BLOCK 4: Output formatting ---
```

#### Step 2: EXTRACT

Extract the first logical block to a helper function

Source: `code_audit\__main__.py`

```python
def __handle_governance_validate_input(args):
    '''Extracted from _handle_governance: input validation'''
    # Paste block 1 code here
    # Return validated data

def _handle_governance(original_args):
    # Replace block 1 with:
    validated = __handle_governance_validate_input(original_args)
    # ... rest of function
```

#### Step 3: TEST

Run tests to verify first extraction


```python
pytest -x
```

#### Step 4: REPEAT

Repeat extraction for each remaining block


```python
# Pattern for each block:
# 1. Create helper: _funcname_blockname(data) -> result
# 2. Move block code to helper
# 3. In main function, call helper
# 4. Test after each extraction

# Final function should look like:
def {func_name}(args):
    validated = _validate_input(args)
    transformed = _transform_data(validated)
    result = _apply_business_logic(transformed)
    return _format_output(result)
```

#### Step 5: OPTIONAL

If >5 helper functions, consider making a class


```python
class HandleGovernanceProcessor:
    def __init__(self, config):
        self.config = config

    def validate(self, data): ...
    def transform(self, data): ...
    def process(self, data): ...
    def format(self, result): ...

    def run(self, data):
        '''Main entry point (replaces original function)'''
        validated = self.validate(data)
        transformed = self.transform(validated)
        result = self.process(transformed)
        return self.format(result)
```

**Rollback**: `git checkout -- code_audit\__main__.py`
**Test**: `pytest -xvs -k _handle_governance`

---

## Plan 6: God Function

**Location**: `code_audit\__main__.py:1262`
**Severity**: HIGH
**Time**: ~44 minutes

### Steps

#### Step 1: ANALYZE

Read _handle_debt and mark logical blocks with comments

Source: `code_audit\__main__.py`

```python
# Add comments like:
# --- BLOCK 1: Input validation ---
# --- BLOCK 2: Data transformation ---
# --- BLOCK 3: Business logic ---
# --- BLOCK 4: Output formatting ---
```

#### Step 2: EXTRACT

Extract the first logical block to a helper function

Source: `code_audit\__main__.py`

```python
def __handle_debt_validate_input(args):
    '''Extracted from _handle_debt: input validation'''
    # Paste block 1 code here
    # Return validated data

def _handle_debt(original_args):
    # Replace block 1 with:
    validated = __handle_debt_validate_input(original_args)
    # ... rest of function
```

#### Step 3: TEST

Run tests to verify first extraction


```python
pytest -x
```

#### Step 4: REPEAT

Repeat extraction for each remaining block


```python
# Pattern for each block:
# 1. Create helper: _funcname_blockname(data) -> result
# 2. Move block code to helper
# 3. In main function, call helper
# 4. Test after each extraction

# Final function should look like:
def {func_name}(args):
    validated = _validate_input(args)
    transformed = _transform_data(validated)
    result = _apply_business_logic(transformed)
    return _format_output(result)
```

#### Step 5: OPTIONAL

If >5 helper functions, consider making a class


```python
class HandleDebtProcessor:
    def __init__(self, config):
        self.config = config

    def validate(self, data): ...
    def transform(self, data): ...
    def process(self, data): ...
    def format(self, result): ...

    def run(self, data):
        '''Main entry point (replaces original function)'''
        validated = self.validate(data)
        transformed = self.transform(validated)
        result = self.process(transformed)
        return self.format(result)
```

**Rollback**: `git checkout -- code_audit\__main__.py`
**Test**: `pytest -xvs -k _handle_debt`

---

## Plan 7: God Function

**Location**: `code_audit\__main__.py:1530`
**Severity**: HIGH
**Time**: ~43 minutes

### Steps

#### Step 1: ANALYZE

Read main and mark logical blocks with comments

Source: `code_audit\__main__.py`

```python
# Add comments like:
# --- BLOCK 1: Input validation ---
# --- BLOCK 2: Data transformation ---
# --- BLOCK 3: Business logic ---
# --- BLOCK 4: Output formatting ---
```

#### Step 2: EXTRACT

Extract the first logical block to a helper function

Source: `code_audit\__main__.py`

```python
def _main_validate_input(args):
    '''Extracted from main: input validation'''
    # Paste block 1 code here
    # Return validated data

def main(original_args):
    # Replace block 1 with:
    validated = _main_validate_input(original_args)
    # ... rest of function
```

#### Step 3: TEST

Run tests to verify first extraction


```python
pytest -x
```

#### Step 4: REPEAT

Repeat extraction for each remaining block


```python
# Pattern for each block:
# 1. Create helper: _funcname_blockname(data) -> result
# 2. Move block code to helper
# 3. In main function, call helper
# 4. Test after each extraction

# Final function should look like:
def {func_name}(args):
    validated = _validate_input(args)
    transformed = _transform_data(validated)
    result = _apply_business_logic(transformed)
    return _format_output(result)
```

#### Step 5: OPTIONAL

If >5 helper functions, consider making a class


```python
class MainProcessor:
    def __init__(self, config):
        self.config = config

    def validate(self, data): ...
    def transform(self, data): ...
    def process(self, data): ...
    def format(self, result): ...

    def run(self, data):
        '''Main entry point (replaces original function)'''
        validated = self.validate(data)
        transformed = self.transform(validated)
        result = self.process(transformed)
        return self.format(result)
```

**Rollback**: `git checkout -- code_audit\__main__.py`
**Test**: `pytest -xvs -k main`

---

## Plan 8: God Function

**Location**: `code_audit\analyzers\dead_code.py:387`
**Severity**: HIGH
**Time**: ~22 minutes

### Steps

#### Step 1: ANALYZE

Read analyze_dead_code and mark logical blocks with comments

Source: `code_audit\analyzers\dead_code.py`

```python
# Add comments like:
# --- BLOCK 1: Input validation ---
# --- BLOCK 2: Data transformation ---
# --- BLOCK 3: Business logic ---
# --- BLOCK 4: Output formatting ---
```

#### Step 2: EXTRACT

Extract the first logical block to a helper function

Source: `code_audit\analyzers\dead_code.py`

```python
def _analyze_dead_code_validate_input(args):
    '''Extracted from analyze_dead_code: input validation'''
    # Paste block 1 code here
    # Return validated data

def analyze_dead_code(original_args):
    # Replace block 1 with:
    validated = _analyze_dead_code_validate_input(original_args)
    # ... rest of function
```

#### Step 3: TEST

Run tests to verify first extraction


```python
pytest -x
```

#### Step 4: REPEAT

Repeat extraction for each remaining block


```python
# Pattern for each block:
# 1. Create helper: _funcname_blockname(data) -> result
# 2. Move block code to helper
# 3. In main function, call helper
# 4. Test after each extraction

# Final function should look like:
def {func_name}(args):
    validated = _validate_input(args)
    transformed = _transform_data(validated)
    result = _apply_business_logic(transformed)
    return _format_output(result)
```

#### Step 5: OPTIONAL

If >5 helper functions, consider making a class


```python
class AnalyzeDeadCodeProcessor:
    def __init__(self, config):
        self.config = config

    def validate(self, data): ...
    def transform(self, data): ...
    def process(self, data): ...
    def format(self, result): ...

    def run(self, data):
        '''Main entry point (replaces original function)'''
        validated = self.validate(data)
        transformed = self.transform(validated)
        result = self.process(transformed)
        return self.format(result)
```

**Rollback**: `git checkout -- code_audit\analyzers\dead_code.py`
**Test**: `pytest -xvs -k analyze_dead_code`

---

## Plan 9: God Function

**Location**: `code_audit\analyzers\dead_code.py:150`
**Severity**: MEDIUM
**Time**: ~11 minutes

### Steps

#### Step 1: ANALYZE

Read _detect_unreachable and mark logical blocks with comments

Source: `code_audit\analyzers\dead_code.py`

```python
# Add comments like:
# --- BLOCK 1: Input validation ---
# --- BLOCK 2: Data transformation ---
# --- BLOCK 3: Business logic ---
# --- BLOCK 4: Output formatting ---
```

#### Step 2: EXTRACT

Extract the first logical block to a helper function

Source: `code_audit\analyzers\dead_code.py`

```python
def __detect_unreachable_validate_input(args):
    '''Extracted from _detect_unreachable: input validation'''
    # Paste block 1 code here
    # Return validated data

def _detect_unreachable(original_args):
    # Replace block 1 with:
    validated = __detect_unreachable_validate_input(original_args)
    # ... rest of function
```

#### Step 3: TEST

Run tests to verify first extraction


```python
pytest -x
```

#### Step 4: REPEAT

Repeat extraction for each remaining block


```python
# Pattern for each block:
# 1. Create helper: _funcname_blockname(data) -> result
# 2. Move block code to helper
# 3. In main function, call helper
# 4. Test after each extraction

# Final function should look like:
def {func_name}(args):
    validated = _validate_input(args)
    transformed = _transform_data(validated)
    result = _apply_business_logic(transformed)
    return _format_output(result)
```

#### Step 5: OPTIONAL

If >5 helper functions, consider making a class


```python
class DetectUnreachableProcessor:
    def __init__(self, config):
        self.config = config

    def validate(self, data): ...
    def transform(self, data): ...
    def process(self, data): ...
    def format(self, result): ...

    def run(self, data):
        '''Main entry point (replaces original function)'''
        validated = self.validate(data)
        transformed = self.transform(validated)
        result = self.process(transformed)
        return self.format(result)
```

**Rollback**: `git checkout -- code_audit\analyzers\dead_code.py`
**Test**: `pytest -xvs -k _detect_unreachable`

---

## Plan 10: God Function

**Location**: `code_audit\analyzers\dead_code.py:206`
**Severity**: MEDIUM
**Time**: ~11 minutes

### Steps

#### Step 1: ANALYZE

Read _check_body_for_unreachable and mark logical blocks with comments

Source: `code_audit\analyzers\dead_code.py`

```python
# Add comments like:
# --- BLOCK 1: Input validation ---
# --- BLOCK 2: Data transformation ---
# --- BLOCK 3: Business logic ---
# --- BLOCK 4: Output formatting ---
```

#### Step 2: EXTRACT

Extract the first logical block to a helper function

Source: `code_audit\analyzers\dead_code.py`

```python
def __check_body_for_unreachable_validate_input(args):
    '''Extracted from _check_body_for_unreachable: input validation'''
    # Paste block 1 code here
    # Return validated data

def _check_body_for_unreachable(original_args):
    # Replace block 1 with:
    validated = __check_body_for_unreachable_validate_input(original_args)
    # ... rest of function
```

#### Step 3: TEST

Run tests to verify first extraction


```python
pytest -x
```

#### Step 4: REPEAT

Repeat extraction for each remaining block


```python
# Pattern for each block:
# 1. Create helper: _funcname_blockname(data) -> result
# 2. Move block code to helper
# 3. In main function, call helper
# 4. Test after each extraction

# Final function should look like:
def {func_name}(args):
    validated = _validate_input(args)
    transformed = _transform_data(validated)
    result = _apply_business_logic(transformed)
    return _format_output(result)
```

#### Step 5: OPTIONAL

If >5 helper functions, consider making a class


```python
class CheckBodyForUnreachableProcessor:
    def __init__(self, config):
        self.config = config

    def validate(self, data): ...
    def transform(self, data): ...
    def process(self, data): ...
    def format(self, result): ...

    def run(self, data):
        '''Main entry point (replaces original function)'''
        validated = self.validate(data)
        transformed = self.transform(validated)
        result = self.process(transformed)
        return self.format(result)
```

**Rollback**: `git checkout -- code_audit\analyzers\dead_code.py`
**Test**: `pytest -xvs -k _check_body_for_unreachable`

---

## Plan 11: God Function

**Location**: `code_audit\analyzers\dead_code.py:264`
**Severity**: MEDIUM
**Time**: ~14 minutes

### Steps

#### Step 1: ANALYZE

Read _detect_if_false and mark logical blocks with comments

Source: `code_audit\analyzers\dead_code.py`

```python
# Add comments like:
# --- BLOCK 1: Input validation ---
# --- BLOCK 2: Data transformation ---
# --- BLOCK 3: Business logic ---
# --- BLOCK 4: Output formatting ---
```

#### Step 2: EXTRACT

Extract the first logical block to a helper function

Source: `code_audit\analyzers\dead_code.py`

```python
def __detect_if_false_validate_input(args):
    '''Extracted from _detect_if_false: input validation'''
    # Paste block 1 code here
    # Return validated data

def _detect_if_false(original_args):
    # Replace block 1 with:
    validated = __detect_if_false_validate_input(original_args)
    # ... rest of function
```

#### Step 3: TEST

Run tests to verify first extraction


```python
pytest -x
```

#### Step 4: REPEAT

Repeat extraction for each remaining block


```python
# Pattern for each block:
# 1. Create helper: _funcname_blockname(data) -> result
# 2. Move block code to helper
# 3. In main function, call helper
# 4. Test after each extraction

# Final function should look like:
def {func_name}(args):
    validated = _validate_input(args)
    transformed = _transform_data(validated)
    result = _apply_business_logic(transformed)
    return _format_output(result)
```

#### Step 5: OPTIONAL

If >5 helper functions, consider making a class


```python
class DetectIfFalseProcessor:
    def __init__(self, config):
        self.config = config

    def validate(self, data): ...
    def transform(self, data): ...
    def process(self, data): ...
    def format(self, result): ...

    def run(self, data):
        '''Main entry point (replaces original function)'''
        validated = self.validate(data)
        transformed = self.transform(validated)
        result = self.process(transformed)
        return self.format(result)
```

**Rollback**: `git checkout -- code_audit\analyzers\dead_code.py`
**Test**: `pytest -xvs -k _detect_if_false`

---

## Plan 12: God Function

**Location**: `code_audit\analyzers\duplication.py:162`
**Severity**: MEDIUM
**Time**: ~18 minutes

### Steps

#### Step 1: ANALYZE

Read run and mark logical blocks with comments

Source: `code_audit\analyzers\duplication.py`

```python
# Add comments like:
# --- BLOCK 1: Input validation ---
# --- BLOCK 2: Data transformation ---
# --- BLOCK 3: Business logic ---
# --- BLOCK 4: Output formatting ---
```

#### Step 2: EXTRACT

Extract the first logical block to a helper function

Source: `code_audit\analyzers\duplication.py`

```python
def _run_validate_input(args):
    '''Extracted from run: input validation'''
    # Paste block 1 code here
    # Return validated data

def run(original_args):
    # Replace block 1 with:
    validated = _run_validate_input(original_args)
    # ... rest of function
```

#### Step 3: TEST

Run tests to verify first extraction


```python
pytest -x
```

#### Step 4: REPEAT

Repeat extraction for each remaining block


```python
# Pattern for each block:
# 1. Create helper: _funcname_blockname(data) -> result
# 2. Move block code to helper
# 3. In main function, call helper
# 4. Test after each extraction

# Final function should look like:
def {func_name}(args):
    validated = _validate_input(args)
    transformed = _transform_data(validated)
    result = _apply_business_logic(transformed)
    return _format_output(result)
```

#### Step 5: OPTIONAL

If >5 helper functions, consider making a class


```python
class RunProcessor:
    def __init__(self, config):
        self.config = config

    def validate(self, data): ...
    def transform(self, data): ...
    def process(self, data): ...
    def format(self, result): ...

    def run(self, data):
        '''Main entry point (replaces original function)'''
        validated = self.validate(data)
        transformed = self.transform(validated)
        result = self.process(transformed)
        return self.format(result)
```

**Rollback**: `git checkout -- code_audit\analyzers\duplication.py`
**Test**: `pytest -xvs -k run`

---

## Plan 13: God Function

**Location**: `code_audit\analyzers\exceptions.py:246`
**Severity**: HIGH
**Time**: ~25 minutes

### Steps

#### Step 1: ANALYZE

Read analyze_exceptions and mark logical blocks with comments

Source: `code_audit\analyzers\exceptions.py`

```python
# Add comments like:
# --- BLOCK 1: Input validation ---
# --- BLOCK 2: Data transformation ---
# --- BLOCK 3: Business logic ---
# --- BLOCK 4: Output formatting ---
```

#### Step 2: EXTRACT

Extract the first logical block to a helper function

Source: `code_audit\analyzers\exceptions.py`

```python
def _analyze_exceptions_validate_input(args):
    '''Extracted from analyze_exceptions: input validation'''
    # Paste block 1 code here
    # Return validated data

def analyze_exceptions(original_args):
    # Replace block 1 with:
    validated = _analyze_exceptions_validate_input(original_args)
    # ... rest of function
```

#### Step 3: TEST

Run tests to verify first extraction


```python
pytest -x
```

#### Step 4: REPEAT

Repeat extraction for each remaining block


```python
# Pattern for each block:
# 1. Create helper: _funcname_blockname(data) -> result
# 2. Move block code to helper
# 3. In main function, call helper
# 4. Test after each extraction

# Final function should look like:
def {func_name}(args):
    validated = _validate_input(args)
    transformed = _transform_data(validated)
    result = _apply_business_logic(transformed)
    return _format_output(result)
```

#### Step 5: OPTIONAL

If >5 helper functions, consider making a class


```python
class AnalyzeExceptionsProcessor:
    def __init__(self, config):
        self.config = config

    def validate(self, data): ...
    def transform(self, data): ...
    def process(self, data): ...
    def format(self, result): ...

    def run(self, data):
        '''Main entry point (replaces original function)'''
        validated = self.validate(data)
        transformed = self.transform(validated)
        result = self.process(transformed)
        return self.format(result)
```

**Rollback**: `git checkout -- code_audit\analyzers\exceptions.py`
**Test**: `pytest -xvs -k analyze_exceptions`

---

## Plan 14: God Function

**Location**: `code_audit\analyzers\exceptions.py:42`
**Severity**: MEDIUM
**Time**: ~14 minutes

### Steps

#### Step 1: ANALYZE

Read run and mark logical blocks with comments

Source: `code_audit\analyzers\exceptions.py`

```python
# Add comments like:
# --- BLOCK 1: Input validation ---
# --- BLOCK 2: Data transformation ---
# --- BLOCK 3: Business logic ---
# --- BLOCK 4: Output formatting ---
```

#### Step 2: EXTRACT

Extract the first logical block to a helper function

Source: `code_audit\analyzers\exceptions.py`

```python
def _run_validate_input(args):
    '''Extracted from run: input validation'''
    # Paste block 1 code here
    # Return validated data

def run(original_args):
    # Replace block 1 with:
    validated = _run_validate_input(original_args)
    # ... rest of function
```

#### Step 3: TEST

Run tests to verify first extraction


```python
pytest -x
```

#### Step 4: REPEAT

Repeat extraction for each remaining block


```python
# Pattern for each block:
# 1. Create helper: _funcname_blockname(data) -> result
# 2. Move block code to helper
# 3. In main function, call helper
# 4. Test after each extraction

# Final function should look like:
def {func_name}(args):
    validated = _validate_input(args)
    transformed = _transform_data(validated)
    result = _apply_business_logic(transformed)
    return _format_output(result)
```

#### Step 5: OPTIONAL

If >5 helper functions, consider making a class


```python
class RunProcessor:
    def __init__(self, config):
        self.config = config

    def validate(self, data): ...
    def transform(self, data): ...
    def process(self, data): ...
    def format(self, result): ...

    def run(self, data):
        '''Main entry point (replaces original function)'''
        validated = self.validate(data)
        transformed = self.transform(validated)
        result = self.process(transformed)
        return self.format(result)
```

**Rollback**: `git checkout -- code_audit\analyzers\exceptions.py`
**Test**: `pytest -xvs -k run`

---

## Plan 15: God Function

**Location**: `code_audit\analyzers\file_sizes.py:62`
**Severity**: MEDIUM
**Time**: ~10 minutes

### Steps

#### Step 1: ANALYZE

Read run and mark logical blocks with comments

Source: `code_audit\analyzers\file_sizes.py`

```python
# Add comments like:
# --- BLOCK 1: Input validation ---
# --- BLOCK 2: Data transformation ---
# --- BLOCK 3: Business logic ---
# --- BLOCK 4: Output formatting ---
```

#### Step 2: EXTRACT

Extract the first logical block to a helper function

Source: `code_audit\analyzers\file_sizes.py`

```python
def _run_validate_input(args):
    '''Extracted from run: input validation'''
    # Paste block 1 code here
    # Return validated data

def run(original_args):
    # Replace block 1 with:
    validated = _run_validate_input(original_args)
    # ... rest of function
```

#### Step 3: TEST

Run tests to verify first extraction


```python
pytest -x
```

#### Step 4: REPEAT

Repeat extraction for each remaining block


```python
# Pattern for each block:
# 1. Create helper: _funcname_blockname(data) -> result
# 2. Move block code to helper
# 3. In main function, call helper
# 4. Test after each extraction

# Final function should look like:
def {func_name}(args):
    validated = _validate_input(args)
    transformed = _transform_data(validated)
    result = _apply_business_logic(transformed)
    return _format_output(result)
```

#### Step 5: OPTIONAL

If >5 helper functions, consider making a class


```python
class RunProcessor:
    def __init__(self, config):
        self.config = config

    def validate(self, data): ...
    def transform(self, data): ...
    def process(self, data): ...
    def format(self, result): ...

    def run(self, data):
        '''Main entry point (replaces original function)'''
        validated = self.validate(data)
        transformed = self.transform(validated)
        result = self.process(transformed)
        return self.format(result)
```

**Rollback**: `git checkout -- code_audit\analyzers\file_sizes.py`
**Test**: `pytest -xvs -k run`

---

## Plan 16: God Function

**Location**: `code_audit\analyzers\global_state.py:135`
**Severity**: MEDIUM
**Time**: ~13 minutes

### Steps

#### Step 1: ANALYZE

Read _check_functions and mark logical blocks with comments

Source: `code_audit\analyzers\global_state.py`

```python
# Add comments like:
# --- BLOCK 1: Input validation ---
# --- BLOCK 2: Data transformation ---
# --- BLOCK 3: Business logic ---
# --- BLOCK 4: Output formatting ---
```

#### Step 2: EXTRACT

Extract the first logical block to a helper function

Source: `code_audit\analyzers\global_state.py`

```python
def __check_functions_validate_input(args):
    '''Extracted from _check_functions: input validation'''
    # Paste block 1 code here
    # Return validated data

def _check_functions(original_args):
    # Replace block 1 with:
    validated = __check_functions_validate_input(original_args)
    # ... rest of function
```

#### Step 3: TEST

Run tests to verify first extraction


```python
pytest -x
```

#### Step 4: REPEAT

Repeat extraction for each remaining block


```python
# Pattern for each block:
# 1. Create helper: _funcname_blockname(data) -> result
# 2. Move block code to helper
# 3. In main function, call helper
# 4. Test after each extraction

# Final function should look like:
def {func_name}(args):
    validated = _validate_input(args)
    transformed = _transform_data(validated)
    result = _apply_business_logic(transformed)
    return _format_output(result)
```

#### Step 5: OPTIONAL

If >5 helper functions, consider making a class


```python
class CheckFunctionsProcessor:
    def __init__(self, config):
        self.config = config

    def validate(self, data): ...
    def transform(self, data): ...
    def process(self, data): ...
    def format(self, result): ...

    def run(self, data):
        '''Main entry point (replaces original function)'''
        validated = self.validate(data)
        transformed = self.transform(validated)
        result = self.process(transformed)
        return self.format(result)
```

**Rollback**: `git checkout -- code_audit\analyzers\global_state.py`
**Test**: `pytest -xvs -k _check_functions`

---

## Plan 17: God Function

**Location**: `code_audit\analyzers\routers.py:225`
**Severity**: MEDIUM
**Time**: ~10 minutes

### Steps

#### Step 1: ANALYZE

Read build_consolidation_plan and mark logical blocks with comments

Source: `code_audit\analyzers\routers.py`

```python
# Add comments like:
# --- BLOCK 1: Input validation ---
# --- BLOCK 2: Data transformation ---
# --- BLOCK 3: Business logic ---
# --- BLOCK 4: Output formatting ---
```

#### Step 2: EXTRACT

Extract the first logical block to a helper function

Source: `code_audit\analyzers\routers.py`

```python
def _build_consolidation_plan_validate_input(args):
    '''Extracted from build_consolidation_plan: input validation'''
    # Paste block 1 code here
    # Return validated data

def build_consolidation_plan(original_args):
    # Replace block 1 with:
    validated = _build_consolidation_plan_validate_input(original_args)
    # ... rest of function
```

#### Step 3: TEST

Run tests to verify first extraction


```python
pytest -x
```

#### Step 4: REPEAT

Repeat extraction for each remaining block


```python
# Pattern for each block:
# 1. Create helper: _funcname_blockname(data) -> result
# 2. Move block code to helper
# 3. In main function, call helper
# 4. Test after each extraction

# Final function should look like:
def {func_name}(args):
    validated = _validate_input(args)
    transformed = _transform_data(validated)
    result = _apply_business_logic(transformed)
    return _format_output(result)
```

#### Step 5: OPTIONAL

If >5 helper functions, consider making a class


```python
class BuildConsolidationPlanProcessor:
    def __init__(self, config):
        self.config = config

    def validate(self, data): ...
    def transform(self, data): ...
    def process(self, data): ...
    def format(self, result): ...

    def run(self, data):
        '''Main entry point (replaces original function)'''
        validated = self.validate(data)
        transformed = self.transform(validated)
        result = self.process(transformed)
        return self.format(result)
```

**Rollback**: `git checkout -- code_audit\analyzers\routers.py`
**Test**: `pytest -xvs -k build_consolidation_plan`

---

## Plan 18: God Function

**Location**: `code_audit\analyzers\routers.py:436`
**Severity**: MEDIUM
**Time**: ~13 minutes

### Steps

#### Step 1: ANALYZE

Read generate_router_report and mark logical blocks with comments

Source: `code_audit\analyzers\routers.py`

```python
# Add comments like:
# --- BLOCK 1: Input validation ---
# --- BLOCK 2: Data transformation ---
# --- BLOCK 3: Business logic ---
# --- BLOCK 4: Output formatting ---
```

#### Step 2: EXTRACT

Extract the first logical block to a helper function

Source: `code_audit\analyzers\routers.py`

```python
def _generate_router_report_validate_input(args):
    '''Extracted from generate_router_report: input validation'''
    # Paste block 1 code here
    # Return validated data

def generate_router_report(original_args):
    # Replace block 1 with:
    validated = _generate_router_report_validate_input(original_args)
    # ... rest of function
```

#### Step 3: TEST

Run tests to verify first extraction


```python
pytest -x
```

#### Step 4: REPEAT

Repeat extraction for each remaining block


```python
# Pattern for each block:
# 1. Create helper: _funcname_blockname(data) -> result
# 2. Move block code to helper
# 3. In main function, call helper
# 4. Test after each extraction

# Final function should look like:
def {func_name}(args):
    validated = _validate_input(args)
    transformed = _transform_data(validated)
    result = _apply_business_logic(transformed)
    return _format_output(result)
```

#### Step 5: OPTIONAL

If >5 helper functions, consider making a class


```python
class GenerateRouterReportProcessor:
    def __init__(self, config):
        self.config = config

    def validate(self, data): ...
    def transform(self, data): ...
    def process(self, data): ...
    def format(self, result): ...

    def run(self, data):
        '''Main entry point (replaces original function)'''
        validated = self.validate(data)
        transformed = self.transform(validated)
        result = self.process(transformed)
        return self.format(result)
```

**Rollback**: `git checkout -- code_audit\analyzers\routers.py`
**Test**: `pytest -xvs -k generate_router_report`

---

## Plan 19: God Function

**Location**: `code_audit\analyzers\routers.py:309`
**Severity**: HIGH
**Time**: ~23 minutes

### Steps

#### Step 1: ANALYZE

Read run and mark logical blocks with comments

Source: `code_audit\analyzers\routers.py`

```python
# Add comments like:
# --- BLOCK 1: Input validation ---
# --- BLOCK 2: Data transformation ---
# --- BLOCK 3: Business logic ---
# --- BLOCK 4: Output formatting ---
```

#### Step 2: EXTRACT

Extract the first logical block to a helper function

Source: `code_audit\analyzers\routers.py`

```python
def _run_validate_input(args):
    '''Extracted from run: input validation'''
    # Paste block 1 code here
    # Return validated data

def run(original_args):
    # Replace block 1 with:
    validated = _run_validate_input(original_args)
    # ... rest of function
```

#### Step 3: TEST

Run tests to verify first extraction


```python
pytest -x
```

#### Step 4: REPEAT

Repeat extraction for each remaining block


```python
# Pattern for each block:
# 1. Create helper: _funcname_blockname(data) -> result
# 2. Move block code to helper
# 3. In main function, call helper
# 4. Test after each extraction

# Final function should look like:
def {func_name}(args):
    validated = _validate_input(args)
    transformed = _transform_data(validated)
    result = _apply_business_logic(transformed)
    return _format_output(result)
```

#### Step 5: OPTIONAL

If >5 helper functions, consider making a class


```python
class RunProcessor:
    def __init__(self, config):
        self.config = config

    def validate(self, data): ...
    def transform(self, data): ...
    def process(self, data): ...
    def format(self, result): ...

    def run(self, data):
        '''Main entry point (replaces original function)'''
        validated = self.validate(data)
        transformed = self.transform(validated)
        result = self.process(transformed)
        return self.format(result)
```

**Rollback**: `git checkout -- code_audit\analyzers\routers.py`
**Test**: `pytest -xvs -k run`

---

## Plan 20: God Function

**Location**: `code_audit\analyzers\security.py:268`
**Severity**: MEDIUM
**Time**: ~18 minutes

### Steps

#### Step 1: ANALYZE

Read _detect_subprocess_shell and mark logical blocks with comments

Source: `code_audit\analyzers\security.py`

```python
# Add comments like:
# --- BLOCK 1: Input validation ---
# --- BLOCK 2: Data transformation ---
# --- BLOCK 3: Business logic ---
# --- BLOCK 4: Output formatting ---
```

#### Step 2: EXTRACT

Extract the first logical block to a helper function

Source: `code_audit\analyzers\security.py`

```python
def __detect_subprocess_shell_validate_input(args):
    '''Extracted from _detect_subprocess_shell: input validation'''
    # Paste block 1 code here
    # Return validated data

def _detect_subprocess_shell(original_args):
    # Replace block 1 with:
    validated = __detect_subprocess_shell_validate_input(original_args)
    # ... rest of function
```

#### Step 3: TEST

Run tests to verify first extraction


```python
pytest -x
```

#### Step 4: REPEAT

Repeat extraction for each remaining block


```python
# Pattern for each block:
# 1. Create helper: _funcname_blockname(data) -> result
# 2. Move block code to helper
# 3. In main function, call helper
# 4. Test after each extraction

# Final function should look like:
def {func_name}(args):
    validated = _validate_input(args)
    transformed = _transform_data(validated)
    result = _apply_business_logic(transformed)
    return _format_output(result)
```

#### Step 5: OPTIONAL

If >5 helper functions, consider making a class


```python
class DetectSubprocessShellProcessor:
    def __init__(self, config):
        self.config = config

    def validate(self, data): ...
    def transform(self, data): ...
    def process(self, data): ...
    def format(self, result): ...

    def run(self, data):
        '''Main entry point (replaces original function)'''
        validated = self.validate(data)
        transformed = self.transform(validated)
        result = self.process(transformed)
        return self.format(result)
```

**Rollback**: `git checkout -- code_audit\analyzers\security.py`
**Test**: `pytest -xvs -k _detect_subprocess_shell`

---

## Plan 21: God Function

**Location**: `code_audit\analyzers\security.py:359`
**Severity**: MEDIUM
**Time**: ~15 minutes

### Steps

#### Step 1: ANALYZE

Read _detect_sql_injection and mark logical blocks with comments

Source: `code_audit\analyzers\security.py`

```python
# Add comments like:
# --- BLOCK 1: Input validation ---
# --- BLOCK 2: Data transformation ---
# --- BLOCK 3: Business logic ---
# --- BLOCK 4: Output formatting ---
```

#### Step 2: EXTRACT

Extract the first logical block to a helper function

Source: `code_audit\analyzers\security.py`

```python
def __detect_sql_injection_validate_input(args):
    '''Extracted from _detect_sql_injection: input validation'''
    # Paste block 1 code here
    # Return validated data

def _detect_sql_injection(original_args):
    # Replace block 1 with:
    validated = __detect_sql_injection_validate_input(original_args)
    # ... rest of function
```

#### Step 3: TEST

Run tests to verify first extraction


```python
pytest -x
```

#### Step 4: REPEAT

Repeat extraction for each remaining block


```python
# Pattern for each block:
# 1. Create helper: _funcname_blockname(data) -> result
# 2. Move block code to helper
# 3. In main function, call helper
# 4. Test after each extraction

# Final function should look like:
def {func_name}(args):
    validated = _validate_input(args)
    transformed = _transform_data(validated)
    result = _apply_business_logic(transformed)
    return _format_output(result)
```

#### Step 5: OPTIONAL

If >5 helper functions, consider making a class


```python
class DetectSqlInjectionProcessor:
    def __init__(self, config):
        self.config = config

    def validate(self, data): ...
    def transform(self, data): ...
    def process(self, data): ...
    def format(self, result): ...

    def run(self, data):
        '''Main entry point (replaces original function)'''
        validated = self.validate(data)
        transformed = self.transform(validated)
        result = self.process(transformed)
        return self.format(result)
```

**Rollback**: `git checkout -- code_audit\analyzers\security.py`
**Test**: `pytest -xvs -k _detect_sql_injection`

---

## Plan 22: God Function

**Location**: `code_audit\analyzers\security.py:484`
**Severity**: MEDIUM
**Time**: ~19 minutes

### Steps

#### Step 1: ANALYZE

Read _detect_yaml_unsafe and mark logical blocks with comments

Source: `code_audit\analyzers\security.py`

```python
# Add comments like:
# --- BLOCK 1: Input validation ---
# --- BLOCK 2: Data transformation ---
# --- BLOCK 3: Business logic ---
# --- BLOCK 4: Output formatting ---
```

#### Step 2: EXTRACT

Extract the first logical block to a helper function

Source: `code_audit\analyzers\security.py`

```python
def __detect_yaml_unsafe_validate_input(args):
    '''Extracted from _detect_yaml_unsafe: input validation'''
    # Paste block 1 code here
    # Return validated data

def _detect_yaml_unsafe(original_args):
    # Replace block 1 with:
    validated = __detect_yaml_unsafe_validate_input(original_args)
    # ... rest of function
```

#### Step 3: TEST

Run tests to verify first extraction


```python
pytest -x
```

#### Step 4: REPEAT

Repeat extraction for each remaining block


```python
# Pattern for each block:
# 1. Create helper: _funcname_blockname(data) -> result
# 2. Move block code to helper
# 3. In main function, call helper
# 4. Test after each extraction

# Final function should look like:
def {func_name}(args):
    validated = _validate_input(args)
    transformed = _transform_data(validated)
    result = _apply_business_logic(transformed)
    return _format_output(result)
```

#### Step 5: OPTIONAL

If >5 helper functions, consider making a class


```python
class DetectYamlUnsafeProcessor:
    def __init__(self, config):
        self.config = config

    def validate(self, data): ...
    def transform(self, data): ...
    def process(self, data): ...
    def format(self, result): ...

    def run(self, data):
        '''Main entry point (replaces original function)'''
        validated = self.validate(data)
        transformed = self.transform(validated)
        result = self.process(transformed)
        return self.format(result)
```

**Rollback**: `git checkout -- code_audit\analyzers\security.py`
**Test**: `pytest -xvs -k _detect_yaml_unsafe`

---

## Plan 23: God Function

**Location**: `code_audit\api.py:74`
**Severity**: MEDIUM
**Time**: ~12 minutes

### Steps

#### Step 1: ANALYZE

Read scan_project and mark logical blocks with comments

Source: `code_audit\api.py`

```python
# Add comments like:
# --- BLOCK 1: Input validation ---
# --- BLOCK 2: Data transformation ---
# --- BLOCK 3: Business logic ---
# --- BLOCK 4: Output formatting ---
```

#### Step 2: EXTRACT

Extract the first logical block to a helper function

Source: `code_audit\api.py`

```python
def _scan_project_validate_input(args):
    '''Extracted from scan_project: input validation'''
    # Paste block 1 code here
    # Return validated data

def scan_project(original_args):
    # Replace block 1 with:
    validated = _scan_project_validate_input(original_args)
    # ... rest of function
```

#### Step 3: TEST

Run tests to verify first extraction


```python
pytest -x
```

#### Step 4: REPEAT

Repeat extraction for each remaining block


```python
# Pattern for each block:
# 1. Create helper: _funcname_blockname(data) -> result
# 2. Move block code to helper
# 3. In main function, call helper
# 4. Test after each extraction

# Final function should look like:
def {func_name}(args):
    validated = _validate_input(args)
    transformed = _transform_data(validated)
    result = _apply_business_logic(transformed)
    return _format_output(result)
```

#### Step 5: OPTIONAL

If >5 helper functions, consider making a class


```python
class ScanProjectProcessor:
    def __init__(self, config):
        self.config = config

    def validate(self, data): ...
    def transform(self, data): ...
    def process(self, data): ...
    def format(self, result): ...

    def run(self, data):
        '''Main entry point (replaces original function)'''
        validated = self.validate(data)
        transformed = self.transform(validated)
        result = self.process(transformed)
        return self.format(result)
```

**Rollback**: `git checkout -- code_audit\api.py`
**Test**: `pytest -xvs -k scan_project`

---

## Plan 24: God Function

**Location**: `code_audit\api.py:195`
**Severity**: MEDIUM
**Time**: ~14 minutes

### Steps

#### Step 1: ANALYZE

Read compare_debt and mark logical blocks with comments

Source: `code_audit\api.py`

```python
# Add comments like:
# --- BLOCK 1: Input validation ---
# --- BLOCK 2: Data transformation ---
# --- BLOCK 3: Business logic ---
# --- BLOCK 4: Output formatting ---
```

#### Step 2: EXTRACT

Extract the first logical block to a helper function

Source: `code_audit\api.py`

```python
def _compare_debt_validate_input(args):
    '''Extracted from compare_debt: input validation'''
    # Paste block 1 code here
    # Return validated data

def compare_debt(original_args):
    # Replace block 1 with:
    validated = _compare_debt_validate_input(original_args)
    # ... rest of function
```

#### Step 3: TEST

Run tests to verify first extraction


```python
pytest -x
```

#### Step 4: REPEAT

Repeat extraction for each remaining block


```python
# Pattern for each block:
# 1. Create helper: _funcname_blockname(data) -> result
# 2. Move block code to helper
# 3. In main function, call helper
# 4. Test after each extraction

# Final function should look like:
def {func_name}(args):
    validated = _validate_input(args)
    transformed = _transform_data(validated)
    result = _apply_business_logic(transformed)
    return _format_output(result)
```

#### Step 5: OPTIONAL

If >5 helper functions, consider making a class


```python
class CompareDebtProcessor:
    def __init__(self, config):
        self.config = config

    def validate(self, data): ...
    def transform(self, data): ...
    def process(self, data): ...
    def format(self, result): ...

    def run(self, data):
        '''Main entry point (replaces original function)'''
        validated = self.validate(data)
        transformed = self.transform(validated)
        result = self.process(transformed)
        return self.format(result)
```

**Rollback**: `git checkout -- code_audit\api.py`
**Test**: `pytest -xvs -k compare_debt`

---

## Plan 25: God Function

**Location**: `code_audit\api.py:340`
**Severity**: MEDIUM
**Time**: ~11 minutes

### Steps

#### Step 1: ANALYZE

Read governance_audit and mark logical blocks with comments

Source: `code_audit\api.py`

```python
# Add comments like:
# --- BLOCK 1: Input validation ---
# --- BLOCK 2: Data transformation ---
# --- BLOCK 3: Business logic ---
# --- BLOCK 4: Output formatting ---
```

#### Step 2: EXTRACT

Extract the first logical block to a helper function

Source: `code_audit\api.py`

```python
def _governance_audit_validate_input(args):
    '''Extracted from governance_audit: input validation'''
    # Paste block 1 code here
    # Return validated data

def governance_audit(original_args):
    # Replace block 1 with:
    validated = _governance_audit_validate_input(original_args)
    # ... rest of function
```

#### Step 3: TEST

Run tests to verify first extraction


```python
pytest -x
```

#### Step 4: REPEAT

Repeat extraction for each remaining block


```python
# Pattern for each block:
# 1. Create helper: _funcname_blockname(data) -> result
# 2. Move block code to helper
# 3. In main function, call helper
# 4. Test after each extraction

# Final function should look like:
def {func_name}(args):
    validated = _validate_input(args)
    transformed = _transform_data(validated)
    result = _apply_business_logic(transformed)
    return _format_output(result)
```

#### Step 5: OPTIONAL

If >5 helper functions, consider making a class


```python
class GovernanceAuditProcessor:
    def __init__(self, config):
        self.config = config

    def validate(self, data): ...
    def transform(self, data): ...
    def process(self, data): ...
    def format(self, result): ...

    def run(self, data):
        '''Main entry point (replaces original function)'''
        validated = self.validate(data)
        transformed = self.transform(validated)
        result = self.process(transformed)
        return self.format(result)
```

**Rollback**: `git checkout -- code_audit\api.py`
**Test**: `pytest -xvs -k governance_audit`

---

## Plan 26: God Function

**Location**: `code_audit\contracts\safety_fence.py:154`
**Severity**: MEDIUM
**Time**: ~12 minutes

### Steps

#### Step 1: ANALYZE

Read _check_safety_decorators and mark logical blocks with comments

Source: `code_audit\contracts\safety_fence.py`

```python
# Add comments like:
# --- BLOCK 1: Input validation ---
# --- BLOCK 2: Data transformation ---
# --- BLOCK 3: Business logic ---
# --- BLOCK 4: Output formatting ---
```

#### Step 2: EXTRACT

Extract the first logical block to a helper function

Source: `code_audit\contracts\safety_fence.py`

```python
def __check_safety_decorators_validate_input(args):
    '''Extracted from _check_safety_decorators: input validation'''
    # Paste block 1 code here
    # Return validated data

def _check_safety_decorators(original_args):
    # Replace block 1 with:
    validated = __check_safety_decorators_validate_input(original_args)
    # ... rest of function
```

#### Step 3: TEST

Run tests to verify first extraction


```python
pytest -x
```

#### Step 4: REPEAT

Repeat extraction for each remaining block


```python
# Pattern for each block:
# 1. Create helper: _funcname_blockname(data) -> result
# 2. Move block code to helper
# 3. In main function, call helper
# 4. Test after each extraction

# Final function should look like:
def {func_name}(args):
    validated = _validate_input(args)
    transformed = _transform_data(validated)
    result = _apply_business_logic(transformed)
    return _format_output(result)
```

#### Step 5: OPTIONAL

If >5 helper functions, consider making a class


```python
class CheckSafetyDecoratorsProcessor:
    def __init__(self, config):
        self.config = config

    def validate(self, data): ...
    def transform(self, data): ...
    def process(self, data): ...
    def format(self, result): ...

    def run(self, data):
        '''Main entry point (replaces original function)'''
        validated = self.validate(data)
        transformed = self.transform(validated)
        result = self.process(transformed)
        return self.format(result)
```

**Rollback**: `git checkout -- code_audit\contracts\safety_fence.py`
**Test**: `pytest -xvs -k _check_safety_decorators`

---

## Plan 27: God Function

**Location**: `code_audit\core\runner.py:23`
**Severity**: MEDIUM
**Time**: ~19 minutes

### Steps

#### Step 1: ANALYZE

Read run_scan and mark logical blocks with comments

Source: `code_audit\core\runner.py`

```python
# Add comments like:
# --- BLOCK 1: Input validation ---
# --- BLOCK 2: Data transformation ---
# --- BLOCK 3: Business logic ---
# --- BLOCK 4: Output formatting ---
```

#### Step 2: EXTRACT

Extract the first logical block to a helper function

Source: `code_audit\core\runner.py`

```python
def _run_scan_validate_input(args):
    '''Extracted from run_scan: input validation'''
    # Paste block 1 code here
    # Return validated data

def run_scan(original_args):
    # Replace block 1 with:
    validated = _run_scan_validate_input(original_args)
    # ... rest of function
```

#### Step 3: TEST

Run tests to verify first extraction


```python
pytest -x
```

#### Step 4: REPEAT

Repeat extraction for each remaining block


```python
# Pattern for each block:
# 1. Create helper: _funcname_blockname(data) -> result
# 2. Move block code to helper
# 3. In main function, call helper
# 4. Test after each extraction

# Final function should look like:
def {func_name}(args):
    validated = _validate_input(args)
    transformed = _transform_data(validated)
    result = _apply_business_logic(transformed)
    return _format_output(result)
```

#### Step 5: OPTIONAL

If >5 helper functions, consider making a class


```python
class RunScanProcessor:
    def __init__(self, config):
        self.config = config

    def validate(self, data): ...
    def transform(self, data): ...
    def process(self, data): ...
    def format(self, result): ...

    def run(self, data):
        '''Main entry point (replaces original function)'''
        validated = self.validate(data)
        transformed = self.transform(validated)
        result = self.process(transformed)
        return self.format(result)
```

**Rollback**: `git checkout -- code_audit\core\runner.py`
**Test**: `pytest -xvs -k run_scan`

---

## Plan 28: God Function

**Location**: `code_audit\governance\deprecation.py:90`
**Severity**: HIGH
**Time**: ~22 minutes

### Steps

#### Step 1: ANALYZE

Read run and mark logical blocks with comments

Source: `code_audit\governance\deprecation.py`

```python
# Add comments like:
# --- BLOCK 1: Input validation ---
# --- BLOCK 2: Data transformation ---
# --- BLOCK 3: Business logic ---
# --- BLOCK 4: Output formatting ---
```

#### Step 2: EXTRACT

Extract the first logical block to a helper function

Source: `code_audit\governance\deprecation.py`

```python
def _run_validate_input(args):
    '''Extracted from run: input validation'''
    # Paste block 1 code here
    # Return validated data

def run(original_args):
    # Replace block 1 with:
    validated = _run_validate_input(original_args)
    # ... rest of function
```

#### Step 3: TEST

Run tests to verify first extraction


```python
pytest -x
```

#### Step 4: REPEAT

Repeat extraction for each remaining block


```python
# Pattern for each block:
# 1. Create helper: _funcname_blockname(data) -> result
# 2. Move block code to helper
# 3. In main function, call helper
# 4. Test after each extraction

# Final function should look like:
def {func_name}(args):
    validated = _validate_input(args)
    transformed = _transform_data(validated)
    result = _apply_business_logic(transformed)
    return _format_output(result)
```

#### Step 5: OPTIONAL

If >5 helper functions, consider making a class


```python
class RunProcessor:
    def __init__(self, config):
        self.config = config

    def validate(self, data): ...
    def transform(self, data): ...
    def process(self, data): ...
    def format(self, result): ...

    def run(self, data):
        '''Main entry point (replaces original function)'''
        validated = self.validate(data)
        transformed = self.transform(validated)
        result = self.process(transformed)
        return self.format(result)
```

**Rollback**: `git checkout -- code_audit\governance\deprecation.py`
**Test**: `pytest -xvs -k run`

---

## Plan 29: God Function

**Location**: `code_audit\governance\import_ban.py:54`
**Severity**: MEDIUM
**Time**: ~12 minutes

### Steps

#### Step 1: ANALYZE

Read run and mark logical blocks with comments

Source: `code_audit\governance\import_ban.py`

```python
# Add comments like:
# --- BLOCK 1: Input validation ---
# --- BLOCK 2: Data transformation ---
# --- BLOCK 3: Business logic ---
# --- BLOCK 4: Output formatting ---
```

#### Step 2: EXTRACT

Extract the first logical block to a helper function

Source: `code_audit\governance\import_ban.py`

```python
def _run_validate_input(args):
    '''Extracted from run: input validation'''
    # Paste block 1 code here
    # Return validated data

def run(original_args):
    # Replace block 1 with:
    validated = _run_validate_input(original_args)
    # ... rest of function
```

#### Step 3: TEST

Run tests to verify first extraction


```python
pytest -x
```

#### Step 4: REPEAT

Repeat extraction for each remaining block


```python
# Pattern for each block:
# 1. Create helper: _funcname_blockname(data) -> result
# 2. Move block code to helper
# 3. In main function, call helper
# 4. Test after each extraction

# Final function should look like:
def {func_name}(args):
    validated = _validate_input(args)
    transformed = _transform_data(validated)
    result = _apply_business_logic(transformed)
    return _format_output(result)
```

#### Step 5: OPTIONAL

If >5 helper functions, consider making a class


```python
class RunProcessor:
    def __init__(self, config):
        self.config = config

    def validate(self, data): ...
    def transform(self, data): ...
    def process(self, data): ...
    def format(self, result): ...

    def run(self, data):
        '''Main entry point (replaces original function)'''
        validated = self.validate(data)
        transformed = self.transform(validated)
        result = self.process(transformed)
        return self.format(result)
```

**Rollback**: `git checkout -- code_audit\governance\import_ban.py`
**Test**: `pytest -xvs -k run`

---

## Plan 30: God Function

**Location**: `code_audit\governance\legacy_usage.py:91`
**Severity**: MEDIUM
**Time**: ~13 minutes

### Steps

#### Step 1: ANALYZE

Read run and mark logical blocks with comments

Source: `code_audit\governance\legacy_usage.py`

```python
# Add comments like:
# --- BLOCK 1: Input validation ---
# --- BLOCK 2: Data transformation ---
# --- BLOCK 3: Business logic ---
# --- BLOCK 4: Output formatting ---
```

#### Step 2: EXTRACT

Extract the first logical block to a helper function

Source: `code_audit\governance\legacy_usage.py`

```python
def _run_validate_input(args):
    '''Extracted from run: input validation'''
    # Paste block 1 code here
    # Return validated data

def run(original_args):
    # Replace block 1 with:
    validated = _run_validate_input(original_args)
    # ... rest of function
```

#### Step 3: TEST

Run tests to verify first extraction


```python
pytest -x
```

#### Step 4: REPEAT

Repeat extraction for each remaining block


```python
# Pattern for each block:
# 1. Create helper: _funcname_blockname(data) -> result
# 2. Move block code to helper
# 3. In main function, call helper
# 4. Test after each extraction

# Final function should look like:
def {func_name}(args):
    validated = _validate_input(args)
    transformed = _transform_data(validated)
    result = _apply_business_logic(transformed)
    return _format_output(result)
```

#### Step 5: OPTIONAL

If >5 helper functions, consider making a class


```python
class RunProcessor:
    def __init__(self, config):
        self.config = config

    def validate(self, data): ...
    def transform(self, data): ...
    def process(self, data): ...
    def format(self, result): ...

    def run(self, data):
        '''Main entry point (replaces original function)'''
        validated = self.validate(data)
        transformed = self.transform(validated)
        result = self.process(transformed)
        return self.format(result)
```

**Rollback**: `git checkout -- code_audit\governance\legacy_usage.py`
**Test**: `pytest -xvs -k run`

---

## Plan 31: God Function

**Location**: `code_audit\governance\sdk_boundary.py:102`
**Severity**: MEDIUM
**Time**: ~13 minutes

### Steps

#### Step 1: ANALYZE

Read run and mark logical blocks with comments

Source: `code_audit\governance\sdk_boundary.py`

```python
# Add comments like:
# --- BLOCK 1: Input validation ---
# --- BLOCK 2: Data transformation ---
# --- BLOCK 3: Business logic ---
# --- BLOCK 4: Output formatting ---
```

#### Step 2: EXTRACT

Extract the first logical block to a helper function

Source: `code_audit\governance\sdk_boundary.py`

```python
def _run_validate_input(args):
    '''Extracted from run: input validation'''
    # Paste block 1 code here
    # Return validated data

def run(original_args):
    # Replace block 1 with:
    validated = _run_validate_input(original_args)
    # ... rest of function
```

#### Step 3: TEST

Run tests to verify first extraction


```python
pytest -x
```

#### Step 4: REPEAT

Repeat extraction for each remaining block


```python
# Pattern for each block:
# 1. Create helper: _funcname_blockname(data) -> result
# 2. Move block code to helper
# 3. In main function, call helper
# 4. Test after each extraction

# Final function should look like:
def {func_name}(args):
    validated = _validate_input(args)
    transformed = _transform_data(validated)
    result = _apply_business_logic(transformed)
    return _format_output(result)
```

#### Step 5: OPTIONAL

If >5 helper functions, consider making a class


```python
class RunProcessor:
    def __init__(self, config):
        self.config = config

    def validate(self, data): ...
    def transform(self, data): ...
    def process(self, data): ...
    def format(self, result): ...

    def run(self, data):
        '''Main entry point (replaces original function)'''
        validated = self.validate(data)
        transformed = self.transform(validated)
        result = self.process(transformed)
        return self.format(result)
```

**Rollback**: `git checkout -- code_audit\governance\sdk_boundary.py`
**Test**: `pytest -xvs -k run`

---

## Plan 32: God Function

**Location**: `code_audit\insights\translator.py:115`
**Severity**: MEDIUM
**Time**: ~11 minutes

### Steps

#### Step 1: ANALYZE

Read _signal_from_global_state and mark logical blocks with comments

Source: `code_audit\insights\translator.py`

```python
# Add comments like:
# --- BLOCK 1: Input validation ---
# --- BLOCK 2: Data transformation ---
# --- BLOCK 3: Business logic ---
# --- BLOCK 4: Output formatting ---
```

#### Step 2: EXTRACT

Extract the first logical block to a helper function

Source: `code_audit\insights\translator.py`

```python
def __signal_from_global_state_validate_input(args):
    '''Extracted from _signal_from_global_state: input validation'''
    # Paste block 1 code here
    # Return validated data

def _signal_from_global_state(original_args):
    # Replace block 1 with:
    validated = __signal_from_global_state_validate_input(original_args)
    # ... rest of function
```

#### Step 3: TEST

Run tests to verify first extraction


```python
pytest -x
```

#### Step 4: REPEAT

Repeat extraction for each remaining block


```python
# Pattern for each block:
# 1. Create helper: _funcname_blockname(data) -> result
# 2. Move block code to helper
# 3. In main function, call helper
# 4. Test after each extraction

# Final function should look like:
def {func_name}(args):
    validated = _validate_input(args)
    transformed = _transform_data(validated)
    result = _apply_business_logic(transformed)
    return _format_output(result)
```

#### Step 5: OPTIONAL

If >5 helper functions, consider making a class


```python
class SignalFromGlobalStateProcessor:
    def __init__(self, config):
        self.config = config

    def validate(self, data): ...
    def transform(self, data): ...
    def process(self, data): ...
    def format(self, result): ...

    def run(self, data):
        '''Main entry point (replaces original function)'''
        validated = self.validate(data)
        transformed = self.transform(validated)
        result = self.process(transformed)
        return self.format(result)
```

**Rollback**: `git checkout -- code_audit\insights\translator.py`
**Test**: `pytest -xvs -k _signal_from_global_state`

---

## Plan 33: God Function

**Location**: `code_audit\insights\translator.py:176`
**Severity**: MEDIUM
**Time**: ~11 minutes

### Steps

#### Step 1: ANALYZE

Read _signal_from_dead_code and mark logical blocks with comments

Source: `code_audit\insights\translator.py`

```python
# Add comments like:
# --- BLOCK 1: Input validation ---
# --- BLOCK 2: Data transformation ---
# --- BLOCK 3: Business logic ---
# --- BLOCK 4: Output formatting ---
```

#### Step 2: EXTRACT

Extract the first logical block to a helper function

Source: `code_audit\insights\translator.py`

```python
def __signal_from_dead_code_validate_input(args):
    '''Extracted from _signal_from_dead_code: input validation'''
    # Paste block 1 code here
    # Return validated data

def _signal_from_dead_code(original_args):
    # Replace block 1 with:
    validated = __signal_from_dead_code_validate_input(original_args)
    # ... rest of function
```

#### Step 3: TEST

Run tests to verify first extraction


```python
pytest -x
```

#### Step 4: REPEAT

Repeat extraction for each remaining block


```python
# Pattern for each block:
# 1. Create helper: _funcname_blockname(data) -> result
# 2. Move block code to helper
# 3. In main function, call helper
# 4. Test after each extraction

# Final function should look like:
def {func_name}(args):
    validated = _validate_input(args)
    transformed = _transform_data(validated)
    result = _apply_business_logic(transformed)
    return _format_output(result)
```

#### Step 5: OPTIONAL

If >5 helper functions, consider making a class


```python
class SignalFromDeadCodeProcessor:
    def __init__(self, config):
        self.config = config

    def validate(self, data): ...
    def transform(self, data): ...
    def process(self, data): ...
    def format(self, result): ...

    def run(self, data):
        '''Main entry point (replaces original function)'''
        validated = self.validate(data)
        transformed = self.transform(validated)
        result = self.process(transformed)
        return self.format(result)
```

**Rollback**: `git checkout -- code_audit\insights\translator.py`
**Test**: `pytest -xvs -k _signal_from_dead_code`

---

## Plan 34: God Function

**Location**: `code_audit\insights\translator.py:236`
**Severity**: MEDIUM
**Time**: ~14 minutes

### Steps

#### Step 1: ANALYZE

Read _signal_from_security and mark logical blocks with comments

Source: `code_audit\insights\translator.py`

```python
# Add comments like:
# --- BLOCK 1: Input validation ---
# --- BLOCK 2: Data transformation ---
# --- BLOCK 3: Business logic ---
# --- BLOCK 4: Output formatting ---
```

#### Step 2: EXTRACT

Extract the first logical block to a helper function

Source: `code_audit\insights\translator.py`

```python
def __signal_from_security_validate_input(args):
    '''Extracted from _signal_from_security: input validation'''
    # Paste block 1 code here
    # Return validated data

def _signal_from_security(original_args):
    # Replace block 1 with:
    validated = __signal_from_security_validate_input(original_args)
    # ... rest of function
```

#### Step 3: TEST

Run tests to verify first extraction


```python
pytest -x
```

#### Step 4: REPEAT

Repeat extraction for each remaining block


```python
# Pattern for each block:
# 1. Create helper: _funcname_blockname(data) -> result
# 2. Move block code to helper
# 3. In main function, call helper
# 4. Test after each extraction

# Final function should look like:
def {func_name}(args):
    validated = _validate_input(args)
    transformed = _transform_data(validated)
    result = _apply_business_logic(transformed)
    return _format_output(result)
```

#### Step 5: OPTIONAL

If >5 helper functions, consider making a class


```python
class SignalFromSecurityProcessor:
    def __init__(self, config):
        self.config = config

    def validate(self, data): ...
    def transform(self, data): ...
    def process(self, data): ...
    def format(self, result): ...

    def run(self, data):
        '''Main entry point (replaces original function)'''
        validated = self.validate(data)
        transformed = self.transform(validated)
        result = self.process(transformed)
        return self.format(result)
```

**Rollback**: `git checkout -- code_audit\insights\translator.py`
**Test**: `pytest -xvs -k _signal_from_security`

---

## Plan 35: God Function

**Location**: `code_audit\insights\translator.py:310`
**Severity**: MEDIUM
**Time**: ~17 minutes

### Steps

#### Step 1: ANALYZE

Read findings_to_signals and mark logical blocks with comments

Source: `code_audit\insights\translator.py`

```python
# Add comments like:
# --- BLOCK 1: Input validation ---
# --- BLOCK 2: Data transformation ---
# --- BLOCK 3: Business logic ---
# --- BLOCK 4: Output formatting ---
```

#### Step 2: EXTRACT

Extract the first logical block to a helper function

Source: `code_audit\insights\translator.py`

```python
def _findings_to_signals_validate_input(args):
    '''Extracted from findings_to_signals: input validation'''
    # Paste block 1 code here
    # Return validated data

def findings_to_signals(original_args):
    # Replace block 1 with:
    validated = _findings_to_signals_validate_input(original_args)
    # ... rest of function
```

#### Step 3: TEST

Run tests to verify first extraction


```python
pytest -x
```

#### Step 4: REPEAT

Repeat extraction for each remaining block


```python
# Pattern for each block:
# 1. Create helper: _funcname_blockname(data) -> result
# 2. Move block code to helper
# 3. In main function, call helper
# 4. Test after each extraction

# Final function should look like:
def {func_name}(args):
    validated = _validate_input(args)
    transformed = _transform_data(validated)
    result = _apply_business_logic(transformed)
    return _format_output(result)
```

#### Step 5: OPTIONAL

If >5 helper functions, consider making a class


```python
class FindingsToSignalsProcessor:
    def __init__(self, config):
        self.config = config

    def validate(self, data): ...
    def transform(self, data): ...
    def process(self, data): ...
    def format(self, result): ...

    def run(self, data):
        '''Main entry point (replaces original function)'''
        validated = self.validate(data)
        transformed = self.transform(validated)
        result = self.process(transformed)
        return self.format(result)
```

**Rollback**: `git checkout -- code_audit\insights\translator.py`
**Test**: `pytest -xvs -k findings_to_signals`

---

## Plan 36: God Function

**Location**: `code_audit\inventory\feature_hunt.py:95`
**Severity**: MEDIUM
**Time**: ~10 minutes

### Steps

#### Step 1: ANALYZE

Read run and mark logical blocks with comments

Source: `code_audit\inventory\feature_hunt.py`

```python
# Add comments like:
# --- BLOCK 1: Input validation ---
# --- BLOCK 2: Data transformation ---
# --- BLOCK 3: Business logic ---
# --- BLOCK 4: Output formatting ---
```

#### Step 2: EXTRACT

Extract the first logical block to a helper function

Source: `code_audit\inventory\feature_hunt.py`

```python
def _run_validate_input(args):
    '''Extracted from run: input validation'''
    # Paste block 1 code here
    # Return validated data

def run(original_args):
    # Replace block 1 with:
    validated = _run_validate_input(original_args)
    # ... rest of function
```

#### Step 3: TEST

Run tests to verify first extraction


```python
pytest -x
```

#### Step 4: REPEAT

Repeat extraction for each remaining block


```python
# Pattern for each block:
# 1. Create helper: _funcname_blockname(data) -> result
# 2. Move block code to helper
# 3. In main function, call helper
# 4. Test after each extraction

# Final function should look like:
def {func_name}(args):
    validated = _validate_input(args)
    transformed = _transform_data(validated)
    result = _apply_business_logic(transformed)
    return _format_output(result)
```

#### Step 5: OPTIONAL

If >5 helper functions, consider making a class


```python
class RunProcessor:
    def __init__(self, config):
        self.config = config

    def validate(self, data): ...
    def transform(self, data): ...
    def process(self, data): ...
    def format(self, result): ...

    def run(self, data):
        '''Main entry point (replaces original function)'''
        validated = self.validate(data)
        transformed = self.transform(validated)
        result = self.process(transformed)
        return self.format(result)
```

**Rollback**: `git checkout -- code_audit\inventory\feature_hunt.py`
**Test**: `pytest -xvs -k run`

---

## Plan 37: God Function

**Location**: `code_audit\ml\bug_predictor.py:84`
**Severity**: MEDIUM
**Time**: ~10 minutes

### Steps

#### Step 1: ANALYZE

Read predict_file and mark logical blocks with comments

Source: `code_audit\ml\bug_predictor.py`

```python
# Add comments like:
# --- BLOCK 1: Input validation ---
# --- BLOCK 2: Data transformation ---
# --- BLOCK 3: Business logic ---
# --- BLOCK 4: Output formatting ---
```

#### Step 2: EXTRACT

Extract the first logical block to a helper function

Source: `code_audit\ml\bug_predictor.py`

```python
def _predict_file_validate_input(args):
    '''Extracted from predict_file: input validation'''
    # Paste block 1 code here
    # Return validated data

def predict_file(original_args):
    # Replace block 1 with:
    validated = _predict_file_validate_input(original_args)
    # ... rest of function
```

#### Step 3: TEST

Run tests to verify first extraction


```python
pytest -x
```

#### Step 4: REPEAT

Repeat extraction for each remaining block


```python
# Pattern for each block:
# 1. Create helper: _funcname_blockname(data) -> result
# 2. Move block code to helper
# 3. In main function, call helper
# 4. Test after each extraction

# Final function should look like:
def {func_name}(args):
    validated = _validate_input(args)
    transformed = _transform_data(validated)
    result = _apply_business_logic(transformed)
    return _format_output(result)
```

#### Step 5: OPTIONAL

If >5 helper functions, consider making a class


```python
class PredictFileProcessor:
    def __init__(self, config):
        self.config = config

    def validate(self, data): ...
    def transform(self, data): ...
    def process(self, data): ...
    def format(self, result): ...

    def run(self, data):
        '''Main entry point (replaces original function)'''
        validated = self.validate(data)
        transformed = self.transform(validated)
        result = self.process(transformed)
        return self.format(result)
```

**Rollback**: `git checkout -- code_audit\ml\bug_predictor.py`
**Test**: `pytest -xvs -k predict_file`

---

## Plan 38: God Function

**Location**: `code_audit\ml\code_clustering.py:196`
**Severity**: MEDIUM
**Time**: ~10 minutes

### Steps

#### Step 1: ANALYZE

Read cluster_from_features and mark logical blocks with comments

Source: `code_audit\ml\code_clustering.py`

```python
# Add comments like:
# --- BLOCK 1: Input validation ---
# --- BLOCK 2: Data transformation ---
# --- BLOCK 3: Business logic ---
# --- BLOCK 4: Output formatting ---
```

#### Step 2: EXTRACT

Extract the first logical block to a helper function

Source: `code_audit\ml\code_clustering.py`

```python
def _cluster_from_features_validate_input(args):
    '''Extracted from cluster_from_features: input validation'''
    # Paste block 1 code here
    # Return validated data

def cluster_from_features(original_args):
    # Replace block 1 with:
    validated = _cluster_from_features_validate_input(original_args)
    # ... rest of function
```

#### Step 3: TEST

Run tests to verify first extraction


```python
pytest -x
```

#### Step 4: REPEAT

Repeat extraction for each remaining block


```python
# Pattern for each block:
# 1. Create helper: _funcname_blockname(data) -> result
# 2. Move block code to helper
# 3. In main function, call helper
# 4. Test after each extraction

# Final function should look like:
def {func_name}(args):
    validated = _validate_input(args)
    transformed = _transform_data(validated)
    result = _apply_business_logic(transformed)
    return _format_output(result)
```

#### Step 5: OPTIONAL

If >5 helper functions, consider making a class


```python
class ClusterFromFeaturesProcessor:
    def __init__(self, config):
        self.config = config

    def validate(self, data): ...
    def transform(self, data): ...
    def process(self, data): ...
    def format(self, result): ...

    def run(self, data):
        '''Main entry point (replaces original function)'''
        validated = self.validate(data)
        transformed = self.transform(validated)
        result = self.process(transformed)
        return self.format(result)
```

**Rollback**: `git checkout -- code_audit\ml\code_clustering.py`
**Test**: `pytest -xvs -k cluster_from_features`

---

## Plan 39: God Function

**Location**: `code_audit\ml\feature_extraction.py:142`
**Severity**: MEDIUM
**Time**: ~18 minutes

### Steps

#### Step 1: ANALYZE

Read extract_file_features and mark logical blocks with comments

Source: `code_audit\ml\feature_extraction.py`

```python
# Add comments like:
# --- BLOCK 1: Input validation ---
# --- BLOCK 2: Data transformation ---
# --- BLOCK 3: Business logic ---
# --- BLOCK 4: Output formatting ---
```

#### Step 2: EXTRACT

Extract the first logical block to a helper function

Source: `code_audit\ml\feature_extraction.py`

```python
def _extract_file_features_validate_input(args):
    '''Extracted from extract_file_features: input validation'''
    # Paste block 1 code here
    # Return validated data

def extract_file_features(original_args):
    # Replace block 1 with:
    validated = _extract_file_features_validate_input(original_args)
    # ... rest of function
```

#### Step 3: TEST

Run tests to verify first extraction


```python
pytest -x
```

#### Step 4: REPEAT

Repeat extraction for each remaining block


```python
# Pattern for each block:
# 1. Create helper: _funcname_blockname(data) -> result
# 2. Move block code to helper
# 3. In main function, call helper
# 4. Test after each extraction

# Final function should look like:
def {func_name}(args):
    validated = _validate_input(args)
    transformed = _transform_data(validated)
    result = _apply_business_logic(transformed)
    return _format_output(result)
```

#### Step 5: OPTIONAL

If >5 helper functions, consider making a class


```python
class ExtractFileFeaturesProcessor:
    def __init__(self, config):
        self.config = config

    def validate(self, data): ...
    def transform(self, data): ...
    def process(self, data): ...
    def format(self, result): ...

    def run(self, data):
        '''Main entry point (replaces original function)'''
        validated = self.validate(data)
        transformed = self.transform(validated)
        result = self.process(transformed)
        return self.format(result)
```

**Rollback**: `git checkout -- code_audit\ml\feature_extraction.py`
**Test**: `pytest -xvs -k extract_file_features`

---

## Plan 40: God Function

**Location**: `code_audit\reports\dashboard.py:42`
**Severity**: HIGH
**Time**: ~23 minutes

### Steps

#### Step 1: ANALYZE

Read render_dashboard and mark logical blocks with comments

Source: `code_audit\reports\dashboard.py`

```python
# Add comments like:
# --- BLOCK 1: Input validation ---
# --- BLOCK 2: Data transformation ---
# --- BLOCK 3: Business logic ---
# --- BLOCK 4: Output formatting ---
```

#### Step 2: EXTRACT

Extract the first logical block to a helper function

Source: `code_audit\reports\dashboard.py`

```python
def _render_dashboard_validate_input(args):
    '''Extracted from render_dashboard: input validation'''
    # Paste block 1 code here
    # Return validated data

def render_dashboard(original_args):
    # Replace block 1 with:
    validated = _render_dashboard_validate_input(original_args)
    # ... rest of function
```

#### Step 3: TEST

Run tests to verify first extraction


```python
pytest -x
```

#### Step 4: REPEAT

Repeat extraction for each remaining block


```python
# Pattern for each block:
# 1. Create helper: _funcname_blockname(data) -> result
# 2. Move block code to helper
# 3. In main function, call helper
# 4. Test after each extraction

# Final function should look like:
def {func_name}(args):
    validated = _validate_input(args)
    transformed = _transform_data(validated)
    result = _apply_business_logic(transformed)
    return _format_output(result)
```

#### Step 5: OPTIONAL

If >5 helper functions, consider making a class


```python
class RenderDashboardProcessor:
    def __init__(self, config):
        self.config = config

    def validate(self, data): ...
    def transform(self, data): ...
    def process(self, data): ...
    def format(self, result): ...

    def run(self, data):
        '''Main entry point (replaces original function)'''
        validated = self.validate(data)
        transformed = self.transform(validated)
        result = self.process(transformed)
        return self.format(result)
```

**Rollback**: `git checkout -- code_audit\reports\dashboard.py`
**Test**: `pytest -xvs -k render_dashboard`

---

## Plan 41: God Function

**Location**: `code_audit\reports\debt_report.py:80`
**Severity**: HIGH
**Time**: ~27 minutes

### Steps

#### Step 1: ANALYZE

Read render_markdown and mark logical blocks with comments

Source: `code_audit\reports\debt_report.py`

```python
# Add comments like:
# --- BLOCK 1: Input validation ---
# --- BLOCK 2: Data transformation ---
# --- BLOCK 3: Business logic ---
# --- BLOCK 4: Output formatting ---
```

#### Step 2: EXTRACT

Extract the first logical block to a helper function

Source: `code_audit\reports\debt_report.py`

```python
def _render_markdown_validate_input(args):
    '''Extracted from render_markdown: input validation'''
    # Paste block 1 code here
    # Return validated data

def render_markdown(original_args):
    # Replace block 1 with:
    validated = _render_markdown_validate_input(original_args)
    # ... rest of function
```

#### Step 3: TEST

Run tests to verify first extraction


```python
pytest -x
```

#### Step 4: REPEAT

Repeat extraction for each remaining block


```python
# Pattern for each block:
# 1. Create helper: _funcname_blockname(data) -> result
# 2. Move block code to helper
# 3. In main function, call helper
# 4. Test after each extraction

# Final function should look like:
def {func_name}(args):
    validated = _validate_input(args)
    transformed = _transform_data(validated)
    result = _apply_business_logic(transformed)
    return _format_output(result)
```

#### Step 5: OPTIONAL

If >5 helper functions, consider making a class


```python
class RenderMarkdownProcessor:
    def __init__(self, config):
        self.config = config

    def validate(self, data): ...
    def transform(self, data): ...
    def process(self, data): ...
    def format(self, result): ...

    def run(self, data):
        '''Main entry point (replaces original function)'''
        validated = self.validate(data)
        transformed = self.transform(validated)
        result = self.process(transformed)
        return self.format(result)
```

**Rollback**: `git checkout -- code_audit\reports\debt_report.py`
**Test**: `pytest -xvs -k render_markdown`

---

## Plan 42: God Function

**Location**: `code_audit\reports\exporters.py:49`
**Severity**: MEDIUM
**Time**: ~10 minutes

### Steps

#### Step 1: ANALYZE

Read export_markdown and mark logical blocks with comments

Source: `code_audit\reports\exporters.py`

```python
# Add comments like:
# --- BLOCK 1: Input validation ---
# --- BLOCK 2: Data transformation ---
# --- BLOCK 3: Business logic ---
# --- BLOCK 4: Output formatting ---
```

#### Step 2: EXTRACT

Extract the first logical block to a helper function

Source: `code_audit\reports\exporters.py`

```python
def _export_markdown_validate_input(args):
    '''Extracted from export_markdown: input validation'''
    # Paste block 1 code here
    # Return validated data

def export_markdown(original_args):
    # Replace block 1 with:
    validated = _export_markdown_validate_input(original_args)
    # ... rest of function
```

#### Step 3: TEST

Run tests to verify first extraction


```python
pytest -x
```

#### Step 4: REPEAT

Repeat extraction for each remaining block


```python
# Pattern for each block:
# 1. Create helper: _funcname_blockname(data) -> result
# 2. Move block code to helper
# 3. In main function, call helper
# 4. Test after each extraction

# Final function should look like:
def {func_name}(args):
    validated = _validate_input(args)
    transformed = _transform_data(validated)
    result = _apply_business_logic(transformed)
    return _format_output(result)
```

#### Step 5: OPTIONAL

If >5 helper functions, consider making a class


```python
class ExportMarkdownProcessor:
    def __init__(self, config):
        self.config = config

    def validate(self, data): ...
    def transform(self, data): ...
    def process(self, data): ...
    def format(self, result): ...

    def run(self, data):
        '''Main entry point (replaces original function)'''
        validated = self.validate(data)
        transformed = self.transform(validated)
        result = self.process(transformed)
        return self.format(result)
```

**Rollback**: `git checkout -- code_audit\reports\exporters.py`
**Test**: `pytest -xvs -k export_markdown`

---

## Plan 43: God Function

**Location**: `code_audit\reports\exporters.py:139`
**Severity**: MEDIUM
**Time**: ~12 minutes

### Steps

#### Step 1: ANALYZE

Read export_html and mark logical blocks with comments

Source: `code_audit\reports\exporters.py`

```python
# Add comments like:
# --- BLOCK 1: Input validation ---
# --- BLOCK 2: Data transformation ---
# --- BLOCK 3: Business logic ---
# --- BLOCK 4: Output formatting ---
```

#### Step 2: EXTRACT

Extract the first logical block to a helper function

Source: `code_audit\reports\exporters.py`

```python
def _export_html_validate_input(args):
    '''Extracted from export_html: input validation'''
    # Paste block 1 code here
    # Return validated data

def export_html(original_args):
    # Replace block 1 with:
    validated = _export_html_validate_input(original_args)
    # ... rest of function
```

#### Step 3: TEST

Run tests to verify first extraction


```python
pytest -x
```

#### Step 4: REPEAT

Repeat extraction for each remaining block


```python
# Pattern for each block:
# 1. Create helper: _funcname_blockname(data) -> result
# 2. Move block code to helper
# 3. In main function, call helper
# 4. Test after each extraction

# Final function should look like:
def {func_name}(args):
    validated = _validate_input(args)
    transformed = _transform_data(validated)
    result = _apply_business_logic(transformed)
    return _format_output(result)
```

#### Step 5: OPTIONAL

If >5 helper functions, consider making a class


```python
class ExportHtmlProcessor:
    def __init__(self, config):
        self.config = config

    def validate(self, data): ...
    def transform(self, data): ...
    def process(self, data): ...
    def format(self, result): ...

    def run(self, data):
        '''Main entry point (replaces original function)'''
        validated = self.validate(data)
        transformed = self.transform(validated)
        result = self.process(transformed)
        return self.format(result)
```

**Rollback**: `git checkout -- code_audit\reports\exporters.py`
**Test**: `pytest -xvs -k export_html`

---

## Plan 44: God Function

**Location**: `code_audit\reports\trend_analysis.py:135`
**Severity**: MEDIUM
**Time**: ~11 minutes

### Steps

#### Step 1: ANALYZE

Read render_trend_markdown and mark logical blocks with comments

Source: `code_audit\reports\trend_analysis.py`

```python
# Add comments like:
# --- BLOCK 1: Input validation ---
# --- BLOCK 2: Data transformation ---
# --- BLOCK 3: Business logic ---
# --- BLOCK 4: Output formatting ---
```

#### Step 2: EXTRACT

Extract the first logical block to a helper function

Source: `code_audit\reports\trend_analysis.py`

```python
def _render_trend_markdown_validate_input(args):
    '''Extracted from render_trend_markdown: input validation'''
    # Paste block 1 code here
    # Return validated data

def render_trend_markdown(original_args):
    # Replace block 1 with:
    validated = _render_trend_markdown_validate_input(original_args)
    # ... rest of function
```

#### Step 3: TEST

Run tests to verify first extraction


```python
pytest -x
```

#### Step 4: REPEAT

Repeat extraction for each remaining block


```python
# Pattern for each block:
# 1. Create helper: _funcname_blockname(data) -> result
# 2. Move block code to helper
# 3. In main function, call helper
# 4. Test after each extraction

# Final function should look like:
def {func_name}(args):
    validated = _validate_input(args)
    transformed = _transform_data(validated)
    result = _apply_business_logic(transformed)
    return _format_output(result)
```

#### Step 5: OPTIONAL

If >5 helper functions, consider making a class


```python
class RenderTrendMarkdownProcessor:
    def __init__(self, config):
        self.config = config

    def validate(self, data): ...
    def transform(self, data): ...
    def process(self, data): ...
    def format(self, result): ...

    def run(self, data):
        '''Main entry point (replaces original function)'''
        validated = self.validate(data)
        transformed = self.transform(validated)
        result = self.process(transformed)
        return self.format(result)
```

**Rollback**: `git checkout -- code_audit\reports\trend_analysis.py`
**Test**: `pytest -xvs -k render_trend_markdown`

---

## Plan 45: God Function

**Location**: `code_audit\run_result.py:87`
**Severity**: MEDIUM
**Time**: ~13 minutes

### Steps

#### Step 1: ANALYZE

Read _compute_confidence_and_vibe and mark logical blocks with comments

Source: `code_audit\run_result.py`

```python
# Add comments like:
# --- BLOCK 1: Input validation ---
# --- BLOCK 2: Data transformation ---
# --- BLOCK 3: Business logic ---
# --- BLOCK 4: Output formatting ---
```

#### Step 2: EXTRACT

Extract the first logical block to a helper function

Source: `code_audit\run_result.py`

```python
def __compute_confidence_and_vibe_validate_input(args):
    '''Extracted from _compute_confidence_and_vibe: input validation'''
    # Paste block 1 code here
    # Return validated data

def _compute_confidence_and_vibe(original_args):
    # Replace block 1 with:
    validated = __compute_confidence_and_vibe_validate_input(original_args)
    # ... rest of function
```

#### Step 3: TEST

Run tests to verify first extraction


```python
pytest -x
```

#### Step 4: REPEAT

Repeat extraction for each remaining block


```python
# Pattern for each block:
# 1. Create helper: _funcname_blockname(data) -> result
# 2. Move block code to helper
# 3. In main function, call helper
# 4. Test after each extraction

# Final function should look like:
def {func_name}(args):
    validated = _validate_input(args)
    transformed = _transform_data(validated)
    result = _apply_business_logic(transformed)
    return _format_output(result)
```

#### Step 5: OPTIONAL

If >5 helper functions, consider making a class


```python
class ComputeConfidenceAndVibeProcessor:
    def __init__(self, config):
        self.config = config

    def validate(self, data): ...
    def transform(self, data): ...
    def process(self, data): ...
    def format(self, result): ...

    def run(self, data):
        '''Main entry point (replaces original function)'''
        validated = self.validate(data)
        transformed = self.transform(validated)
        result = self.process(transformed)
        return self.format(result)
```

**Rollback**: `git checkout -- code_audit\run_result.py`
**Test**: `pytest -xvs -k _compute_confidence_and_vibe`

---

## Plan 46: God Function

**Location**: `code_audit\run_result.py:158`
**Severity**: HIGH
**Time**: ~30 minutes

### Steps

#### Step 1: ANALYZE

Read _build_signals_snapshot and mark logical blocks with comments

Source: `code_audit\run_result.py`

```python
# Add comments like:
# --- BLOCK 1: Input validation ---
# --- BLOCK 2: Data transformation ---
# --- BLOCK 3: Business logic ---
# --- BLOCK 4: Output formatting ---
```

#### Step 2: EXTRACT

Extract the first logical block to a helper function

Source: `code_audit\run_result.py`

```python
def __build_signals_snapshot_validate_input(args):
    '''Extracted from _build_signals_snapshot: input validation'''
    # Paste block 1 code here
    # Return validated data

def _build_signals_snapshot(original_args):
    # Replace block 1 with:
    validated = __build_signals_snapshot_validate_input(original_args)
    # ... rest of function
```

#### Step 3: TEST

Run tests to verify first extraction


```python
pytest -x
```

#### Step 4: REPEAT

Repeat extraction for each remaining block


```python
# Pattern for each block:
# 1. Create helper: _funcname_blockname(data) -> result
# 2. Move block code to helper
# 3. In main function, call helper
# 4. Test after each extraction

# Final function should look like:
def {func_name}(args):
    validated = _validate_input(args)
    transformed = _transform_data(validated)
    result = _apply_business_logic(transformed)
    return _format_output(result)
```

#### Step 5: OPTIONAL

If >5 helper functions, consider making a class


```python
class BuildSignalsSnapshotProcessor:
    def __init__(self, config):
        self.config = config

    def validate(self, data): ...
    def transform(self, data): ...
    def process(self, data): ...
    def format(self, result): ...

    def run(self, data):
        '''Main entry point (replaces original function)'''
        validated = self.validate(data)
        transformed = self.transform(validated)
        result = self.process(transformed)
        return self.format(result)
```

**Rollback**: `git checkout -- code_audit\run_result.py`
**Test**: `pytest -xvs -k _build_signals_snapshot`

---

## Plan 47: God Function

**Location**: `code_audit\run_result.py:314`
**Severity**: MEDIUM
**Time**: ~15 minutes

### Steps

#### Step 1: ANALYZE

Read build_run_result and mark logical blocks with comments

Source: `code_audit\run_result.py`

```python
# Add comments like:
# --- BLOCK 1: Input validation ---
# --- BLOCK 2: Data transformation ---
# --- BLOCK 3: Business logic ---
# --- BLOCK 4: Output formatting ---
```

#### Step 2: EXTRACT

Extract the first logical block to a helper function

Source: `code_audit\run_result.py`

```python
def _build_run_result_validate_input(args):
    '''Extracted from build_run_result: input validation'''
    # Paste block 1 code here
    # Return validated data

def build_run_result(original_args):
    # Replace block 1 with:
    validated = _build_run_result_validate_input(original_args)
    # ... rest of function
```

#### Step 3: TEST

Run tests to verify first extraction


```python
pytest -x
```

#### Step 4: REPEAT

Repeat extraction for each remaining block


```python
# Pattern for each block:
# 1. Create helper: _funcname_blockname(data) -> result
# 2. Move block code to helper
# 3. In main function, call helper
# 4. Test after each extraction

# Final function should look like:
def {func_name}(args):
    validated = _validate_input(args)
    transformed = _transform_data(validated)
    result = _apply_business_logic(transformed)
    return _format_output(result)
```

#### Step 5: OPTIONAL

If >5 helper functions, consider making a class


```python
class BuildRunResultProcessor:
    def __init__(self, config):
        self.config = config

    def validate(self, data): ...
    def transform(self, data): ...
    def process(self, data): ...
    def format(self, result): ...

    def run(self, data):
        '''Main entry point (replaces original function)'''
        validated = self.validate(data)
        transformed = self.transform(validated)
        result = self.process(transformed)
        return self.format(result)
```

**Rollback**: `git checkout -- code_audit\run_result.py`
**Test**: `pytest -xvs -k build_run_result`

---

## Plan 48: God Function

**Location**: `code_audit\strangler\debt_detector.py:191`
**Severity**: MEDIUM
**Time**: ~13 minutes

### Steps

#### Step 1: ANALYZE

Read _check_classes and mark logical blocks with comments

Source: `code_audit\strangler\debt_detector.py`

```python
# Add comments like:
# --- BLOCK 1: Input validation ---
# --- BLOCK 2: Data transformation ---
# --- BLOCK 3: Business logic ---
# --- BLOCK 4: Output formatting ---
```

#### Step 2: EXTRACT

Extract the first logical block to a helper function

Source: `code_audit\strangler\debt_detector.py`

```python
def __check_classes_validate_input(args):
    '''Extracted from _check_classes: input validation'''
    # Paste block 1 code here
    # Return validated data

def _check_classes(original_args):
    # Replace block 1 with:
    validated = __check_classes_validate_input(original_args)
    # ... rest of function
```

#### Step 3: TEST

Run tests to verify first extraction


```python
pytest -x
```

#### Step 4: REPEAT

Repeat extraction for each remaining block


```python
# Pattern for each block:
# 1. Create helper: _funcname_blockname(data) -> result
# 2. Move block code to helper
# 3. In main function, call helper
# 4. Test after each extraction

# Final function should look like:
def {func_name}(args):
    validated = _validate_input(args)
    transformed = _transform_data(validated)
    result = _apply_business_logic(transformed)
    return _format_output(result)
```

#### Step 5: OPTIONAL

If >5 helper functions, consider making a class


```python
class CheckClassesProcessor:
    def __init__(self, config):
        self.config = config

    def validate(self, data): ...
    def transform(self, data): ...
    def process(self, data): ...
    def format(self, result): ...

    def run(self, data):
        '''Main entry point (replaces original function)'''
        validated = self.validate(data)
        transformed = self.transform(validated)
        result = self.process(transformed)
        return self.format(result)
```

**Rollback**: `git checkout -- code_audit\strangler\debt_detector.py`
**Test**: `pytest -xvs -k _check_classes`

---

## Plan 49: God Function

**Location**: `code_audit\strangler\debt_detector.py:259`
**Severity**: HIGH
**Time**: ~30 minutes

### Steps

#### Step 1: ANALYZE

Read _check_functions and mark logical blocks with comments

Source: `code_audit\strangler\debt_detector.py`

```python
# Add comments like:
# --- BLOCK 1: Input validation ---
# --- BLOCK 2: Data transformation ---
# --- BLOCK 3: Business logic ---
# --- BLOCK 4: Output formatting ---
```

#### Step 2: EXTRACT

Extract the first logical block to a helper function

Source: `code_audit\strangler\debt_detector.py`

```python
def __check_functions_validate_input(args):
    '''Extracted from _check_functions: input validation'''
    # Paste block 1 code here
    # Return validated data

def _check_functions(original_args):
    # Replace block 1 with:
    validated = __check_functions_validate_input(original_args)
    # ... rest of function
```

#### Step 3: TEST

Run tests to verify first extraction


```python
pytest -x
```

#### Step 4: REPEAT

Repeat extraction for each remaining block


```python
# Pattern for each block:
# 1. Create helper: _funcname_blockname(data) -> result
# 2. Move block code to helper
# 3. In main function, call helper
# 4. Test after each extraction

# Final function should look like:
def {func_name}(args):
    validated = _validate_input(args)
    transformed = _transform_data(validated)
    result = _apply_business_logic(transformed)
    return _format_output(result)
```

#### Step 5: OPTIONAL

If >5 helper functions, consider making a class


```python
class CheckFunctionsProcessor:
    def __init__(self, config):
        self.config = config

    def validate(self, data): ...
    def transform(self, data): ...
    def process(self, data): ...
    def format(self, result): ...

    def run(self, data):
        '''Main entry point (replaces original function)'''
        validated = self.validate(data)
        transformed = self.transform(validated)
        result = self.process(transformed)
        return self.format(result)
```

**Rollback**: `git checkout -- code_audit\strangler\debt_detector.py`
**Test**: `pytest -xvs -k _check_functions`

---

## Plan 50: God Function

**Location**: `code_audit\strangler\plan_generator.py:43`
**Severity**: MEDIUM
**Time**: ~18 minutes

### Steps

#### Step 1: ANALYZE

Read generate_plan and mark logical blocks with comments

Source: `code_audit\strangler\plan_generator.py`

```python
# Add comments like:
# --- BLOCK 1: Input validation ---
# --- BLOCK 2: Data transformation ---
# --- BLOCK 3: Business logic ---
# --- BLOCK 4: Output formatting ---
```

#### Step 2: EXTRACT

Extract the first logical block to a helper function

Source: `code_audit\strangler\plan_generator.py`

```python
def _generate_plan_validate_input(args):
    '''Extracted from generate_plan: input validation'''
    # Paste block 1 code here
    # Return validated data

def generate_plan(original_args):
    # Replace block 1 with:
    validated = _generate_plan_validate_input(original_args)
    # ... rest of function
```

#### Step 3: TEST

Run tests to verify first extraction


```python
pytest -x
```

#### Step 4: REPEAT

Repeat extraction for each remaining block


```python
# Pattern for each block:
# 1. Create helper: _funcname_blockname(data) -> result
# 2. Move block code to helper
# 3. In main function, call helper
# 4. Test after each extraction

# Final function should look like:
def {func_name}(args):
    validated = _validate_input(args)
    transformed = _transform_data(validated)
    result = _apply_business_logic(transformed)
    return _format_output(result)
```

#### Step 5: OPTIONAL

If >5 helper functions, consider making a class


```python
class GeneratePlanProcessor:
    def __init__(self, config):
        self.config = config

    def validate(self, data): ...
    def transform(self, data): ...
    def process(self, data): ...
    def format(self, result): ...

    def run(self, data):
        '''Main entry point (replaces original function)'''
        validated = self.validate(data)
        transformed = self.transform(validated)
        result = self.process(transformed)
        return self.format(result)
```

**Rollback**: `git checkout -- code_audit\strangler\plan_generator.py`
**Test**: `pytest -xvs -k generate_plan`

---

## Plan 51: God Function

**Location**: `code_audit\utils\parse_truth_map.py:54`
**Severity**: MEDIUM
**Time**: ~18 minutes

### Steps

#### Step 1: ANALYZE

Read parse_truth_map and mark logical blocks with comments

Source: `code_audit\utils\parse_truth_map.py`

```python
# Add comments like:
# --- BLOCK 1: Input validation ---
# --- BLOCK 2: Data transformation ---
# --- BLOCK 3: Business logic ---
# --- BLOCK 4: Output formatting ---
```

#### Step 2: EXTRACT

Extract the first logical block to a helper function

Source: `code_audit\utils\parse_truth_map.py`

```python
def _parse_truth_map_validate_input(args):
    '''Extracted from parse_truth_map: input validation'''
    # Paste block 1 code here
    # Return validated data

def parse_truth_map(original_args):
    # Replace block 1 with:
    validated = _parse_truth_map_validate_input(original_args)
    # ... rest of function
```

#### Step 3: TEST

Run tests to verify first extraction


```python
pytest -x
```

#### Step 4: REPEAT

Repeat extraction for each remaining block


```python
# Pattern for each block:
# 1. Create helper: _funcname_blockname(data) -> result
# 2. Move block code to helper
# 3. In main function, call helper
# 4. Test after each extraction

# Final function should look like:
def {func_name}(args):
    validated = _validate_input(args)
    transformed = _transform_data(validated)
    result = _apply_business_logic(transformed)
    return _format_output(result)
```

#### Step 5: OPTIONAL

If >5 helper functions, consider making a class


```python
class ParseTruthMapProcessor:
    def __init__(self, config):
        self.config = config

    def validate(self, data): ...
    def transform(self, data): ...
    def process(self, data): ...
    def format(self, result): ...

    def run(self, data):
        '''Main entry point (replaces original function)'''
        validated = self.validate(data)
        transformed = self.transform(validated)
        result = self.process(transformed)
        return self.format(result)
```

**Rollback**: `git checkout -- code_audit\utils\parse_truth_map.py`
**Test**: `pytest -xvs -k parse_truth_map`

---

## Plan 52: Large File

**Location**: `code_audit\__main__.py`
**Severity**: HIGH
**Time**: ~70 minutes

### Steps

#### Step 1: CREATE

Convert code_audit\__main__.py to a package (folder)


```python
# Run these commands:
mkdir -p code_audit/__main__
touch code_audit/__main__/__init__.py

# Or use Python:
from pathlib import Path
pkg = Path('code_audit/__main__')
pkg.mkdir(exist_ok=True)
(pkg / '__init__.py').touch()
```

#### Step 2: ANALYZE

Identify logical domains in the file

Source: `code_audit\__main__.py`

```python
# Common patterns to look for:
# - Classes that work together
# - Functions with common prefixes
# - Imports that cluster together
# - Related constants/configs

# Typical splits:
# - models.py: Data classes, schemas
# - services.py: Business logic
# - utils.py: Helper functions
# - constants.py: Config values
```

#### Step 3: MOVE

Move data models to models.py

Source: `code_audit\__main__.py`
Target: `code_audit/__main__/models.py`

```python
# code_audit/__main__/models.py
'''Data models extracted from __main__.py'''

from dataclasses import dataclass
from typing import Optional, List

# Move all @dataclass, TypedDict, NamedTuple here
# Move Pydantic models here
# Move SQLAlchemy models here
```

#### Step 4: MOVE

Move business logic to services.py

Source: `code_audit\__main__.py`
Target: `code_audit/__main__/services.py`

```python
# code_audit/__main__/services.py
'''Business logic extracted from __main__.py'''

from .models import *  # Import your models

# Move classes/functions that:
# - Do complex processing
# - Interact with external services
# - Contain business rules
```

#### Step 5: UPDATE

Re-export public API from __init__.py

Target: `code_audit/__main__/__init__.py`

```python
# code_audit/__main__/__init__.py
'''
  Main   module

Public API re-exported here for backward compatibility.
'''

from .models import (
    Model1,
    Model2,
)

from .services import (
    process_data,
    validate_input,
)

__all__ = [
    'Model1',
    'Model2',
    'process_data',
    'validate_input',
]
```

#### Step 6: DELETE

Delete original code_audit\__main__.py (now replaced by package)

Source: `code_audit\__main__.py`

```python
# Only after tests pass!
rm code_audit\__main__.py

# Or safer:
git rm code_audit\__main__.py
```

**Rollback**: `git checkout -- code_audit/`
**Test**: `pytest -xvs code_audit/`

---

## Plan 53: Large File

**Location**: `code_audit\analyzers\dead_code.py`
**Severity**: MEDIUM
**Time**: ~22 minutes

### Steps

#### Step 1: CREATE

Convert code_audit\analyzers\dead_code.py to a package (folder)


```python
# Run these commands:
mkdir -p code_audit\analyzers/dead_code
touch code_audit\analyzers/dead_code/__init__.py

# Or use Python:
from pathlib import Path
pkg = Path('code_audit\analyzers/dead_code')
pkg.mkdir(exist_ok=True)
(pkg / '__init__.py').touch()
```

#### Step 2: ANALYZE

Identify logical domains in the file

Source: `code_audit\analyzers\dead_code.py`

```python
# Common patterns to look for:
# - Classes that work together
# - Functions with common prefixes
# - Imports that cluster together
# - Related constants/configs

# Typical splits:
# - models.py: Data classes, schemas
# - services.py: Business logic
# - utils.py: Helper functions
# - constants.py: Config values
```

#### Step 3: MOVE

Move data models to models.py

Source: `code_audit\analyzers\dead_code.py`
Target: `code_audit\analyzers/dead_code/models.py`

```python
# code_audit\analyzers/dead_code/models.py
'''Data models extracted from dead_code.py'''

from dataclasses import dataclass
from typing import Optional, List

# Move all @dataclass, TypedDict, NamedTuple here
# Move Pydantic models here
# Move SQLAlchemy models here
```

#### Step 4: MOVE

Move business logic to services.py

Source: `code_audit\analyzers\dead_code.py`
Target: `code_audit\analyzers/dead_code/services.py`

```python
# code_audit\analyzers/dead_code/services.py
'''Business logic extracted from dead_code.py'''

from .models import *  # Import your models

# Move classes/functions that:
# - Do complex processing
# - Interact with external services
# - Contain business rules
```

#### Step 5: UPDATE

Re-export public API from __init__.py

Target: `code_audit\analyzers/dead_code/__init__.py`

```python
# code_audit\analyzers/dead_code/__init__.py
'''
Dead Code module

Public API re-exported here for backward compatibility.
'''

from .models import (
    Model1,
    Model2,
)

from .services import (
    process_data,
    validate_input,
)

__all__ = [
    'Model1',
    'Model2',
    'process_data',
    'validate_input',
]
```

#### Step 6: DELETE

Delete original code_audit\analyzers\dead_code.py (now replaced by package)

Source: `code_audit\analyzers\dead_code.py`

```python
# Only after tests pass!
rm code_audit\analyzers\dead_code.py

# Or safer:
git rm code_audit\analyzers\dead_code.py
```

**Rollback**: `git checkout -- code_audit\analyzers/`
**Test**: `pytest -xvs code_audit\analyzers/`

---

## Plan 54: Large File

**Location**: `code_audit\analyzers\routers.py`
**Severity**: MEDIUM
**Time**: ~20 minutes

### Steps

#### Step 1: CREATE

Convert code_audit\analyzers\routers.py to a package (folder)


```python
# Run these commands:
mkdir -p code_audit\analyzers/routers
touch code_audit\analyzers/routers/__init__.py

# Or use Python:
from pathlib import Path
pkg = Path('code_audit\analyzers/routers')
pkg.mkdir(exist_ok=True)
(pkg / '__init__.py').touch()
```

#### Step 2: ANALYZE

Identify logical domains in the file

Source: `code_audit\analyzers\routers.py`

```python
# Common patterns to look for:
# - Classes that work together
# - Functions with common prefixes
# - Imports that cluster together
# - Related constants/configs

# Typical splits:
# - models.py: Data classes, schemas
# - services.py: Business logic
# - utils.py: Helper functions
# - constants.py: Config values
```

#### Step 3: MOVE

Move data models to models.py

Source: `code_audit\analyzers\routers.py`
Target: `code_audit\analyzers/routers/models.py`

```python
# code_audit\analyzers/routers/models.py
'''Data models extracted from routers.py'''

from dataclasses import dataclass
from typing import Optional, List

# Move all @dataclass, TypedDict, NamedTuple here
# Move Pydantic models here
# Move SQLAlchemy models here
```

#### Step 4: MOVE

Move business logic to services.py

Source: `code_audit\analyzers\routers.py`
Target: `code_audit\analyzers/routers/services.py`

```python
# code_audit\analyzers/routers/services.py
'''Business logic extracted from routers.py'''

from .models import *  # Import your models

# Move classes/functions that:
# - Do complex processing
# - Interact with external services
# - Contain business rules
```

#### Step 5: UPDATE

Re-export public API from __init__.py

Target: `code_audit\analyzers/routers/__init__.py`

```python
# code_audit\analyzers/routers/__init__.py
'''
Routers module

Public API re-exported here for backward compatibility.
'''

from .models import (
    Model1,
    Model2,
)

from .services import (
    process_data,
    validate_input,
)

__all__ = [
    'Model1',
    'Model2',
    'process_data',
    'validate_input',
]
```

#### Step 6: DELETE

Delete original code_audit\analyzers\routers.py (now replaced by package)

Source: `code_audit\analyzers\routers.py`

```python
# Only after tests pass!
rm code_audit\analyzers\routers.py

# Or safer:
git rm code_audit\analyzers\routers.py
```

**Rollback**: `git checkout -- code_audit\analyzers/`
**Test**: `pytest -xvs code_audit\analyzers/`

---

## Plan 55: Large File

**Location**: `code_audit\analyzers\security.py`
**Severity**: MEDIUM
**Time**: ~23 minutes

### Steps

#### Step 1: CREATE

Convert code_audit\analyzers\security.py to a package (folder)


```python
# Run these commands:
mkdir -p code_audit\analyzers/security
touch code_audit\analyzers/security/__init__.py

# Or use Python:
from pathlib import Path
pkg = Path('code_audit\analyzers/security')
pkg.mkdir(exist_ok=True)
(pkg / '__init__.py').touch()
```

#### Step 2: ANALYZE

Identify logical domains in the file

Source: `code_audit\analyzers\security.py`

```python
# Common patterns to look for:
# - Classes that work together
# - Functions with common prefixes
# - Imports that cluster together
# - Related constants/configs

# Typical splits:
# - models.py: Data classes, schemas
# - services.py: Business logic
# - utils.py: Helper functions
# - constants.py: Config values
```

#### Step 3: MOVE

Move data models to models.py

Source: `code_audit\analyzers\security.py`
Target: `code_audit\analyzers/security/models.py`

```python
# code_audit\analyzers/security/models.py
'''Data models extracted from security.py'''

from dataclasses import dataclass
from typing import Optional, List

# Move all @dataclass, TypedDict, NamedTuple here
# Move Pydantic models here
# Move SQLAlchemy models here
```

#### Step 4: MOVE

Move business logic to services.py

Source: `code_audit\analyzers\security.py`
Target: `code_audit\analyzers/security/services.py`

```python
# code_audit\analyzers/security/services.py
'''Business logic extracted from security.py'''

from .models import *  # Import your models

# Move classes/functions that:
# - Do complex processing
# - Interact with external services
# - Contain business rules
```

#### Step 5: UPDATE

Re-export public API from __init__.py

Target: `code_audit\analyzers/security/__init__.py`

```python
# code_audit\analyzers/security/__init__.py
'''
Security module

Public API re-exported here for backward compatibility.
'''

from .models import (
    Model1,
    Model2,
)

from .services import (
    process_data,
    validate_input,
)

__all__ = [
    'Model1',
    'Model2',
    'process_data',
    'validate_input',
]
```

#### Step 6: DELETE

Delete original code_audit\analyzers\security.py (now replaced by package)

Source: `code_audit\analyzers\security.py`

```python
# Only after tests pass!
rm code_audit\analyzers\security.py

# Or safer:
git rm code_audit\analyzers\security.py
```

**Rollback**: `git checkout -- code_audit\analyzers/`
**Test**: `pytest -xvs code_audit\analyzers/`

---

## Plan 56: Large File

**Location**: `code_audit\scaffold.py`
**Severity**: HIGH
**Time**: ~41 minutes

### Steps

#### Step 1: CREATE

Convert code_audit\scaffold.py to a package (folder)


```python
# Run these commands:
mkdir -p code_audit/scaffold
touch code_audit/scaffold/__init__.py

# Or use Python:
from pathlib import Path
pkg = Path('code_audit/scaffold')
pkg.mkdir(exist_ok=True)
(pkg / '__init__.py').touch()
```

#### Step 2: ANALYZE

Identify logical domains in the file

Source: `code_audit\scaffold.py`

```python
# Common patterns to look for:
# - Classes that work together
# - Functions with common prefixes
# - Imports that cluster together
# - Related constants/configs

# Typical splits:
# - models.py: Data classes, schemas
# - services.py: Business logic
# - utils.py: Helper functions
# - constants.py: Config values
```

#### Step 3: MOVE

Move data models to models.py

Source: `code_audit\scaffold.py`
Target: `code_audit/scaffold/models.py`

```python
# code_audit/scaffold/models.py
'''Data models extracted from scaffold.py'''

from dataclasses import dataclass
from typing import Optional, List

# Move all @dataclass, TypedDict, NamedTuple here
# Move Pydantic models here
# Move SQLAlchemy models here
```

#### Step 4: MOVE

Move business logic to services.py

Source: `code_audit\scaffold.py`
Target: `code_audit/scaffold/services.py`

```python
# code_audit/scaffold/services.py
'''Business logic extracted from scaffold.py'''

from .models import *  # Import your models

# Move classes/functions that:
# - Do complex processing
# - Interact with external services
# - Contain business rules
```

#### Step 5: UPDATE

Re-export public API from __init__.py

Target: `code_audit/scaffold/__init__.py`

```python
# code_audit/scaffold/__init__.py
'''
Scaffold module

Public API re-exported here for backward compatibility.
'''

from .models import (
    Model1,
    Model2,
)

from .services import (
    process_data,
    validate_input,
)

__all__ = [
    'Model1',
    'Model2',
    'process_data',
    'validate_input',
]
```

#### Step 6: DELETE

Delete original code_audit\scaffold.py (now replaced by package)

Source: `code_audit\scaffold.py`

```python
# Only after tests pass!
rm code_audit\scaffold.py

# Or safer:
git rm code_audit\scaffold.py
```

**Rollback**: `git checkout -- code_audit/`
**Test**: `pytest -xvs code_audit/`

---

## Plan 57: Deep Nesting

**Location**: `code_audit\__main__.py:1530`
**Severity**: MEDIUM
**Time**: ~25 minutes

### Steps

#### Step 1: REFACTOR

Convert nested conditions to guard clauses

Source: `code_audit\__main__.py`

```python
# BEFORE:
def process(data):
    if data:
        if data.valid:
            if data.ready:
                # actual logic here
                pass

# AFTER:
def process(data):
    if not data:
        return None
    if not data.valid:
        raise ValueError("Invalid data")
    if not data.ready:
        return  # or raise

    # actual logic here - now at top level
```

#### Step 2: EXTRACT

Extract deeply nested blocks to helper functions

Source: `code_audit\__main__.py`

```python
# BEFORE:
def main(data):
    for item in data:
        if item.valid:
            for sub in item.subs:
                if sub.ready:
                    # deep logic
                    pass

# AFTER:
def _process_sub(sub):
    '''Extracted inner logic'''
    if not sub.ready:
        return None
    # logic here

def _process_item(item):
    '''Extracted middle logic'''
    if not item.valid:
        return []
    return [_process_sub(sub) for sub in item.subs]

def main(data):
    results = []
    for item in data:
        results.extend(_process_item(item))
    return results
```

#### Step 3: SIMPLIFY

Replace simple nested loops with comprehensions


```python
# BEFORE:
results = []
for item in items:
    if item.valid:
        results.append(item.value)

# AFTER:
results = [item.value for item in items if item.valid]
```

**Rollback**: `git checkout -- code_audit\__main__.py`
**Test**: `pytest -xvs -k main`

---

## Plan 58: Deep Nesting

**Location**: `code_audit\analyzers\complexity.py:16`
**Severity**: HIGH
**Time**: ~35 minutes

### Steps

#### Step 1: REFACTOR

Convert nested conditions to guard clauses

Source: `code_audit\analyzers\complexity.py`

```python
# BEFORE:
def process(data):
    if data:
        if data.valid:
            if data.ready:
                # actual logic here
                pass

# AFTER:
def process(data):
    if not data:
        return None
    if not data.valid:
        raise ValueError("Invalid data")
    if not data.ready:
        return  # or raise

    # actual logic here - now at top level
```

#### Step 2: EXTRACT

Extract deeply nested blocks to helper functions

Source: `code_audit\analyzers\complexity.py`

```python
# BEFORE:
def _cyclomatic_complexity(data):
    for item in data:
        if item.valid:
            for sub in item.subs:
                if sub.ready:
                    # deep logic
                    pass

# AFTER:
def _process_sub(sub):
    '''Extracted inner logic'''
    if not sub.ready:
        return None
    # logic here

def _process_item(item):
    '''Extracted middle logic'''
    if not item.valid:
        return []
    return [_process_sub(sub) for sub in item.subs]

def _cyclomatic_complexity(data):
    results = []
    for item in data:
        results.extend(_process_item(item))
    return results
```

#### Step 3: SIMPLIFY

Replace simple nested loops with comprehensions


```python
# BEFORE:
results = []
for item in items:
    if item.valid:
        results.append(item.value)

# AFTER:
results = [item.value for item in items if item.valid]
```

**Rollback**: `git checkout -- code_audit\analyzers\complexity.py`
**Test**: `pytest -xvs -k _cyclomatic_complexity`

---

## Plan 59: Deep Nesting

**Location**: `code_audit\analyzers\dead_code.py:387`
**Severity**: HIGH
**Time**: ~35 minutes

### Steps

#### Step 1: REFACTOR

Convert nested conditions to guard clauses

Source: `code_audit\analyzers\dead_code.py`

```python
# BEFORE:
def process(data):
    if data:
        if data.valid:
            if data.ready:
                # actual logic here
                pass

# AFTER:
def process(data):
    if not data:
        return None
    if not data.valid:
        raise ValueError("Invalid data")
    if not data.ready:
        return  # or raise

    # actual logic here - now at top level
```

#### Step 2: EXTRACT

Extract deeply nested blocks to helper functions

Source: `code_audit\analyzers\dead_code.py`

```python
# BEFORE:
def analyze_dead_code(data):
    for item in data:
        if item.valid:
            for sub in item.subs:
                if sub.ready:
                    # deep logic
                    pass

# AFTER:
def _process_sub(sub):
    '''Extracted inner logic'''
    if not sub.ready:
        return None
    # logic here

def _process_item(item):
    '''Extracted middle logic'''
    if not item.valid:
        return []
    return [_process_sub(sub) for sub in item.subs]

def analyze_dead_code(data):
    results = []
    for item in data:
        results.extend(_process_item(item))
    return results
```

#### Step 3: SIMPLIFY

Replace simple nested loops with comprehensions


```python
# BEFORE:
results = []
for item in items:
    if item.valid:
        results.append(item.value)

# AFTER:
results = [item.value for item in items if item.valid]
```

**Rollback**: `git checkout -- code_audit\analyzers\dead_code.py`
**Test**: `pytest -xvs -k analyze_dead_code`

---

## Plan 60: Deep Nesting

**Location**: `code_audit\analyzers\dead_code.py:150`
**Severity**: HIGH
**Time**: ~35 minutes

### Steps

#### Step 1: REFACTOR

Convert nested conditions to guard clauses

Source: `code_audit\analyzers\dead_code.py`

```python
# BEFORE:
def process(data):
    if data:
        if data.valid:
            if data.ready:
                # actual logic here
                pass

# AFTER:
def process(data):
    if not data:
        return None
    if not data.valid:
        raise ValueError("Invalid data")
    if not data.ready:
        return  # or raise

    # actual logic here - now at top level
```

#### Step 2: EXTRACT

Extract deeply nested blocks to helper functions

Source: `code_audit\analyzers\dead_code.py`

```python
# BEFORE:
def _detect_unreachable(data):
    for item in data:
        if item.valid:
            for sub in item.subs:
                if sub.ready:
                    # deep logic
                    pass

# AFTER:
def _process_sub(sub):
    '''Extracted inner logic'''
    if not sub.ready:
        return None
    # logic here

def _process_item(item):
    '''Extracted middle logic'''
    if not item.valid:
        return []
    return [_process_sub(sub) for sub in item.subs]

def _detect_unreachable(data):
    results = []
    for item in data:
        results.extend(_process_item(item))
    return results
```

#### Step 3: SIMPLIFY

Replace simple nested loops with comprehensions


```python
# BEFORE:
results = []
for item in items:
    if item.valid:
        results.append(item.value)

# AFTER:
results = [item.value for item in items if item.valid]
```

**Rollback**: `git checkout -- code_audit\analyzers\dead_code.py`
**Test**: `pytest -xvs -k _detect_unreachable`

---

## Plan 61: Deep Nesting

**Location**: `code_audit\analyzers\exceptions.py:181`
**Severity**: MEDIUM
**Time**: ~25 minutes

### Steps

#### Step 1: REFACTOR

Convert nested conditions to guard clauses

Source: `code_audit\analyzers\exceptions.py`

```python
# BEFORE:
def process(data):
    if data:
        if data.valid:
            if data.ready:
                # actual logic here
                pass

# AFTER:
def process(data):
    if not data:
        return None
    if not data.valid:
        raise ValueError("Invalid data")
    if not data.ready:
        return  # or raise

    # actual logic here - now at top level
```

#### Step 2: EXTRACT

Extract deeply nested blocks to helper functions

Source: `code_audit\analyzers\exceptions.py`

```python
# BEFORE:
def _handler_has_logging(data):
    for item in data:
        if item.valid:
            for sub in item.subs:
                if sub.ready:
                    # deep logic
                    pass

# AFTER:
def _process_sub(sub):
    '''Extracted inner logic'''
    if not sub.ready:
        return None
    # logic here

def _process_item(item):
    '''Extracted middle logic'''
    if not item.valid:
        return []
    return [_process_sub(sub) for sub in item.subs]

def _handler_has_logging(data):
    results = []
    for item in data:
        results.extend(_process_item(item))
    return results
```

#### Step 3: SIMPLIFY

Replace simple nested loops with comprehensions


```python
# BEFORE:
results = []
for item in items:
    if item.valid:
        results.append(item.value)

# AFTER:
results = [item.value for item in items if item.valid]
```

**Rollback**: `git checkout -- code_audit\analyzers\exceptions.py`
**Test**: `pytest -xvs -k _handler_has_logging`

---

## Plan 62: Deep Nesting

**Location**: `code_audit\analyzers\exceptions.py:246`
**Severity**: HIGH
**Time**: ~35 minutes

### Steps

#### Step 1: REFACTOR

Convert nested conditions to guard clauses

Source: `code_audit\analyzers\exceptions.py`

```python
# BEFORE:
def process(data):
    if data:
        if data.valid:
            if data.ready:
                # actual logic here
                pass

# AFTER:
def process(data):
    if not data:
        return None
    if not data.valid:
        raise ValueError("Invalid data")
    if not data.ready:
        return  # or raise

    # actual logic here - now at top level
```

#### Step 2: EXTRACT

Extract deeply nested blocks to helper functions

Source: `code_audit\analyzers\exceptions.py`

```python
# BEFORE:
def analyze_exceptions(data):
    for item in data:
        if item.valid:
            for sub in item.subs:
                if sub.ready:
                    # deep logic
                    pass

# AFTER:
def _process_sub(sub):
    '''Extracted inner logic'''
    if not sub.ready:
        return None
    # logic here

def _process_item(item):
    '''Extracted middle logic'''
    if not item.valid:
        return []
    return [_process_sub(sub) for sub in item.subs]

def analyze_exceptions(data):
    results = []
    for item in data:
        results.extend(_process_item(item))
    return results
```

#### Step 3: SIMPLIFY

Replace simple nested loops with comprehensions


```python
# BEFORE:
results = []
for item in items:
    if item.valid:
        results.append(item.value)

# AFTER:
results = [item.value for item in items if item.valid]
```

**Rollback**: `git checkout -- code_audit\analyzers\exceptions.py`
**Test**: `pytest -xvs -k analyze_exceptions`

---

## Plan 63: Deep Nesting

**Location**: `code_audit\analyzers\exceptions.py:42`
**Severity**: MEDIUM
**Time**: ~30 minutes

### Steps

#### Step 1: REFACTOR

Convert nested conditions to guard clauses

Source: `code_audit\analyzers\exceptions.py`

```python
# BEFORE:
def process(data):
    if data:
        if data.valid:
            if data.ready:
                # actual logic here
                pass

# AFTER:
def process(data):
    if not data:
        return None
    if not data.valid:
        raise ValueError("Invalid data")
    if not data.ready:
        return  # or raise

    # actual logic here - now at top level
```

#### Step 2: EXTRACT

Extract deeply nested blocks to helper functions

Source: `code_audit\analyzers\exceptions.py`

```python
# BEFORE:
def run(data):
    for item in data:
        if item.valid:
            for sub in item.subs:
                if sub.ready:
                    # deep logic
                    pass

# AFTER:
def _process_sub(sub):
    '''Extracted inner logic'''
    if not sub.ready:
        return None
    # logic here

def _process_item(item):
    '''Extracted middle logic'''
    if not item.valid:
        return []
    return [_process_sub(sub) for sub in item.subs]

def run(data):
    results = []
    for item in data:
        results.extend(_process_item(item))
    return results
```

#### Step 3: SIMPLIFY

Replace simple nested loops with comprehensions


```python
# BEFORE:
results = []
for item in items:
    if item.valid:
        results.append(item.value)

# AFTER:
results = [item.value for item in items if item.valid]
```

**Rollback**: `git checkout -- code_audit\analyzers\exceptions.py`
**Test**: `pytest -xvs -k run`

---

## Plan 64: Deep Nesting

**Location**: `code_audit\analyzers\security.py:168`
**Severity**: MEDIUM
**Time**: ~30 minutes

### Steps

#### Step 1: REFACTOR

Convert nested conditions to guard clauses

Source: `code_audit\analyzers\security.py`

```python
# BEFORE:
def process(data):
    if data:
        if data.valid:
            if data.ready:
                # actual logic here
                pass

# AFTER:
def process(data):
    if not data:
        return None
    if not data.valid:
        raise ValueError("Invalid data")
    if not data.ready:
        return  # or raise

    # actual logic here - now at top level
```

#### Step 2: EXTRACT

Extract deeply nested blocks to helper functions

Source: `code_audit\analyzers\security.py`

```python
# BEFORE:
def _detect_hardcoded_secrets(data):
    for item in data:
        if item.valid:
            for sub in item.subs:
                if sub.ready:
                    # deep logic
                    pass

# AFTER:
def _process_sub(sub):
    '''Extracted inner logic'''
    if not sub.ready:
        return None
    # logic here

def _process_item(item):
    '''Extracted middle logic'''
    if not item.valid:
        return []
    return [_process_sub(sub) for sub in item.subs]

def _detect_hardcoded_secrets(data):
    results = []
    for item in data:
        results.extend(_process_item(item))
    return results
```

#### Step 3: SIMPLIFY

Replace simple nested loops with comprehensions


```python
# BEFORE:
results = []
for item in items:
    if item.valid:
        results.append(item.value)

# AFTER:
results = [item.value for item in items if item.valid]
```

**Rollback**: `git checkout -- code_audit\analyzers\security.py`
**Test**: `pytest -xvs -k _detect_hardcoded_secrets`

---

## Plan 65: Deep Nesting

**Location**: `code_audit\analyzers\security.py:359`
**Severity**: HIGH
**Time**: ~35 minutes

### Steps

#### Step 1: REFACTOR

Convert nested conditions to guard clauses

Source: `code_audit\analyzers\security.py`

```python
# BEFORE:
def process(data):
    if data:
        if data.valid:
            if data.ready:
                # actual logic here
                pass

# AFTER:
def process(data):
    if not data:
        return None
    if not data.valid:
        raise ValueError("Invalid data")
    if not data.ready:
        return  # or raise

    # actual logic here - now at top level
```

#### Step 2: EXTRACT

Extract deeply nested blocks to helper functions

Source: `code_audit\analyzers\security.py`

```python
# BEFORE:
def _detect_sql_injection(data):
    for item in data:
        if item.valid:
            for sub in item.subs:
                if sub.ready:
                    # deep logic
                    pass

# AFTER:
def _process_sub(sub):
    '''Extracted inner logic'''
    if not sub.ready:
        return None
    # logic here

def _process_item(item):
    '''Extracted middle logic'''
    if not item.valid:
        return []
    return [_process_sub(sub) for sub in item.subs]

def _detect_sql_injection(data):
    results = []
    for item in data:
        results.extend(_process_item(item))
    return results
```

#### Step 3: SIMPLIFY

Replace simple nested loops with comprehensions


```python
# BEFORE:
results = []
for item in items:
    if item.valid:
        results.append(item.value)

# AFTER:
results = [item.value for item in items if item.valid]
```

**Rollback**: `git checkout -- code_audit\analyzers\security.py`
**Test**: `pytest -xvs -k _detect_sql_injection`

---

## Plan 66: Deep Nesting

**Location**: `code_audit\analyzers\security.py:484`
**Severity**: MEDIUM
**Time**: ~30 minutes

### Steps

#### Step 1: REFACTOR

Convert nested conditions to guard clauses

Source: `code_audit\analyzers\security.py`

```python
# BEFORE:
def process(data):
    if data:
        if data.valid:
            if data.ready:
                # actual logic here
                pass

# AFTER:
def process(data):
    if not data:
        return None
    if not data.valid:
        raise ValueError("Invalid data")
    if not data.ready:
        return  # or raise

    # actual logic here - now at top level
```

#### Step 2: EXTRACT

Extract deeply nested blocks to helper functions

Source: `code_audit\analyzers\security.py`

```python
# BEFORE:
def _detect_yaml_unsafe(data):
    for item in data:
        if item.valid:
            for sub in item.subs:
                if sub.ready:
                    # deep logic
                    pass

# AFTER:
def _process_sub(sub):
    '''Extracted inner logic'''
    if not sub.ready:
        return None
    # logic here

def _process_item(item):
    '''Extracted middle logic'''
    if not item.valid:
        return []
    return [_process_sub(sub) for sub in item.subs]

def _detect_yaml_unsafe(data):
    results = []
    for item in data:
        results.extend(_process_item(item))
    return results
```

#### Step 3: SIMPLIFY

Replace simple nested loops with comprehensions


```python
# BEFORE:
results = []
for item in items:
    if item.valid:
        results.append(item.value)

# AFTER:
results = [item.value for item in items if item.valid]
```

**Rollback**: `git checkout -- code_audit\analyzers\security.py`
**Test**: `pytest -xvs -k _detect_yaml_unsafe`

---

## Plan 67: Deep Nesting

**Location**: `code_audit\governance\legacy_usage.py:91`
**Severity**: MEDIUM
**Time**: ~25 minutes

### Steps

#### Step 1: REFACTOR

Convert nested conditions to guard clauses

Source: `code_audit\governance\legacy_usage.py`

```python
# BEFORE:
def process(data):
    if data:
        if data.valid:
            if data.ready:
                # actual logic here
                pass

# AFTER:
def process(data):
    if not data:
        return None
    if not data.valid:
        raise ValueError("Invalid data")
    if not data.ready:
        return  # or raise

    # actual logic here - now at top level
```

#### Step 2: EXTRACT

Extract deeply nested blocks to helper functions

Source: `code_audit\governance\legacy_usage.py`

```python
# BEFORE:
def run(data):
    for item in data:
        if item.valid:
            for sub in item.subs:
                if sub.ready:
                    # deep logic
                    pass

# AFTER:
def _process_sub(sub):
    '''Extracted inner logic'''
    if not sub.ready:
        return None
    # logic here

def _process_item(item):
    '''Extracted middle logic'''
    if not item.valid:
        return []
    return [_process_sub(sub) for sub in item.subs]

def run(data):
    results = []
    for item in data:
        results.extend(_process_item(item))
    return results
```

#### Step 3: SIMPLIFY

Replace simple nested loops with comprehensions


```python
# BEFORE:
results = []
for item in items:
    if item.valid:
        results.append(item.value)

# AFTER:
results = [item.value for item in items if item.valid]
```

**Rollback**: `git checkout -- code_audit\governance\legacy_usage.py`
**Test**: `pytest -xvs -k run`

---

## Plan 68: Deep Nesting

**Location**: `code_audit\ml\feature_extraction.py:25`
**Severity**: HIGH
**Time**: ~35 minutes

### Steps

#### Step 1: REFACTOR

Convert nested conditions to guard clauses

Source: `code_audit\ml\feature_extraction.py`

```python
# BEFORE:
def process(data):
    if data:
        if data.valid:
            if data.ready:
                # actual logic here
                pass

# AFTER:
def process(data):
    if not data:
        return None
    if not data.valid:
        raise ValueError("Invalid data")
    if not data.ready:
        return  # or raise

    # actual logic here - now at top level
```

#### Step 2: EXTRACT

Extract deeply nested blocks to helper functions

Source: `code_audit\ml\feature_extraction.py`

```python
# BEFORE:
def _cyclomatic_complexity(data):
    for item in data:
        if item.valid:
            for sub in item.subs:
                if sub.ready:
                    # deep logic
                    pass

# AFTER:
def _process_sub(sub):
    '''Extracted inner logic'''
    if not sub.ready:
        return None
    # logic here

def _process_item(item):
    '''Extracted middle logic'''
    if not item.valid:
        return []
    return [_process_sub(sub) for sub in item.subs]

def _cyclomatic_complexity(data):
    results = []
    for item in data:
        results.extend(_process_item(item))
    return results
```

#### Step 3: SIMPLIFY

Replace simple nested loops with comprehensions


```python
# BEFORE:
results = []
for item in items:
    if item.valid:
        results.append(item.value)

# AFTER:
results = [item.value for item in items if item.valid]
```

**Rollback**: `git checkout -- code_audit\ml\feature_extraction.py`
**Test**: `pytest -xvs -k _cyclomatic_complexity`

---

## Plan 69: Deep Nesting

**Location**: `code_audit\ml\feature_extraction.py:142`
**Severity**: MEDIUM
**Time**: ~25 minutes

### Steps

#### Step 1: REFACTOR

Convert nested conditions to guard clauses

Source: `code_audit\ml\feature_extraction.py`

```python
# BEFORE:
def process(data):
    if data:
        if data.valid:
            if data.ready:
                # actual logic here
                pass

# AFTER:
def process(data):
    if not data:
        return None
    if not data.valid:
        raise ValueError("Invalid data")
    if not data.ready:
        return  # or raise

    # actual logic here - now at top level
```

#### Step 2: EXTRACT

Extract deeply nested blocks to helper functions

Source: `code_audit\ml\feature_extraction.py`

```python
# BEFORE:
def extract_file_features(data):
    for item in data:
        if item.valid:
            for sub in item.subs:
                if sub.ready:
                    # deep logic
                    pass

# AFTER:
def _process_sub(sub):
    '''Extracted inner logic'''
    if not sub.ready:
        return None
    # logic here

def _process_item(item):
    '''Extracted middle logic'''
    if not item.valid:
        return []
    return [_process_sub(sub) for sub in item.subs]

def extract_file_features(data):
    results = []
    for item in data:
        results.extend(_process_item(item))
    return results
```

#### Step 3: SIMPLIFY

Replace simple nested loops with comprehensions


```python
# BEFORE:
results = []
for item in items:
    if item.valid:
        results.append(item.value)

# AFTER:
results = [item.value for item in items if item.valid]
```

**Rollback**: `git checkout -- code_audit\ml\feature_extraction.py`
**Test**: `pytest -xvs -k extract_file_features`

---

## Plan 70: Deep Nesting

**Location**: `code_audit\run_result.py:87`
**Severity**: HIGH
**Time**: ~40 minutes

### Steps

#### Step 1: REFACTOR

Convert nested conditions to guard clauses

Source: `code_audit\run_result.py`

```python
# BEFORE:
def process(data):
    if data:
        if data.valid:
            if data.ready:
                # actual logic here
                pass

# AFTER:
def process(data):
    if not data:
        return None
    if not data.valid:
        raise ValueError("Invalid data")
    if not data.ready:
        return  # or raise

    # actual logic here - now at top level
```

#### Step 2: EXTRACT

Extract deeply nested blocks to helper functions

Source: `code_audit\run_result.py`

```python
# BEFORE:
def _compute_confidence_and_vibe(data):
    for item in data:
        if item.valid:
            for sub in item.subs:
                if sub.ready:
                    # deep logic
                    pass

# AFTER:
def _process_sub(sub):
    '''Extracted inner logic'''
    if not sub.ready:
        return None
    # logic here

def _process_item(item):
    '''Extracted middle logic'''
    if not item.valid:
        return []
    return [_process_sub(sub) for sub in item.subs]

def _compute_confidence_and_vibe(data):
    results = []
    for item in data:
        results.extend(_process_item(item))
    return results
```

#### Step 3: SIMPLIFY

Replace simple nested loops with comprehensions


```python
# BEFORE:
results = []
for item in items:
    if item.valid:
        results.append(item.value)

# AFTER:
results = [item.value for item in items if item.valid]
```

**Rollback**: `git checkout -- code_audit\run_result.py`
**Test**: `pytest -xvs -k _compute_confidence_and_vibe`

---

## Plan 71: Deep Nesting

**Location**: `code_audit\strangler\debt_detector.py:47`
**Severity**: MEDIUM
**Time**: ~25 minutes

### Steps

#### Step 1: REFACTOR

Convert nested conditions to guard clauses

Source: `code_audit\strangler\debt_detector.py`

```python
# BEFORE:
def process(data):
    if data:
        if data.valid:
            if data.ready:
                # actual logic here
                pass

# AFTER:
def process(data):
    if not data:
        return None
    if not data.valid:
        raise ValueError("Invalid data")
    if not data.ready:
        return  # or raise

    # actual logic here - now at top level
```

#### Step 2: EXTRACT

Extract deeply nested blocks to helper functions

Source: `code_audit\strangler\debt_detector.py`

```python
# BEFORE:
def _count_attributes(data):
    for item in data:
        if item.valid:
            for sub in item.subs:
                if sub.ready:
                    # deep logic
                    pass

# AFTER:
def _process_sub(sub):
    '''Extracted inner logic'''
    if not sub.ready:
        return None
    # logic here

def _process_item(item):
    '''Extracted middle logic'''
    if not item.valid:
        return []
    return [_process_sub(sub) for sub in item.subs]

def _count_attributes(data):
    results = []
    for item in data:
        results.extend(_process_item(item))
    return results
```

#### Step 3: SIMPLIFY

Replace simple nested loops with comprehensions


```python
# BEFORE:
results = []
for item in items:
    if item.valid:
        results.append(item.value)

# AFTER:
results = [item.value for item in items if item.valid]
```

**Rollback**: `git checkout -- code_audit\strangler\debt_detector.py`
**Test**: `pytest -xvs -k _count_attributes`

---

## Plan 72: Deep Nesting

**Location**: `code_audit\web_api\config.py:39`
**Severity**: MEDIUM
**Time**: ~25 minutes

### Steps

#### Step 1: REFACTOR

Convert nested conditions to guard clauses

Source: `code_audit\web_api\config.py`

```python
# BEFORE:
def process(data):
    if data:
        if data.valid:
            if data.ready:
                # actual logic here
                pass

# AFTER:
def process(data):
    if not data:
        return None
    if not data.valid:
        raise ValueError("Invalid data")
    if not data.ready:
        return  # or raise

    # actual logic here - now at top level
```

#### Step 2: EXTRACT

Extract deeply nested blocks to helper functions

Source: `code_audit\web_api\config.py`

```python
# BEFORE:
def __post_init__(data):
    for item in data:
        if item.valid:
            for sub in item.subs:
                if sub.ready:
                    # deep logic
                    pass

# AFTER:
def _process_sub(sub):
    '''Extracted inner logic'''
    if not sub.ready:
        return None
    # logic here

def _process_item(item):
    '''Extracted middle logic'''
    if not item.valid:
        return []
    return [_process_sub(sub) for sub in item.subs]

def __post_init__(data):
    results = []
    for item in data:
        results.extend(_process_item(item))
    return results
```

#### Step 3: SIMPLIFY

Replace simple nested loops with comprehensions


```python
# BEFORE:
results = []
for item in items:
    if item.valid:
        results.append(item.value)

# AFTER:
results = [item.value for item in items if item.valid]
```

**Rollback**: `git checkout -- code_audit\web_api\config.py`
**Test**: `pytest -xvs -k __post_init__`

---

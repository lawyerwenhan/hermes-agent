"""
Pre-flight validation system for Hermes tools.
Inspects file paths and content against dangerous patterns before execution.
Layers:
  A - Pattern registry loader (~/.hermes/patterns/registry.yaml)
  B - Content/Path checker against known dangerous patterns
  C - Syntax validation (py_compile, shellcheck)
  D - Pattern match rejection
  E - Syntax error rejection
"""

import os
import re
import subprocess
import tempfile
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple


def get_hermes_home() -> Path:
    """Return base Hermes home directory."""
    return Path(os.path.expanduser("~/.hermes"))


class PreFlightError(Exception):
    """Raised when pre-flight validation fails."""
    
    def __init__(self, message: str, layer: str, pattern_id: Optional[str] = None, severity: str = "error"):
        self.message = message
        self.layer = layer
        self.pattern_id = pattern_id
        self.severity = severity
        super().__init__(self.message)
    
    def __str__(self) -> str:
        base = f"[PreFlight {self.layer}] {self.message}"
        if self.pattern_id:
            base += f" (pattern: {self.pattern_id})"
        return base
    
    def is_blocking(self) -> bool:
        """Return True if this error should block execution."""
        return self.severity == "error"


def load_pattern_registry() -> Dict[str, Any]:
    """
    Layer A: Load pattern registry from YAML.
    Returns dict with 'patterns' key containing list of pattern definitions.
    """
    import yaml
    registry_path = get_hermes_home() / "patterns" / "registry.yaml"
    
    if not registry_path.exists():
        return {"patterns": [], "version": 0}
    
    try:
        with open(registry_path, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f)
            if data is None:
                return {"patterns": [], "version": 0}
            return data
    except yaml.YAMLError as e:
        raise PreFlightError(f"Invalid YAML in pattern registry: {e}", "A")
    except Exception as e:
        raise PreFlightError(f"Failed to load pattern registry: {e}", "A")


def normalize_pattern(pattern: str) -> str:
    """Normalize pattern for matching (replace internal whitespace with flexible match)."""
    # Collapse internal whitespace
    return re.sub(r'\s+', r'\\s+', pattern.strip())


def check_content_patterns(
    content: Optional[str],
    file_path: Optional[str] = None,
    pattern_registry: Optional[Dict] = None
) -> Tuple[bool, List[PreFlightError]]:
    """
    Layer B/D: Check content against dangerous patterns.
    Returns (has_errors, list_of_errors).
    """
    errors = []
    
    if content is None:
        # No content to check (e.g., terminal command with no file context)
        return False, []
    
    if pattern_registry is None:
        try:
            pattern_registry = load_pattern_registry()
        except PreFlightError as e:
            # Registry error is fatal for pattern checking
            return True, [e]
    
    patterns = pattern_registry.get("patterns", [])
    if not patterns:
        return False, []
    
    for pat_def in patterns:
        pattern_id = pat_def.get("id", "unknown")
        pat_type = pat_def.get("type", "content")
        
        # Type: content - match against command/file content
        if pat_type == "content":
            pattern_str = pat_def.get("pattern", "")
            if not pattern_str:
                continue
            
            # Try exact match first, then normalized
            if pattern_str in content:
                severity = pat_def.get("severity", "error")
                errors.append(PreFlightError(
                    message=pat_def.get("message", f"Dangerous pattern detected: {pattern_id}"),
                    layer="D",
                    pattern_id=pattern_id,
                    severity=severity,
                ))
                continue
            
            # Try regex if normalized pattern differs
            normalized = normalize_pattern(pattern_str)
            if normalized != pattern_str:
                try:
                    if re.search(normalized, content, re.IGNORECASE):
                        severity = pat_def.get("severity", "error")
                        errors.append(PreFlightError(
                            message=pat_def.get("message", f"Dangerous pattern detected: {pattern_id}"),
                            layer="D",
                            pattern_id=pattern_id,
                            severity=severity,
                        ))
                except re.error:
                    pass  # Invalid regex is silently ignored
        
        # Type: path - check if file_path matches pattern
        elif pat_type == "path" and file_path:
            pattern_str = pat_def.get("pattern", "")
            if pattern_str and file_path.startswith(pattern_str):
                severity = pat_def.get("severity", "error")
                errors.append(PreFlightError(
                    message=pat_def.get("message", f"Protected path pattern detected: {pattern_id}"),
                    layer="D",
                    pattern_id=pattern_id,
                    severity=severity,
                ))
        
        # Type: overwrite - check if we're overwriting a protected path
        elif pat_type == "overwrite" and file_path:
            pattern_str = pat_def.get("pattern", "")
            if pattern_str and re.search(pattern_str, file_path):
                # Check if file actually exists
                if Path(file_path).exists():
                    severity = pat_def.get("severity", "error")
                    errors.append(PreFlightError(
                        message=pat_def.get("message", f"Overwrite of protected file: {file_path}"),
                        layer="D",
                        pattern_id=pattern_id,
                        severity=severity,
                    ))
    
    return bool(errors), errors


def check_py_syntax(content: str, filename: str = "<string>") -> Tuple[bool, Optional[str]]:
    """
    Layer C/E: Validate Python code using py_compile.
    Returns (has_errors, error_message).
    """
    try:
        import py_compile
        # Write to temp file to use py_compile
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write(content)
            temp_path = f.name
        
        try:
            py_compile.compile(temp_path, doraise=True)
            return False, None
        except py_compile.PyCompileError as e:
            return True, str(e)
        finally:
            os.unlink(temp_path)
    except Exception as e:
        return True, f"Syntax check failed: {e}"


def check_shell_syntax(content: str) -> Tuple[bool, Optional[str]]:
    """
    Layer C/E: Validate shell script using shellcheck if available.
    Returns (has_errors, error_message).
    """
    # First check if shellcheck is available
    shellcheck_path = subprocess.run(
        ["which", "shellcheck"],
        capture_output=True, text=True
    )
    
    if shellcheck_path.returncode != 0:
        # Shellcheck not available, skip validation
        return False, None
    
    # Write to temp file for shellcheck
    try:
        with tempfile.NamedTemporaryFile(mode='w', suffix='.sh', delete=False) as f:
            f.write(content)
            temp_path = f.name
        
        try:
            result = subprocess.run(
                ["shellcheck", "-S", "error", temp_path],
                capture_output=True, text=True
            )
            
            if result.returncode != 0 and result.stdout:
                # Extract first error line
                lines = result.stdout.strip().split('\n')
                error_lines = [l for l in lines if 'error:' in l.lower()]
                if error_lines:
                    return True, f"shellcheck: {error_lines[0]}"
                return True, f"shellcheck: {result.stdout[:200]}"
            
            return False, None
        finally:
            os.unlink(temp_path)
    except Exception as e:
        return True, f"Shellcheck failed: {e}"


def validate_file_write(
    file_path: str,
    content: Optional[str],
    enforce_syntax: bool = True
) -> Tuple[bool, List[PreFlightError]]:
    """
    Full pre-flight validation for file write operations.
    Layer D: Pattern checks
    Layer E: Syntax checks (if enforce_syntax=True)
    """
    all_errors = []
    
    # Guard: No content to validate (e.g., file deletion, or None passed)
    if content is None:
        return False, []
    
    # Layer D: Pattern checks
    has_pattern_errors, pattern_errors = check_content_patterns(content, file_path)
    all_errors.extend(pattern_errors)
    
    # Layer E: Syntax checks for code files
    if enforce_syntax:
        path_obj = Path(file_path)
        
        # Python files
        if path_obj.suffix == '.py':
            has_error, msg = check_py_syntax(content, file_path)
            if has_error:
                all_errors.append(PreFlightError(
                    message=f"Python syntax error: {msg}",
                    layer="E"
                ))
        
        # Shell scripts
        elif path_obj.suffix == '.sh' or content.startswith('#!'):
            has_error, msg = check_shell_syntax(content)
            if has_error:
                all_errors.append(PreFlightError(
                    message=f"Shell script error: {msg}",
                    layer="E"
                ))
    
    return bool(all_errors), all_errors


def validate_terminal_command(
    command: str,
    context: Optional[Dict] = None
) -> Tuple[bool, List[PreFlightError]]:
    """
    Pre-flight validation for terminal commands.
    Checks for dangerous patterns in command content.
    """
    all_errors = []
    
    # Layer D: Pattern checks
    # Pass None as file_path since this is a command, not a file
    has_pattern_errors, pattern_errors = check_content_patterns(command, None)
    all_errors.extend(pattern_errors)
    
    return bool(all_errors), all_errors


def format_pre_flight_errors(errors: List[PreFlightError]) -> str:
    """Format a list of PreFlightErrors into a human-readable message."""
    if not errors:
        return ""
    
    lines = ["Pre-flight validation failed:", ""]
    for i, err in enumerate(errors, 1):
        lines.append(f"  {i}. {err}")
    
    return "\n".join(lines)
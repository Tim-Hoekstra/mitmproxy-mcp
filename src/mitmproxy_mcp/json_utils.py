from __future__ import annotations

import json
import re
from typing import Any


def json_structure_preview(data: Any, max_depth: int = 2, current_depth: int = 0) -> Any:
    """Replace leaf values with type indicators, preserving structure up to max_depth.

    Example output: {"data": {"users": "[50 items]"}, "meta": {"...": "3 keys"}}
    """
    if current_depth >= max_depth:
        if isinstance(data, dict):
            return {"...": f"{len(data)} keys"}
        elif isinstance(data, list):
            return f"[{len(data)} items]"
        elif isinstance(data, str):
            return "[string]"
        elif isinstance(data, bool):
            return "[bool]"
        elif isinstance(data, int):
            return "[int]"
        elif isinstance(data, float):
            return "[float]"
        elif data is None:
            return "[null]"
        return f"[{type(data).__name__}]"

    if isinstance(data, dict):
        return {k: json_structure_preview(v, max_depth, current_depth + 1) for k, v in data.items()}
    elif isinstance(data, list):
        if not data:
            return "[]"
        if len(data) <= 3:
            return [json_structure_preview(item, max_depth, current_depth + 1) for item in data]
        return f"[{len(data)} items]"
    elif isinstance(data, str):
        if len(data) > 100:
            return f"[string, {len(data)} chars]"
        return data
    else:
        return data


def smart_body_content(
    body: bytes | None,
    content_type: str | None,
    truncate_at: int = 2000,
) -> tuple[Any, bool, bool]:
    """Return (content, is_truncated, is_preview).

    - Small bodies: returned as-is (string or base64)
    - Large JSON: structure preview
    - Large non-JSON: truncated string
    """
    if body is None:
        return None, False, False

    is_json = content_type and "json" in content_type.lower()

    if len(body) <= truncate_at:
        try:
            text = body.decode("utf-8")
            if is_json:
                try:
                    return json.loads(text), False, False
                except (json.JSONDecodeError, ValueError):
                    pass
            return text, False, False
        except UnicodeDecodeError:
            import base64
            return base64.b64encode(body).decode("ascii"), False, False

    # Body exceeds truncate_at
    if is_json:
        try:
            text = body.decode("utf-8")
            parsed = json.loads(text)
            return json_structure_preview(parsed), True, True
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
            pass

    # Non-JSON or failed JSON parse: truncate
    try:
        text = body[:truncate_at].decode("utf-8", errors="ignore")
        return f"{text}...[truncated {len(body)} bytes total]", True, False
    except Exception:
        import base64
        return base64.b64encode(body[:truncate_at]).decode("ascii") + f"...[truncated {len(body)} bytes total]", True, False


# ---------------------------------------------------------------------------
# JSONPath parser
# ---------------------------------------------------------------------------

_PATH_TOKEN_RE = re.compile(
    r"""
    \.(\w+)               # .key
    | \[(\d+)\]           # [0]
    | \['([^']+)'\]       # ['key']
    | \["([^"]+)"\]       # ["key"]
    """,
    re.VERBOSE,
)


def extract_json_path(data: Any, path: str) -> Any:
    """Extract a value from parsed JSON using a simple JSONPath expression.

    Supports: $.key, $.key.sub, $.arr[0], $.obj['key-with-dash'], $.obj["quoted"]
    Returns None if the path doesn't resolve.
    """
    # Strip leading $
    if path.startswith("$"):
        path = path[1:]

    if not path:
        return data

    current = data
    for match in _PATH_TOKEN_RE.finditer(path):
        dot_key, array_idx, single_quoted, double_quoted = match.groups()
        key = dot_key or single_quoted or double_quoted

        if key is not None:
            if isinstance(current, dict):
                if key not in current:
                    return None
                current = current[key]
            else:
                return None
        elif array_idx is not None:
            idx = int(array_idx)
            if isinstance(current, list) and 0 <= idx < len(current):
                current = current[idx]
            else:
                return None

    return current

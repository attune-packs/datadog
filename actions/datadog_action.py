#!/usr/bin/env python3
"""Shared flat stdin/JSON entry point for Datadog actions."""

from __future__ import annotations

import json
import os
import sys

PACK_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PACK_ROOT not in sys.path:
    sys.path.insert(0, PACK_ROOT)

from lib.datadog_client import DatadogPackError, execute_action


def main() -> int:
    try:
        raw = sys.stdin.read()
        params = json.loads(raw) if raw.strip() else {}
        if not isinstance(params, dict):
            raise DatadogPackError("action parameters must be a JSON object")
        operation = os.environ.get("ATTUNE_ACTION", "").rsplit(".", 1)[-1]
        result = execute_action(operation, params)
        json.dump({"operation": operation, "result": result}, sys.stdout, separators=(",", ":"))
        sys.stdout.write("\n")
        return 0
    except (DatadogPackError, ValueError, TypeError, OSError) as exc:
        print(f"datadog action failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:  # noqa: BLE001 - redact every unexpected library failure
        # Unknown remote/library exceptions may contain keys, URLs, or response bodies.
        print(f"datadog action failed: {type(exc).__name__}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

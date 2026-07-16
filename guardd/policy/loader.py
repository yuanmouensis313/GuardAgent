from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import jsonschema
import yaml

from guardd.security import digest_payload


class PolicyValidationError(ValueError):
    pass


@dataclass(frozen=True)
class LoadedPolicy:
    document: dict[str, Any]
    digest: str
    source: Path

    @property
    def mode(self) -> str:
        return str(self.document.get("defaults", {}).get("mode", "observe")).lower()


class PolicyLoader:
    def __init__(self, schema_path: Path | None = None):
        self.schema_path = schema_path or Path(__file__).with_name("policy.schema.json")

    def validate(self, document: dict[str, Any]) -> list[str]:
        errors: list[str] = []
        try:
            schema = json.loads(self.schema_path.read_text(encoding="utf-8"))
            validator = jsonschema.Draft202012Validator(schema)
            errors.extend(error.message for error in sorted(validator.iter_errors(document), key=lambda e: list(e.path)))
        except (OSError, json.JSONDecodeError) as exc:
            errors.append(f"policy schema unavailable: {exc}")
        ids = [rule.get("id") for rule in document.get("rules", []) if isinstance(rule, dict)]
        duplicates = sorted({item for item in ids if ids.count(item) > 1})
        if duplicates:
            errors.append(f"duplicate rule IDs: {', '.join(duplicates)}")
        for item in document.get("protected_paths", []):
            if isinstance(item, str) and "${" not in item and "%" not in item and not Path(item).expanduser().is_absolute():
                errors.append(f"protected path must be absolute after environment expansion: {item}")
        for item in document.get("secret_detection", {}).get("custom_patterns", []):
            try:
                re.compile(str(item.get("regex", "")))
            except re.error as exc:
                errors.append(f"invalid custom secret regex {item.get('id')}: {exc}")
        return errors

    def parse(self, text: str, source: Path = Path("<memory>")) -> LoadedPolicy:
        try:
            document = yaml.safe_load(text)
        except yaml.YAMLError as exc:
            raise PolicyValidationError(str(exc)) from exc
        if not isinstance(document, dict):
            raise PolicyValidationError("policy root must be a mapping")
        document = self._expand(document)
        errors = self.validate(document)
        if errors:
            raise PolicyValidationError("; ".join(errors))
        return LoadedPolicy(document=document, digest=digest_payload(document), source=source)

    def load(self, path: Path) -> LoadedPolicy:
        return self.parse(path.read_text(encoding="utf-8"), path)

    def _expand(self, value: Any) -> Any:
        if isinstance(value, str):
            return os.path.expandvars(value)
        if isinstance(value, list):
            return [self._expand(item) for item in value]
        if isinstance(value, dict):
            return {key: self._expand(item) for key, item in value.items()}
        return value

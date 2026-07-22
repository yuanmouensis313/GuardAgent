from __future__ import annotations

import argparse
import hashlib
import json
import os
import queue
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, TextIO
from uuid import uuid4

import httpx

from guardd.security import SANITIZATION_PATTERN_DIGEST, digest_payload, sanitize


LIST_METHODS = {
    "tools/list": ("tools", "tool"),
    "prompts/list": ("prompts", "prompt"),
    "resources/list": ("resources", "resource"),
}


@dataclass
class AdmittedDescriptor:
    name: str
    descriptor_digest: str
    artifact_digest: str


class GuardMcpProxy:
    def __init__(
        self, command: list[str], server_identity: str, guardd_url: str,
        token_file: Path, session_key: str, agent_id: str, mode: str,
    ):
        if not command:
            raise ValueError("an upstream MCP command is required")
        if mode not in {"observe", "enforce"}:
            raise ValueError("mode must be observe or enforce")
        self.command = command
        self.server_identity = server_identity
        self.transport_identity = digest_payload({"transport": "stdio", "command": command[0], "argc": len(command)})
        self.session_key = session_key if session_key.startswith("sha256:") else "sha256:" + hashlib.sha256(session_key.encode()).hexdigest()
        self.agent_id = agent_id
        self.mode = mode
        token = token_file.read_text(encoding="utf-8").strip()
        if len(token) < 32:
            raise ValueError("invalid guardd token file")
        self.client = httpx.Client(
            base_url=guardd_url, headers={"Authorization": f"Bearer {token}"}, timeout=10,
        )
        self.pending: dict[Any, str] = {}
        self.admitted_tools: dict[str, AdmittedDescriptor] = {}
        self.server_version: str | None = None
        self.protocol_version: str | None = None
        self.capabilities: dict[str, Any] = {}

    def run(self) -> int:
        process = subprocess.Popen(
            self.command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=None, text=True, encoding="utf-8", bufsize=1,
        )
        if process.stdin is None or process.stdout is None:
            raise RuntimeError("failed to open upstream MCP stdio pipes")
        messages: queue.Queue[tuple[str, str | None]] = queue.Queue()
        threading.Thread(target=self._pump, args=("client", sys.stdin, messages), daemon=True).start()
        threading.Thread(target=self._pump, args=("upstream", process.stdout, messages), daemon=True).start()
        try:
            while True:
                source, line = messages.get()
                if line is None:
                    if source == "client":
                        break
                    return process.wait(timeout=2)
                try:
                    message = json.loads(line)
                except json.JSONDecodeError:
                    if source == "upstream":
                        self._write({"jsonrpc": "2.0", "method": "notifications/message", "params": {"level": "error", "data": "Guard MCP proxy removed malformed upstream JSON"}})
                    continue
                if source == "client":
                    forwarded = self._from_client(message)
                    if forwarded is not None:
                        process.stdin.write(json.dumps(forwarded, ensure_ascii=False, separators=(",", ":")) + "\n")
                        process.stdin.flush()
                else:
                    forwarded = self._from_upstream(message)
                    if forwarded is not None:
                        self._write(forwarded)
        finally:
            self.client.close()
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    process.kill()
        return process.returncode or 0

    @staticmethod
    def _pump(source: str, stream: TextIO, output: queue.Queue[tuple[str, str | None]]) -> None:
        try:
            for line in stream:
                if line.strip():
                    output.put((source, line))
        finally:
            output.put((source, None))

    @staticmethod
    def _write(message: dict[str, Any]) -> None:
        sys.stdout.write(json.dumps(message, ensure_ascii=False, separators=(",", ":")) + "\n")
        sys.stdout.flush()

    def _from_client(self, message: dict[str, Any]) -> dict[str, Any] | None:
        method = str(message.get("method", ""))
        request_id = message.get("id")
        if request_id is not None and method:
            self.pending[request_id] = method
        if method == "tools/call":
            params = message.get("params") if isinstance(message.get("params"), dict) else {}
            name = str(params.get("name", ""))
            admitted = self.admitted_tools.get(name)
            if admitted is None:
                self._write(self._error(request_id, -32001, "MCP tool is not admitted by digest-bound inspection"))
                self.pending.pop(request_id, None)
                return None
            arguments = params.get("arguments") if isinstance(params.get("arguments"), dict) else {}
            clean_arguments, classifications = sanitize(arguments)
            decision = self._guard_decision(name, admitted, clean_arguments, classifications)
            allowed = decision.get("decision") == "ALLOW" or (self.mode == "observe" and decision.get("decision") == "OBSERVE")
            if decision.get("decision") == "REQUIRE_APPROVAL":
                rule_ids = set(decision.get("rule_ids") or [])
                if any(str(rule).startswith(("TASK-POLICY-", "CONTENT-INSPECTION-")) for rule in rule_ids):
                    allowed = False
                else:
                    allowed = self._await_approval(str(decision.get("approval_id") or ""))
            if not allowed:
                self._write(self._error(request_id, -32002, f"GuardAgent blocked MCP call: {decision.get('reason', 'policy')}"))
                self.pending.pop(request_id, None)
                return None
            execution = decision.get("execution_params") or decision.get("rewritten_params")
            plan = decision.get("transformation_plan") or []
            actions = {str(item.get("action")) for item in plan if isinstance(item, dict)}
            if "block" in actions or "require_approval" in actions:
                self._write(self._error(request_id, -32003, "GuardAgent blocked secret-bearing MCP arguments"))
                self.pending.pop(request_id, None)
                return None
            if execution is not None:
                params["arguments"] = execution
            elif actions & {"redact", "drop"}:
                params["arguments"] = clean_arguments
            else:
                params["arguments"] = arguments
            message["params"] = params
        return message

    def _await_approval(self, approval_id: str, timeout_seconds: float = 60.0) -> bool:
        if not approval_id:
            return False
        deadline = time.monotonic() + timeout_seconds
        while time.monotonic() < deadline:
            try:
                response = self.client.get(f"/v1/approvals/{approval_id}")
                if response.status_code == 404:
                    return False
                response.raise_for_status()
                status = str(response.json().get("status", "pending"))
            except (httpx.HTTPError, ValueError):
                return False
            if status == "allowed_once":
                return True
            if status in {"denied", "expired"}:
                return False
            time.sleep(0.5)
        return False

    def _from_upstream(self, message: dict[str, Any]) -> dict[str, Any] | None:
        if message.get("method") in {"notifications/tools/list_changed", "notifications/prompts/list_changed", "notifications/resources/list_changed"}:
            self.admitted_tools.clear()
            return message
        request_id = message.get("id")
        method = self.pending.pop(request_id, None) if request_id is not None else None
        if method == "initialize" and isinstance(message.get("result"), dict):
            result = message["result"]
            self.protocol_version = str(result.get("protocolVersion", "")) or None
            server_info = result.get("serverInfo") if isinstance(result.get("serverInfo"), dict) else {}
            self.server_version = str(server_info.get("version", "")) or None
            self.capabilities = result.get("capabilities") if isinstance(result.get("capabilities"), dict) else {}
        if method in LIST_METHODS and isinstance(message.get("result"), dict):
            key, kind = LIST_METHODS[method]
            descriptors = message["result"].get(key)
            if isinstance(descriptors, list):
                admitted: list[dict[str, Any]] = []
                for descriptor in descriptors:
                    if not isinstance(descriptor, dict):
                        continue
                    identity = self._inspect_descriptor(kind, descriptor)
                    if identity is None:
                        continue
                    admitted.append(descriptor)
                    if kind == "tool":
                        self.admitted_tools[identity.name] = identity
                message["result"][key] = admitted
        if method == "tools/call" and "result" in message:
            original = message["result"]
            clean, classifications = sanitize(original)
            message["result"] = self._tag_tool_content(clean)
            self._record_sanitization(classifications, original, message["result"])
        return message

    def _inspect_descriptor(self, kind: str, descriptor: dict[str, Any]) -> AdmittedDescriptor | None:
        key = {"tool": "tools", "prompt": "prompts", "resource": "resources"}[kind]
        payload = {
            "schema_version": "1.0", "request_id": str(uuid4()),
            "server_identity": self.server_identity, "source_identity": f"mcp:{self.server_identity}",
            "transport_identity": self.transport_identity, "server_version": self.server_version,
            "protocol_version": self.protocol_version, "capabilities": self.capabilities,
            "tools": [], "prompts": [], "resources": [], key: [descriptor],
        }
        try:
            response = self.client.post("/v1/inspections/mcp-descriptors", json=payload)
            response.raise_for_status()
            inspected = response.json()
        except (httpx.HTTPError, ValueError):
            return None
        if inspected.get("effective_decision") != "ALLOW":
            return None
        entries = inspected.get("manifest", {}).get("descriptors", [])
        if not entries:
            return None
        entry = entries[0]
        return AdmittedDescriptor(
            name=str(descriptor.get("name") or descriptor.get("uri") or "unknown"),
            descriptor_digest=str(entry["digest"]), artifact_digest=str(inspected["content_digest"]),
        )

    def _guard_decision(
        self, name: str, identity: AdmittedDescriptor,
        policy_arguments: dict[str, Any], classifications: list[str],
    ) -> dict[str, Any]:
        event = {
            "schema_version": "1.1", "event_id": str(uuid4()), "event_type": "tool.before",
            "source": "openclaw", "agent_id": self.agent_id, "session_key": self.session_key,
            "tool": {"name": name, "kind": "mcp"}, "params": policy_arguments,
            "data_classification": classifications,
            "content_identity": {
                "kind": "mcp", "name": name, "digest": identity.descriptor_digest,
                "artifact_digest": identity.artifact_digest, "server_identity": self.server_identity,
            },
        }
        try:
            response = self.client.post(
                "/v1/decisions/tool",
                json={"schema_version": "1.0", "request_id": str(uuid4()), "event": event},
            )
            response.raise_for_status()
            return response.json()
        except (httpx.HTTPError, ValueError) as exc:
            return {"decision": "DENY", "reason": f"guardd unavailable: {type(exc).__name__}"}

    def _record_sanitization(self, classifications: list[str], original: Any, result: Any) -> None:
        transformations = [
            {
                "json_path": "$", "classification": classification, "length": 0,
                "source": "mcp-result-pattern", "proposed_action": "redact",
                "ref": f"event-local-{index}",
            }
            for index, classification in enumerate(sorted(set(classifications)), start=1)
        ]
        try:
            self.client.post("/v1/events/sanitization", json={
                "schema_version": "1.0", "request_id": str(uuid4()), "sanitizer_event_id": str(uuid4()),
                "direction": "inbound", "session_key": self.session_key, "tool_name": "mcp-result",
                "classifications": classifications, "transformations": transformations,
                "original_size": len(json.dumps(original, ensure_ascii=False, default=str).encode()),
                "result_size": len(json.dumps(result, ensure_ascii=False, default=str).encode()),
                "truncated": False, "blocked": False, "pattern_digest": SANITIZATION_PATTERN_DIGEST,
                "content_digest": digest_payload(result),
            })
        except httpx.HTTPError:
            pass

    def _tag_tool_content(self, value: Any) -> Any:
        if isinstance(value, str):
            return f'<UNTRUSTED_TOOL_CONTENT tool="mcp:{self.server_identity}">\n{value}\n</UNTRUSTED_TOOL_CONTENT>'
        if isinstance(value, list):
            return [self._tag_tool_content(item) for item in value]
        if isinstance(value, dict):
            output = dict(value)
            if output.get("type") == "text" and isinstance(output.get("text"), str):
                output["text"] = self._tag_tool_content(output["text"])
            else:
                output = {key: self._tag_tool_content(item) for key, item in output.items()}
            return output
        return value

    @staticmethod
    def _error(request_id: Any, code: int, message: str) -> dict[str, Any]:
        return {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}


def main() -> None:
    parser = argparse.ArgumentParser(description="Digest-bound GuardAgent proxy for stdio MCP servers")
    parser.add_argument("--server-identity", required=True)
    parser.add_argument("--guardd-url", default=os.getenv("GUARDD_URL", "http://127.0.0.1:8787"))
    parser.add_argument("--token-file", type=Path, default=Path(os.getenv("GUARDD_TOKEN_FILE", "guardd.token")))
    parser.add_argument("--session-key", default=os.getenv("GUARD_MCP_SESSION_KEY", "mcp-proxy"))
    parser.add_argument("--agent-id", default=os.getenv("GUARD_MCP_AGENT_ID", "main"))
    parser.add_argument("--mode", choices=["observe", "enforce"], default=os.getenv("GUARD_MCP_MODE", "enforce"))
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    proxy = GuardMcpProxy(
        command, args.server_identity, args.guardd_url, args.token_file,
        args.session_key, args.agent_id, args.mode,
    )
    raise SystemExit(proxy.run())


if __name__ == "__main__":
    main()

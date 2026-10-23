#!/usr/bin/env python3
"""Resolve which connector calls a Kortix agent may make without a person.

Reads a kortix.yaml (v2 or v3) and answers, for each ``<connector>.<tool>`` path
you give it, whether Kortix will run the call (``allow``), hold it for a person
(``require_approval``) or refuse it (``block``) — with the rule that decided it
and how long a held call waits (``approvals.ttl``).

The order is the platform's own (kortix.yaml reference, "policy and policies"):
the agent's connectors grant, then project ``policies`` (first match wins), then
the connector's own ``policies``, then a connector's ``sensitive`` flag, then
``policy.default_mode``.

Read-only: it opens one YAML file, contacts nothing and holds no credential.
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

try:
    import yaml
except ImportError:  # pragma: no cover - exercised only without the dependency
    print("needs PyYAML: pip install -r requirements.txt", file=sys.stderr)
    raise SystemExit(2)

ALLOW = "allow"
APPROVE = "require_approval"
BLOCK = "block"
UNDECIDED = "undecided"

CHANNEL_CONNECTORS = {"kortix_slack", "kortix_teams", "kortix_email"}
RESERVED_CONNECTORS = CHANNEL_CONNECTORS | {"computer"}
VALID_ACTIONS = {APPROVE, BLOCK, "always_run"}
EFFECTS = {"read", "write", "destructive"}

TTL_DEFAULT_MINUTES = 24 * 60
TTL_MIN_MINUTES = 5
TTL_MAX_MINUTES = 30 * 24 * 60


SKIP = "__skip__"


class AuditError(Exception):
    """The manifest or the call list cannot be read."""


# --------------------------------------------------------------------------- #
# manifest reading


@dataclass
class Connector:
    slug: str
    sensitive: bool = False
    policies: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class Manifest:
    path: Path
    version: int
    default_agent: str | None
    agents: dict[str, dict[str, Any]]
    connectors: dict[str, Connector]
    default_mode: str
    policies: list[dict[str, Any]]
    ttl_minutes: int
    ttl_note: str


def _grant(value: Any) -> str | list[str]:
    """Normalise a grant set: 'all', 'none', or a list of names."""
    if value is None:
        return "none"
    if isinstance(value, str):
        text = value.strip()
        if text in {"", "none"}:
            return "none"
        if text in {"all", "*"}:
            return "all"
        return [text]
    if isinstance(value, (list, tuple)):
        names = [str(item) for item in value]
        if not names:
            return "none"
        if "*" in names:
            return "all"
        return names
    raise AuditError(f"a grant set must be all, none or a list of names, not {value!r}")


def parse_ttl(value: Any) -> tuple[int, str]:
    """Return (minutes, note). Kortix clamps 5m..30d and falls back to 24h."""
    if value is None:
        return TTL_DEFAULT_MINUTES, "no approvals.ttl: 24h"
    text = str(value).strip().lower()
    match = re.fullmatch(r"(\d+)\s*([mhd])", text)
    if not match:
        return TTL_DEFAULT_MINUTES, f"malformed approvals.ttl {value!r}: 24h"
    amount, unit = int(match.group(1)), match.group(2)
    minutes = amount * {"m": 1, "h": 60, "d": 1440}[unit]
    if minutes < TTL_MIN_MINUTES:
        return TTL_MIN_MINUTES, f"approvals.ttl {text} clamped up to 5m"
    if minutes > TTL_MAX_MINUTES:
        return TTL_MAX_MINUTES, f"approvals.ttl {text} clamped down to 30d"
    return minutes, f"approvals.ttl {text}"


def load_manifest(path: Path) -> Manifest:
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise AuditError(f"cannot read {path}: {exc}") from exc
    except yaml.YAMLError as exc:
        raise AuditError(f"{path} is not valid YAML: {exc}") from exc
    if not isinstance(raw, dict):
        raise AuditError(f"{path} does not hold a mapping at the top level")

    version = raw.get("kortix_version")
    if version not in (2, 3):
        raise AuditError(
            "kortix_version must be 2 or 3; a v1 kortix.toml has a different shape "
            "(migrate it with `kortix projects upgrade`)"
        )

    agents = raw.get("agents")
    if not isinstance(agents, dict) or not agents:
        raise AuditError("agents: at least one agent block is required in v2 and v3")

    connectors: dict[str, Connector] = {}
    entries = raw.get("connectors") or []
    if not isinstance(entries, list):
        raise AuditError("connectors must be a list")
    for entry in entries:
        if not isinstance(entry, dict) or not entry.get("slug"):
            raise AuditError(f"a connector entry needs a slug: {entry!r}")
        slug = str(entry["slug"])
        policies = entry.get("policies") or []
        if not isinstance(policies, list):
            raise AuditError(f"connectors[{slug}].policies must be a list")
        connectors[slug] = Connector(
            slug=slug,
            sensitive=bool(entry.get("sensitive", False)),
            policies=[p for p in policies if isinstance(p, dict)],
        )

    policy = raw.get("policy") or {}
    if not isinstance(policy, dict):
        raise AuditError("policy must be a mapping")
    default_mode = str(policy.get("default_mode") or "allow_all")
    if default_mode not in {"allow_all", "risk"}:
        raise AuditError(f"policy.default_mode must be allow_all or risk, not {default_mode!r}")

    policies = raw.get("policies") or []
    if not isinstance(policies, list):
        raise AuditError("policies must be a list")

    approvals = raw.get("approvals") or {}
    if not isinstance(approvals, dict):
        raise AuditError("approvals must be a mapping")
    ttl_minutes, ttl_note = parse_ttl(approvals.get("ttl"))

    return Manifest(
        path=path,
        version=int(version),
        default_agent=raw.get("default_agent"),
        agents={str(name): (block if isinstance(block, dict) else {}) for name, block in agents.items()},
        connectors=connectors,
        default_mode=default_mode,
        policies=[p for p in policies if isinstance(p, dict)],
        ttl_minutes=ttl_minutes,
        ttl_note=ttl_note,
    )


# --------------------------------------------------------------------------- #
# rule matching


def _arg_value(args: dict[str, Any], path: str) -> Any:
    """Look a (possibly dotted) argument name up in the call's arguments."""
    current: Any = args
    for part in path.split("."):
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current


def _matches(pattern: str, value: str) -> bool:
    """fnmatch glob by default; /regex/ in slashes."""
    if len(pattern) > 2 and pattern.startswith("/") and pattern.endswith("/"):
        try:
            return re.search(pattern[1:-1], value) is not None
        except re.error:
            return False
    return fnmatch.fnmatchcase(value, pattern)


def conditions_hold(conditions: Any, args: dict[str, Any]) -> tuple[bool, str | None]:
    """All conditions must hold. Returns (held, error)."""
    if not conditions:
        return True, None
    if not isinstance(conditions, list):
        return False, "conditions must be a list"
    for condition in conditions:
        if not isinstance(condition, dict):
            return False, f"a condition must be a mapping: {condition!r}"
        arg = condition.get("arg")
        pattern = condition.get("match")
        if not arg or pattern is None:
            return False, f"a condition needs arg and match: {condition!r}"
        value = _arg_value(args, str(arg))
        hit = value is not None and _matches(str(pattern), str(value))
        if condition.get("negate"):
            hit = not hit
        if not hit:
            return False, None
    return True, None


@dataclass
class Decision:
    call: str
    effect: str
    action: str
    decided_by: str
    error: str | None = None

    def as_dict(self, ttl_minutes: int) -> dict[str, Any]:
        held = self.action == APPROVE
        return {
            "call": self.call,
            "effect": self.effect,
            "decision": self.action,
            "decided_by": self.decided_by,
            "ttl_minutes": ttl_minutes if held else None,
            "error": self.error,
        }


def _connector_of(call: str) -> tuple[str, str]:
    if "." not in call:
        raise AuditError(f"a call is <connector>.<tool>, not {call!r}")
    connector, tool = call.split(".", 1)
    return connector, tool


def resolve(
    manifest: Manifest,
    agent: str,
    call: str,
    effect: str,
    args: dict[str, Any] | None = None,
    channel: str | None = None,
) -> Decision:
    args = args or {}
    connector_slug, tool = _connector_of(call)
    grant = _grant(manifest.agents[agent].get("connectors"))

    # 1. The agent's grant.
    channel_slug = {"slack": "kortix_slack", "teams": "kortix_teams", "email": "kortix_email"}.get(
        channel or "", None
    )
    reachable = grant == "all" or (isinstance(grant, list) and connector_slug in grant)
    if connector_slug == channel_slug:
        reachable = True
    if connector_slug in manifest.connectors:
        declared = True
    elif connector_slug in RESERVED_CONNECTORS:
        declared = True
    else:
        declared = False

    if not declared:
        return Decision(call, effect, BLOCK, f"connector {connector_slug} is not declared in kortix.yaml")
    if not reachable:
        where = "all" if grant == "all" else ("none" if grant == "none" else ", ".join(grant))
        return Decision(
            call,
            effect,
            BLOCK,
            f"agents.{agent}.connectors does not grant {connector_slug} (grant: {where})",
        )

    # 2. Project rules, first match wins.
    for index, rule in enumerate(manifest.policies, start=1):
        pattern, action = str(rule.get("match", "")), str(rule.get("action", ""))
        if not pattern:
            continue
        if _matches(pattern, call):
            held, error = conditions_hold(rule.get("conditions"), args)
            if error:
                return Decision(call, effect, UNDECIDED, f"project rule #{index}", error)
            if held:
                if action not in VALID_ACTIONS:
                    return Decision(
                        call,
                        effect,
                        UNDECIDED,
                        f"project rule #{index} ({pattern})",
                        f"unknown action {action!r}",
                    )
                return Decision(
                    call,
                    effect,
                    ALLOW if action == "always_run" else action,
                    f"project rule #{index} {pattern} -> {action}",
                )

    # 3. The connector's own policies, first match wins.
    connector = manifest.connectors.get(connector_slug)
    if connector is not None:
        for index, rule in enumerate(connector.policies, start=1):
            pattern, action = str(rule.get("match", "")), str(rule.get("action", ""))
            if not pattern:
                continue
            candidate = call if "." in pattern else tool
            if _matches(pattern, candidate):
                held, error = conditions_hold(rule.get("conditions"), args)
                if error:
                    return Decision(call, effect, UNDECIDED, f"connector rule #{index}", error)
                if held:
                    if action not in VALID_ACTIONS:
                        return Decision(
                            call,
                            effect,
                            UNDECIDED,
                            f"connector {connector_slug} rule #{index} ({pattern})",
                            f"unknown action {action!r}",
                        )
                    return Decision(
                        call,
                        effect,
                        ALLOW if action == "always_run" else action,
                        f"connector {connector_slug} rule #{index} {pattern} -> {action}",
                    )

        # 4. A connector marked sensitive holds every unmatched call.
        if connector.sensitive:
            return Decision(call, effect, APPROVE, f"connector {connector_slug} is sensitive: unmatched calls need approval")

    # 5. policy.default_mode.
    if manifest.default_mode == "allow_all":
        return Decision(call, effect, ALLOW, "policy.default_mode allow_all")
    if effect == "read":
        return Decision(call, effect, ALLOW, "policy.default_mode risk: a read runs")
    if effect in {"write", "destructive"}:
        return Decision(
            call,
            effect,
            APPROVE,
            f"policy.default_mode risk: a {effect} call needs approval",
        )
    return Decision(
        call,
        effect,
        UNDECIDED,
        "policy.default_mode risk",
        "declare the call's effect (read, write or destructive) to resolve it",
    )


# --------------------------------------------------------------------------- #
# calls input


@dataclass
class Call:
    path: str
    effect: str
    args: dict[str, Any]


def parse_call_line(line: str, origin: str) -> Call:
    text = line.strip()
    if not text or text.startswith("#"):
        raise AuditError(SKIP)
    args: dict[str, Any] = {}
    path, effect = text, "unknown"
    if "{" in text:
        head, _, tail = text.partition("{")
        try:
            parsed = json.loads("{" + tail)
        except json.JSONDecodeError as exc:
            raise AuditError(f"{origin}: arguments are not JSON: {text}") from exc
        if not isinstance(parsed, dict):
            raise AuditError(f"{origin}: arguments must be a JSON object: {text}")
        args = parsed
        text = head.strip()
        path = text
    if "=" in text:
        path, _, effect = text.partition("=")
        path, effect = path.strip(), effect.strip().lower()
    if not path:
        raise AuditError(f"{origin}: no call path in {line!r}")
    if effect not in EFFECTS | {"unknown"}:
        raise AuditError(f"{origin}: effect must be read, write or destructive, not {effect!r}")
    return Call(path=path, effect=effect, args=args)


def read_calls(path: Path) -> list[Call]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise AuditError(f"cannot read {path}: {exc}") from exc
    calls: list[Call] = []
    for index, line in enumerate(lines, start=1):
        try:
            calls.append(parse_call_line(line, f"{path}:{index}"))
        except AuditError as exc:
            if str(exc) == SKIP:
                continue
            raise
    return calls


# --------------------------------------------------------------------------- #
# output


def format_minutes(minutes: int) -> str:
    if minutes % 1440 == 0:
        return f"{minutes // 1440}d"
    if minutes % 60 == 0:
        return f"{minutes // 60}h"
    return f"{minutes}m"


def print_table(manifest: Manifest, decisions: list[Decision]) -> None:
    rows = [("call", "effect", "decision", "decided by")]
    for decision in decisions:
        by = decision.decided_by
        if decision.error:
            by = f"{by} — {decision.error}"
        if decision.action == APPROVE:
            by = f"{by} ({format_minutes(manifest.ttl_minutes)})"
        rows.append((decision.call, decision.effect, decision.action, by))
    widths = [max(len(row[column]) for row in rows) for column in range(3)]
    for row in rows:
        print(
            f"{row[0]:<{widths[0]}}  {row[1]:<{widths[1]}}  {row[2]:<{widths[2]}}  {row[3]}".rstrip()
        )


def print_agents(manifest: Manifest) -> None:
    print(f"{manifest.path} — kortix_version {manifest.version}, default_agent {manifest.default_agent}")
    print(f"policy.default_mode {manifest.default_mode} · approvals.ttl {format_minutes(manifest.ttl_minutes)} ({manifest.ttl_note})")
    print(f"connectors declared: {', '.join(sorted(manifest.connectors)) or 'none'}")
    for name, block in manifest.agents.items():
        grant = _grant(block.get("connectors"))
        reach = "all declared connectors" if grant == "all" else ("none" if grant == "none" else ", ".join(grant))
        secrets = _grant(block.get("secrets"))
        secret_text = "all" if secrets == "all" else ("none" if secrets == "none" else f"{len(secrets)} named")
        enabled = "" if block.get("enabled", True) else "  [enabled: false]"
        print(f"- {name}: connectors {reach}; secrets {secret_text}{enabled}")


# --------------------------------------------------------------------------- #
# main


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Resolve which Kortix connector calls run unattended, are held for a person, or are blocked."
    )
    parser.add_argument("manifest", type=Path, help="path to kortix.yaml")
    parser.add_argument("--agent", help="agent name (default: the manifest's default_agent)")
    parser.add_argument("--check", action="append", default=[], metavar="CONNECTOR.TOOL[=EFFECT]",
                        help="a call to resolve; repeatable")
    parser.add_argument("--calls", type=Path, help="file of calls: <connector>.<tool>[=effect] [JSON args]")
    parser.add_argument("--channel", choices=["slack", "teams", "email"],
                        help="the channel the session started from; its connector is always callable")
    parser.add_argument("--agents", action="store_true", help="print each agent's grants and exit")
    parser.add_argument("--json", action="store_true", help="print JSON instead of a table")
    return parser


def main(argv: Iterable[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)
    try:
        manifest = load_manifest(args.manifest)

        if args.agents:
            print_agents(manifest)
            return 0

        agent = args.agent or manifest.default_agent
        if not agent:
            raise AuditError("default_agent is missing; pass --agent")
        if agent not in manifest.agents:
            raise AuditError(f"agent {agent!r} is not declared (agents: {', '.join(manifest.agents)})")

        calls: list[Call] = [parse_call_line(item, "--check") for item in args.check]
        if args.calls:
            calls.extend(read_calls(args.calls))
        if not calls:
            raise AuditError("nothing to resolve: pass --check or --calls (or --agents for the grants)")

        decisions = [
            resolve(manifest, agent, call.path, call.effect, call.args, args.channel) for call in calls
        ]
    except AuditError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.json:
        print(
            json.dumps(
                {
                    "manifest": str(manifest.path),
                    "kortix_version": manifest.version,
                    "agent": agent,
                    "default_mode": manifest.default_mode,
                    "ttl_minutes": manifest.ttl_minutes,
                    "ttl_note": manifest.ttl_note,
                    "calls": [decision.as_dict(manifest.ttl_minutes) for decision in decisions],
                },
                indent=2,
            )
        )
    else:
        print_table(manifest, decisions)

    return 1 if any(decision.action == UNDECIDED for decision in decisions) else 0


if __name__ == "__main__":
    raise SystemExit(main())

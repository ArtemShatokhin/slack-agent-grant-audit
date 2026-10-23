"""Decision resolution, one behaviour at a time.

Each test writes a manifest into a temp directory and asserts the decision, the
rule that decided it and — where a call is held — the resolved TTL.
"""

from __future__ import annotations

import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import audit  # noqa: E402

BASE = """\
kortix_version: 2
default_agent: kortix
agents:
  kortix:
    file: agents/kortix.md
    connectors: {grant}
connectors:
{connectors}
{extra}
"""


class ManifestCase(unittest.TestCase):
    def manifest(self, grant="all", connectors="  - slug: gmail\n    provider: composio\n    app: gmail", extra=""):
        text = BASE.format(grant=grant, connectors=connectors, extra=extra)
        directory = tempfile.mkdtemp()
        path = Path(directory) / "kortix.yaml"
        path.write_text(textwrap.dedent(text), encoding="utf-8")
        return audit.load_manifest(path)

    def decide(self, manifest, call, effect="write", args=None, channel=None, agent="kortix"):
        return audit.resolve(manifest, agent, call, effect, args or {}, channel)


class DefaultMode(ManifestCase):
    def test_allow_all_is_the_default(self):
        manifest = self.manifest()
        decision = self.decide(manifest, "gmail.send_email")
        self.assertEqual(decision.action, audit.ALLOW)
        self.assertIn("allow_all", decision.decided_by)

    def test_risk_runs_a_read_and_holds_a_write(self):
        manifest = self.manifest(extra="policy:\n  default_mode: risk")
        self.assertEqual(self.decide(manifest, "gmail.search_threads", "read").action, audit.ALLOW)
        held = self.decide(manifest, "gmail.send_email", "write")
        self.assertEqual(held.action, audit.APPROVE)
        self.assertIn("risk", held.decided_by)

    def test_risk_holds_a_destructive_call(self):
        manifest = self.manifest(extra="policy:\n  default_mode: risk")
        self.assertEqual(self.decide(manifest, "gmail.delete_message", "destructive").action, audit.APPROVE)

    def test_risk_with_an_undeclared_effect_is_undecided(self):
        manifest = self.manifest(extra="policy:\n  default_mode: risk")
        decision = self.decide(manifest, "gmail.send_email", "unknown")
        self.assertEqual(decision.action, audit.UNDECIDED)
        self.assertIn("effect", decision.error)

    def test_an_unknown_default_mode_is_refused(self):
        with self.assertRaises(audit.AuditError):
            self.manifest(extra="policy:\n  default_mode: sometimes")


class ProjectRules(ManifestCase):
    def test_a_project_rule_beats_the_default(self):
        manifest = self.manifest(extra="policy:\n  default_mode: allow_all\npolicies:\n  - match: gmail.send_email\n    action: require_approval")
        decision = self.decide(manifest, "gmail.send_email")
        self.assertEqual(decision.action, audit.APPROVE)
        self.assertIn("project rule #1", decision.decided_by)

    def test_first_match_wins(self):
        manifest = self.manifest(
            extra=(
                "policies:\n"
                "  - match: gmail.send_email\n    action: block\n"
                "  - match: gmail.*\n    action: require_approval\n"
            )
        )
        self.assertEqual(self.decide(manifest, "gmail.send_email").action, audit.BLOCK)
        self.assertEqual(self.decide(manifest, "gmail.search_threads", "read").action, audit.APPROVE)

    def test_a_glob_matches_the_full_path(self):
        manifest = self.manifest(extra="policies:\n  - match: 'linear.*'\n    action: block")
        self.assertEqual(self.decide(manifest, "linear.create_issue").action, audit.BLOCK)
        self.assertEqual(self.decide(manifest, "gmail.send_email").action, audit.ALLOW)

    def test_a_regex_rule_is_read_from_slashes(self):
        manifest = self.manifest(extra="policies:\n  - match: '/^gmail\\.send_/'\n    action: block")
        self.assertEqual(self.decide(manifest, "gmail.send_email").action, audit.BLOCK)

    def test_a_rule_with_an_unknown_action_is_undecided(self):
        manifest = self.manifest(extra="policies:\n  - match: gmail.send_email\n    action: maybe")
        decision = self.decide(manifest, "gmail.send_email")
        self.assertEqual(decision.action, audit.UNDECIDED)
        self.assertIn("maybe", decision.error)


class Conditions(ManifestCase):
    EXTRA = (
        "policies:\n"
        "  - match: gmail.send_email\n    action: require_approval\n"
        "    conditions:\n      - arg: to\n        match: '*@example.com'\n"
    )

    def test_a_condition_holds_when_the_argument_matches(self):
        manifest = self.manifest(extra=self.EXTRA)
        decision = self.decide(manifest, "gmail.send_email", args={"to": "buyer@example.com"})
        self.assertEqual(decision.action, audit.APPROVE)

    def test_a_condition_that_does_not_hold_falls_through_to_the_next_rule(self):
        manifest = self.manifest(extra=self.EXTRA + "  - match: gmail.send_email\n    action: block\n")
        decision = self.decide(manifest, "gmail.send_email", args={"to": "buyer@other.test"})
        self.assertEqual(decision.action, audit.BLOCK)
        self.assertIn("project rule #2", decision.decided_by)

    def test_a_condition_on_a_missing_argument_does_not_hold(self):
        manifest = self.manifest(extra=self.EXTRA)
        decision = self.decide(manifest, "gmail.send_email", args={})
        self.assertEqual(decision.action, audit.ALLOW)

    def test_negate_inverts_a_condition(self):
        manifest = self.manifest(
            extra=(
                "policies:\n  - match: gmail.send_email\n    action: require_approval\n"
                "    conditions:\n      - arg: to\n        match: '*@kortix.com'\n        negate: true\n"
            )
        )
        self.assertEqual(self.decide(manifest, "gmail.send_email", args={"to": "a@other.test"}).action, audit.APPROVE)
        self.assertEqual(self.decide(manifest, "gmail.send_email", args={"to": "a@kortix.com"}).action, audit.ALLOW)

    def test_a_dotted_argument_path_is_followed(self):
        manifest = self.manifest(
            extra=(
                "policies:\n  - match: gmail.send_email\n    action: require_approval\n"
                "    conditions:\n      - arg: message.to\n        match: '*@bank.test'\n"
            )
        )
        decision = self.decide(manifest, "gmail.send_email", args={"message": {"to": "ops@bank.test"}})
        self.assertEqual(decision.action, audit.APPROVE)


class ConnectorRules(ManifestCase):
    def test_a_connector_rule_holds_a_write(self):
        manifest = self.manifest(
            connectors=(
                "  - slug: gmail\n    provider: composio\n    app: gmail\n"
                "    policies:\n      - match: send_*\n        action: require_approval\n"
            )
        )
        self.assertEqual(self.decide(manifest, "gmail.send_email").action, audit.APPROVE)
        self.assertEqual(self.decide(manifest, "gmail.search_threads", "read").action, audit.ALLOW)

    def test_a_project_rule_is_checked_before_the_connector_rule(self):
        manifest = self.manifest(
            connectors=(
                "  - slug: gmail\n    provider: composio\n    app: gmail\n"
                "    policies:\n      - match: '*'\n        action: always_run\n"
            ),
            extra="policies:\n  - match: gmail.send_email\n    action: block",
        )
        self.assertEqual(self.decide(manifest, "gmail.send_email").action, audit.BLOCK)

    def test_a_sensitive_connector_holds_an_unmatched_call(self):
        manifest = self.manifest(
            connectors="  - slug: gmail\n    provider: composio\n    app: gmail\n    sensitive: true"
        )
        decision = self.decide(manifest, "gmail.send_email")
        self.assertEqual(decision.action, audit.APPROVE)
        self.assertIn("sensitive", decision.decided_by)

    def test_a_sensitive_connector_still_lets_a_rule_decide(self):
        manifest = self.manifest(
            connectors=(
                "  - slug: gmail\n    provider: composio\n    app: gmail\n    sensitive: true\n"
                "    policies:\n      - match: search_*\n        action: always_run\n"
            )
        )
        self.assertEqual(self.decide(manifest, "gmail.search_threads", "read").action, audit.ALLOW)


class Grants(ManifestCase):
    def test_an_omitted_grant_reaches_no_connector(self):
        manifest = self.manifest(grant="none")
        decision = self.decide(manifest, "gmail.send_email")
        self.assertEqual(decision.action, audit.BLOCK)
        self.assertIn("does not grant", decision.decided_by)

    def test_a_list_grant_reaches_only_its_names(self):
        manifest = self.manifest(grant="[gmail]", connectors="  - slug: gmail\n    provider: composio\n    app: gmail\n  - slug: linear\n    provider: composio\n    app: linear")
        self.assertEqual(self.decide(manifest, "gmail.send_email").action, audit.ALLOW)
        self.assertEqual(self.decide(manifest, "linear.create_issue").action, audit.BLOCK)

    def test_all_with_a_star_is_the_same_as_all(self):
        manifest = self.manifest(grant="['*']")
        self.assertEqual(self.decide(manifest, "gmail.send_email").action, audit.ALLOW)

    def test_the_starting_channel_connector_is_always_callable(self):
        manifest = self.manifest(grant="none")
        decision = self.decide(manifest, "kortix_slack.post_message", channel="slack")
        self.assertEqual(decision.action, audit.ALLOW)
        # and it is not callable when the session did not start there
        self.assertEqual(self.decide(manifest, "kortix_slack.post_message").action, audit.BLOCK)

    def test_an_undeclared_connector_is_blocked(self):
        manifest = self.manifest()
        decision = self.decide(manifest, "stripe.create_charge", "destructive")
        self.assertEqual(decision.action, audit.BLOCK)
        self.assertIn("not declared", decision.decided_by)

    def test_a_call_without_a_connector_is_refused(self):
        manifest = self.manifest()
        with self.assertRaises(audit.AuditError):
            self.decide(manifest, "send_email")

    def test_an_unknown_agent_is_refused_at_resolve(self):
        manifest = self.manifest()
        with self.assertRaises(KeyError):
            self.decide(manifest, "gmail.send_email", agent="nobody")


class Ttl(ManifestCase):
    def test_absent_ttl_is_24h(self):
        self.assertEqual(audit.parse_ttl(None), (1440, "no approvals.ttl: 24h"))

    def test_hours_minutes_and_days(self):
        self.assertEqual(audit.parse_ttl("4h")[0], 240)
        self.assertEqual(audit.parse_ttl("30m")[0], 30)
        self.assertEqual(audit.parse_ttl("7d")[0], 10080)

    def test_a_malformed_ttl_falls_back_to_24h(self):
        self.assertEqual(audit.parse_ttl("4 hours")[0], 1440)
        self.assertEqual(audit.parse_ttl("soon")[0], 1440)

    def test_a_short_ttl_is_clamped_up_to_five_minutes(self):
        self.assertEqual(audit.parse_ttl("1m")[0], 5)

    def test_a_long_ttl_is_clamped_down_to_thirty_days(self):
        self.assertEqual(audit.parse_ttl("90d")[0], 43200)


class Calls(ManifestCase):
    def test_a_bare_path_is_an_unknown_effect(self):
        call = audit.parse_call_line("gmail.send_email", "test")
        self.assertEqual((call.path, call.effect, call.args), ("gmail.send_email", "unknown", {}))

    def test_an_effect_and_json_arguments_are_read(self):
        call = audit.parse_call_line('gmail.send_email=write {"to": "a@b.test"}', "test")
        self.assertEqual(call.effect, "write")
        self.assertEqual(call.args, {"to": "a@b.test"})

    def test_an_invalid_effect_is_refused(self):
        with self.assertRaises(audit.AuditError):
            audit.parse_call_line("gmail.send_email=loud", "test")

    def test_comments_and_blank_lines_are_skipped(self):
        path = Path(tempfile.mkdtemp()) / "calls.txt"
        path.write_text("# a comment\n\ngmail.send_email=write\n", encoding="utf-8")
        self.assertEqual([call.path for call in audit.read_calls(path)], ["gmail.send_email"])


class EndToEnd(ManifestCase):
    EXAMPLE = Path(__file__).resolve().parents[1] / "examples" / "slack-project"

    def test_the_example_project_resolves_as_documented(self):
        manifest = audit.load_manifest(self.EXAMPLE / "kortix.yaml")
        calls = audit.read_calls(self.EXAMPLE / "calls.txt")
        got = {
            (call.path, call.effect): audit.resolve(manifest, "kortix", call.path, call.effect, call.args, "slack")
            for call in calls
        }
        self.assertEqual(manifest.ttl_minutes, 240)
        expected = {
            ("kortix_slack.post_message", "write"): audit.APPROVE,
            ("gmail.search_threads", "read"): audit.ALLOW,
            ("gmail.send_email", "write"): audit.BLOCK,
            ("linear.list_issues", "read"): audit.ALLOW,
            ("linear.create_issue", "write"): audit.APPROVE,
            ("github.list_pull_requests", "read"): audit.ALLOW,
            ("github.merge_pr", "write"): audit.APPROVE,
            ("github.delete_repo", "destructive"): audit.BLOCK,
        }
        for key, action in expected.items():
            self.assertEqual(got[key].action, action, f"{key}: {got[key].decided_by}")

    def test_main_reports_an_undecided_call_with_exit_1(self):
        directory = Path(tempfile.mkdtemp())
        path = directory / "kortix.yaml"
        path.write_text(
            "kortix_version: 2\ndefault_agent: kortix\nagents:\n  kortix:\n    file: agents/kortix.md\n"
            "    connectors: all\nconnectors:\n  - slug: gmail\n    provider: composio\n    app: gmail\n"
            "policy:\n  default_mode: risk\n",
            encoding="utf-8",
        )
        self.assertEqual(audit.main([str(path), "--check", "gmail.send_email"]), 1)
        self.assertEqual(audit.main([str(path), "--check", "gmail.search_threads=read"]), 0)

    def test_main_reads_a_missing_manifest_as_exit_2(self):
        self.assertEqual(audit.main(["/nonexistent/kortix.yaml", "--agents"]), 2)


if __name__ == "__main__":
    unittest.main()

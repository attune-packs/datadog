from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import os
import sys
import unittest
from pathlib import Path
from types import ModuleType, SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from lib import datadog_client as datadog


class FakeResponse:
    def __init__(self, body=None, *, status=200, headers=None, chunks=None):
        self.status_code = status
        self.headers = headers or {}
        self.closed = False
        encoded = b"" if body is None else json.dumps(body, separators=(",", ":")).encode()
        self.chunks = list(chunks) if chunks is not None else [encoded]

    def iter_content(self, chunk_size):
        return iter(self.chunks)

    def close(self):
        self.closed = True


class FakeSession:
    def __init__(self, *responses):
        self.responses = list(responses)
        self.calls = []
        self.headers = {}
        self.trust_env = True

    def request(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


def make_client(*responses, **config):
    session = FakeSession(*responses)
    client = datadog.DatadogClient(
        {"api_key": "API_SECRET", "application_key": "APP_SECRET", **config},
        session=session,
        sleep=lambda _: None,
    )
    return client, session


class MetadataTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.actions = {}
        for path in sorted((ROOT / "actions").glob("*.yaml")):
            text = path.read_text(encoding="utf-8")
            ref = next(line.split(":", 1)[1].strip() for line in text.splitlines() if line.startswith("ref:"))
            cls.actions[ref.removeprefix("datadog.")] = text

    def test_curated_action_inventory_matches_dispatch(self):
        self.assertEqual(24, len(self.actions))
        self.assertEqual(set(datadog.OPERATIONS), set(self.actions))
        self.assertEqual(
            {
                "monitor_list", "monitor_get", "monitor_create", "monitor_update", "monitor_delete",
                "monitor_mute", "monitor_unmute", "downtime_schedule", "downtime_list", "downtime_get",
                "downtime_cancel", "event_post", "event_list", "metric_submit", "metric_query", "host_list",
                "host_mute", "host_unmute", "tag_list_hosts", "tag_get_host", "tag_add_host",
                "tag_update_host", "tag_delete_host", "service_check_submit",
            },
            set(self.actions),
        )

    def test_all_actions_use_flat_stdin_json_and_structured_output(self):
        required_lines = (
            "enabled: true\n",
            "runner_type: python\n",
            'runtime_version: ">=3.10"\n',
            "entry_point: datadog_action.py\n",
            "parameter_delivery: stdin\n",
            "parameter_format: json\n",
            "output_format: json\n",
            "default_execution_permission_set_refs: [standard]\n",
            'credential_key: {type: string, default: "datadog.credentials", required: true',
            "operation: {type: string, required: true}\n",
            "result: {type: object, required: true}\n",
        )
        for name, text in self.actions.items():
            with self.subTest(action=name):
                self.assertIn(f"ref: datadog.{name}\n", text)
                for line in required_lines:
                    self.assertIn(line, text)

    def test_collection_limits_and_mutation_contracts_are_declared(self):
        for name in ("monitor_list", "downtime_list", "event_list", "host_list"):
            self.assertIn("max_results: {type: integer, default: 100, minimum: 1, maximum: 1000", self.actions[name])
        self.assertIn("downtime_id: {type: string, required: true", self.actions["monitor_unmute"])
        self.assertIn("from: {type: integer, required: true", self.actions["metric_query"])
        self.assertIn("checks: {type: array, required: true", self.actions["service_check_submit"])

    def test_pack_records_exact_upstream_and_current_review_metadata(self):
        pack = (ROOT / "pack.yaml").read_text(encoding="utf-8")
        self.assertIn('source_version: "1.0.2"', pack)
        revision = "8ade8fd35cdd30f124206425abfa8738438bd3bc"
        self.assertIn(f'source_revision: "{revision}"', pack)
        self.assertIn('license: "Apache-2.0"', pack)
        self.assertIn('api_review_date: "2026-08-14"', pack)
        notice = (ROOT / "NOTICE").read_text(encoding="utf-8")
        self.assertIn(revision, notice)
        self.assertIn("Apache License 2.0", notice)

    def test_license_matches_upstream_apache_text(self):
        digest = hashlib.sha256((ROOT / "LICENSE").read_bytes()).hexdigest()
        self.assertEqual("b40930bbcf80744c86c46a12bc9da056641d722716c378f5659b9e555ef833e1", digest)

    def test_retired_resources_are_not_actions_or_client_paths(self):
        names = " ".join(self.actions)
        source = (ROOT / "lib" / "datadog_client.py").read_text(encoding="utf-8")
        for retired in ("screenboard", "timeboard", "embed"):
            self.assertNotIn(retired, names)
            self.assertNotIn(f"/{retired}", source)
        self.assertNotIn("mute_all", names)
        self.assertNotIn("unmute_all", names)

    def test_readme_lists_every_action_and_live_gaps(self):
        text = (ROOT / "README.md").read_text(encoding="utf-8")
        for name in self.actions:
            self.assertIn(f"`datadog.{name}`", text)
        for phrase in ("Current API Gaps", "private beta", "change", "alert", "no live Datadog credentials"):
            self.assertIn(phrase, text)

    def test_test_dependencies_are_declared(self):
        requirements = (ROOT / "requirements.txt").read_text(encoding="utf-8")
        self.assertIn("requests", requirements)
        self.assertIn("attune-sdk", requirements)


class ClientSecurityTests(unittest.TestCase):
    def test_site_policy_maps_every_documented_site_to_exact_hosts(self):
        self.assertEqual(9, len(datadog.SITE_HOSTS))
        for site, (api_host, intake_host) in datadog.SITE_HOSTS.items():
            with self.subTest(site=site):
                client, _ = make_client(site=site)
                self.assertEqual(f"https://{api_host}", client.api_base)
                self.assertEqual(f"https://{intake_host}", client.intake_base)
                self.assertNotIn("/", api_host)
                self.assertNotIn("@", api_host)

    def test_unsafe_sites_and_unbounded_settings_are_rejected(self):
        invalid = [
            {"site": "https://api.datadoghq.com"},
            {"site": "datadoghq.com.evil.invalid"},
            {"site": "localhost"},
            {"site": ["datadoghq.com"]},
            {"timeout_seconds": 0},
            {"timeout_seconds": 61},
            {"max_response_bytes": 100},
            {"max_response_bytes": 20_000_000},
            {"read_rate_limit_retries": 4},
            {"max_retry_wait_seconds": 11},
        ]
        for extra in invalid:
            with self.subTest(extra=extra), self.assertRaises(datadog.DatadogPackError):
                make_client(**extra)
        with self.assertRaises(datadog.DatadogPackError):
            datadog.DatadogClient({"api_key": "x"}, session=FakeSession())

    def test_transport_forces_tls_no_redirects_no_environment_and_bounded_streaming(self):
        response = FakeResponse({"id": 1})
        client, session = make_client(response, site="datadoghq.eu", timeout_seconds=12)
        self.assertEqual({"id": 1}, client.request("GET", "/api/v1/monitor/1"))
        method, url, kwargs = session.calls[0]
        self.assertEqual((method, url), ("GET", "https://api.datadoghq.eu/api/v1/monitor/1"))
        self.assertEqual((10.0, 12.0), kwargs["timeout"])
        self.assertTrue(kwargs["verify"])
        self.assertFalse(kwargs["allow_redirects"])
        self.assertTrue(kwargs["stream"])
        self.assertFalse(session.trust_env)
        self.assertEqual("API_SECRET", session.headers["DD-API-KEY"])
        self.assertEqual("APP_SECRET", session.headers["DD-APPLICATION-KEY"])
        self.assertTrue(response.closed)

    def test_internal_paths_cannot_override_destination(self):
        client, session = make_client()
        for path in ("https://evil.invalid/api/v1/hosts", "//evil.invalid/api/v1/hosts", "/api/v1/hosts?x=1"):
            with self.subTest(path=path), self.assertRaises(datadog.DatadogPackError):
                client.request("GET", path)
        self.assertEqual([], session.calls)

    def test_response_limits_close_content_length_and_stream_overflow(self):
        declared = FakeResponse({}, headers={"Content-Length": "2048"})
        client, _ = make_client(declared, max_response_bytes=1024)
        with self.assertRaisesRegex(datadog.DatadogPackError, "max_response_bytes"):
            client.request("GET", "/api/v1/hosts")
        self.assertTrue(declared.closed)

        streamed = FakeResponse(chunks=[b"x" * 700, b"y" * 700])
        client, _ = make_client(streamed, max_response_bytes=1024)
        with self.assertRaisesRegex(datadog.DatadogPackError, "max_response_bytes"):
            client.request("GET", "/api/v1/hosts")
        self.assertTrue(streamed.closed)

    def test_http_and_transport_errors_redact_keys_url_and_response_body(self):
        response = FakeResponse({"errors": ["SECRET_BODY"]}, status=403)
        client, _ = make_client(response)
        with self.assertRaises(datadog.DatadogPackError) as raised:
            client.request("GET", "/api/v1/monitor/1")
        message = str(raised.exception)
        self.assertEqual("Datadog request failed with HTTP status 403", message)
        self.assertNotIn("SECRET", message)
        self.assertNotIn("datadoghq", message)
        self.assertTrue(response.closed)

        client, _ = make_client(RuntimeError("API_SECRET APP_SECRET response body"))
        with self.assertRaisesRegex(datadog.DatadogPackError, "request failed") as transport:
            client.request("GET", "/api/v1/hosts")
        self.assertNotIn("SECRET", str(transport.exception))

    def test_rate_limit_retry_is_bounded_and_get_only(self):
        first = FakeResponse({"errors": ["limited"]}, status=429, headers={"X-RateLimit-Reset": "3"})
        second = FakeResponse({"ok": True})
        session = FakeSession(first, second)
        waits = []
        client = datadog.DatadogClient(
            {"api_key": "x", "application_key": "y", "read_rate_limit_retries": 1},
            session=session,
            sleep=waits.append,
        )
        self.assertEqual({"ok": True}, client.request("GET", "/api/v1/hosts"))
        self.assertEqual([3.0], waits)
        self.assertEqual(2, len(session.calls))
        self.assertTrue(first.closed)

        mutation = FakeResponse({"errors": ["limited"]}, status=429)
        client, session = make_client(mutation, read_rate_limit_retries=3)
        with self.assertRaisesRegex(datadog.DatadogPackError, "429"):
            client.request("POST", "/api/v1/monitor", body={"name": "x"})
        self.assertEqual(1, len(session.calls))


class OperationTests(unittest.TestCase):
    def test_monitor_pagination_and_filters_are_v1(self):
        first = [{"id": value} for value in range(100)]
        second = [{"id": 100}, {"id": 101}]
        client, session = make_client(FakeResponse(first), FakeResponse(second))
        result = datadog.monitor_list(client, {"max_results": 101, "group_states": "alert,warn", "with_downtimes": True})
        self.assertEqual(101, result["count"])
        self.assertTrue(result["truncated"])
        self.assertEqual("/api/v1/monitor", session.calls[0][1].removeprefix(client.api_base))
        self.assertIn(("page", 1), session.calls[1][2]["params"])
        self.assertIn(("page_size", 2), session.calls[1][2]["params"])
        self.assertIn(("group_states", "alert,warn"), session.calls[0][2]["params"])

    def test_monitor_mutations_use_v1_once_and_force_is_string(self):
        client, session = make_client(FakeResponse({"id": 7}), FakeResponse({"deleted_monitor_id": 7}))
        created = datadog.monitor_create(client, {"body": {"name": "Test", "type": "query alert", "query": "x"}})
        deleted = datadog.monitor_delete(client, {"monitor_id": 7, "force": True})
        self.assertEqual(7, created["id"])
        self.assertEqual({"deleted": True, "monitor_id": 7}, deleted)
        self.assertEqual(("POST", client.api_base + "/api/v1/monitor"), session.calls[0][:2])
        self.assertEqual([("force", "true")], session.calls[1][2]["params"])
        self.assertEqual(2, len(session.calls))

    def test_monitor_mute_and_unmute_use_v2_downtime(self):
        response = {"data": {"type": "downtime", "id": "uuid-1"}}
        client, session = make_client(FakeResponse(response), FakeResponse(status=204))
        result = datadog.monitor_mute(
            client,
            {"monitor_id": 42, "scope": "env:prod", "message": "Deploy", "schedule": {"start": "now"}},
        )
        unmuted = datadog.monitor_unmute(client, {"downtime_id": "uuid-1"})
        self.assertEqual("uuid-1", result["data"]["id"])
        body = session.calls[0][2]["json"]
        self.assertEqual("downtime", body["data"]["type"])
        self.assertEqual({"monitor_id": 42}, body["data"]["attributes"]["monitor_identifier"])
        self.assertEqual("env:prod", body["data"]["attributes"]["scope"])
        self.assertEqual(("DELETE", client.api_base + "/api/v2/downtime/uuid-1"), session.calls[1][:2])
        self.assertEqual({"unmuted": True, "downtime_id": "uuid-1"}, unmuted)

    def test_downtime_pagination_uses_current_v2_parameters(self):
        first = {"data": [{"id": str(value)} for value in range(100)]}
        second = {"data": [{"id": "100"}, {"id": "101"}]}
        client, session = make_client(FakeResponse(first), FakeResponse(second))
        result = datadog.downtime_list(client, {"max_results": 101, "current_only": True, "include": "monitor"})
        self.assertEqual(101, result["count"])
        params = session.calls[0][2]["params"]
        self.assertIn(("current_only", True), params)
        self.assertNotIn(("filter[current_only]", True), params)
        self.assertIn(("page[offset]", 100), session.calls[1][2]["params"])
        self.assertTrue(all(call[1].endswith("/api/v2/downtime") for call in session.calls))

    def test_event_post_uses_intake_and_event_list_follows_cursor(self):
        client, session = make_client(
            FakeResponse({"data": {"id": "event-1"}}),
            FakeResponse({"data": [{"id": "one"}], "meta": {"page": {"after": "cursor-2"}}}),
            FakeResponse({"data": [{"id": "two"}], "meta": {"page": {}}}),
            site="us3.datadoghq.com",
        )
        posted = datadog.event_post(client, {"body": {"data": {"type": "event", "attributes": {"category": "change"}}}})
        listed = datadog.event_list(client, {"max_results": 2, "query": "service:web"})
        self.assertEqual("event-1", posted["data"]["id"])
        self.assertEqual("https://event-management-intake.us3.datadoghq.com/api/v2/events", session.calls[0][1])
        self.assertEqual("https://api.us3.datadoghq.com/api/v2/events", session.calls[1][1])
        self.assertIn(("page[cursor]", "cursor-2"), session.calls[2][2]["params"])
        self.assertEqual(["one", "two"], [item["id"] for item in listed["items"]])
        self.assertFalse(listed["truncated"])

    def test_metric_submit_is_v2_and_query_is_current_v1(self):
        client, session = make_client(FakeResponse({"errors": []}), FakeResponse({"series": []}))
        series = [{"metric": "example.value", "type": 3, "points": [{"timestamp": 1, "value": 2}]}]
        self.assertEqual({"errors": []}, datadog.metric_submit(client, {"series": series}))
        self.assertEqual({"series": []}, datadog.metric_query(client, {"from": 1, "to": 2, "query": "avg:example.value{*}"}))
        self.assertEqual("/api/v2/series", session.calls[0][1].removeprefix(client.api_base))
        self.assertEqual({"series": series}, session.calls[0][2]["json"])
        self.assertEqual("/api/v1/query", session.calls[1][1].removeprefix(client.api_base))
        self.assertEqual([("from", 1), ("to", 2), ("query", "avg:example.value{*}")], session.calls[1][2]["params"])

    def test_host_pagination_preserves_total_and_encodes_host_paths(self):
        first = {"host_list": [{"name": str(value)} for value in range(100)], "total_matching": 102}
        second = {"host_list": [{"name": "100"}, {"name": "101"}], "total_matching": 102}
        client, session = make_client(FakeResponse(first), FakeResponse(second), FakeResponse({"action": "muted"}))
        result = datadog.host_list(client, {"max_results": 101, "filter": "env:prod"})
        muted = datadog.host_mute(client, {"host_name": "web/one", "message": "work", "override": False})
        self.assertEqual((101, 102, True), (result["count"], result["total_matching"], result["truncated"]))
        self.assertIn(("start", 100), session.calls[1][2]["params"])
        self.assertTrue(session.calls[2][1].endswith("/api/v1/host/web%2Fone/mute"))
        self.assertEqual({"message": "work", "override": False}, session.calls[2][2]["json"])
        self.assertEqual("muted", muted["action"])

    def test_tag_operations_and_service_checks_use_current_v1_contracts(self):
        client, session = make_client(
            FakeResponse({"tags": ["env:test"]}),
            FakeResponse({"tags": ["env:test"]}),
            FakeResponse({"status": "ok"}),
        )
        got = datadog.tag_get_host(client, {"host_name": "db/one", "source": "users"})
        updated = datadog.tag_update_host(client, {"host_name": "db/one", "source": "users", "tags": ["env:test"]})
        checks = [{"check": "app.ready", "host_name": "db-one", "status": 0}]
        submitted = datadog.service_check_submit(client, {"checks": checks})
        self.assertEqual(["env:test"], got["tags"])
        self.assertTrue(session.calls[0][1].endswith("/api/v1/tags/hosts/db%2Fone"))
        self.assertEqual({"tags": ["env:test"]}, session.calls[1][2]["json"])
        self.assertEqual(("POST", client.api_base + "/api/v1/check_run"), session.calls[2][:2])
        self.assertEqual(checks, session.calls[2][2]["json"])
        self.assertEqual("ok", submitted["status"])
        self.assertEqual(["env:test"], updated["tags"])

    def test_validation_rejects_bad_identifiers_arrays_and_times(self):
        client, session = make_client()
        cases = [
            (datadog.monitor_get, {"monitor_id": ""}),
            (datadog.tag_get_host, {"host_name": ".."}),
            (datadog.metric_submit, {"series": []}),
            (datadog.metric_query, {"from": "1", "to": 2, "query": "x"}),
            (datadog.tag_add_host, {"host_name": "h", "tags": [""]}),
            (datadog.monitor_mute, {"monitor_id": True}),
        ]
        for function, params in cases:
            with self.subTest(function=function.__name__), self.assertRaises(datadog.DatadogPackError):
                function(client, params)
        self.assertEqual([], session.calls)


class AttuneAndEntrypointTests(unittest.TestCase):
    def test_fetch_key_requests_decryption_and_accepts_json_string(self):
        calls = {}
        get_key = ModuleType("attune.api_client.api.secrets.get_key")
        get_key.sync_detailed = lambda ref, *, client, decrypt: calls.update(
            ref=ref, client=client, decrypt=decrypt
        ) or SimpleNamespace(
            status_code=200,
            parsed=SimpleNamespace(data=SimpleNamespace(value='{"api_key":"x","application_key":"y"}')),
        )
        secrets = ModuleType("attune.api_client.api.secrets")
        secrets.get_key = get_key
        attune = ModuleType("attune")
        attune.context = SimpleNamespace(client="execution-client")
        modules = {
            "attune": attune,
            "attune.api_client": ModuleType("attune.api_client"),
            "attune.api_client.api": ModuleType("attune.api_client.api"),
            "attune.api_client.api.secrets": secrets,
        }
        with patch.dict(sys.modules, modules):
            value = datadog._fetch_key("datadog.credentials")
        self.assertEqual({"api_key": "x", "application_key": "y"}, value)
        self.assertEqual({"ref": "datadog.credentials", "client": "execution-client", "decrypt": True}, calls)

    def test_execute_action_uses_default_pack_key(self):
        with patch.object(datadog, "_fetch_key", return_value={"api_key": "x", "application_key": "y"}) as fetch, patch.object(
            datadog, "DatadogClient", return_value="client"
        ), patch.dict(datadog.OPERATIONS, {"monitor_get": lambda client, params: {"id": params["monitor_id"]}}):
            result = datadog.execute_action("monitor_get", {"monitor_id": 9})
        self.assertEqual({"id": 9}, result)
        fetch.assert_called_once_with("datadog.credentials")

    def test_entrypoint_success_and_secret_redaction(self):
        spec = importlib.util.spec_from_file_location("datadog_action_test", ROOT / "actions" / "datadog_action.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        stdout, stderr = io.StringIO(), io.StringIO()
        with patch.dict(os.environ, {"ATTUNE_ACTION": "datadog.monitor_get"}), patch.object(
            module, "execute_action", return_value={"id": 1}
        ), patch.object(sys, "stdin", io.StringIO('{"monitor_id":1}')), patch.object(sys, "stdout", stdout), patch.object(sys, "stderr", stderr):
            self.assertEqual(0, module.main())
        self.assertEqual({"operation": "monitor_get", "result": {"id": 1}}, json.loads(stdout.getvalue()))
        self.assertEqual("", stderr.getvalue())

        stdout, stderr = io.StringIO(), io.StringIO()
        with patch.object(module, "execute_action", side_effect=RuntimeError("API_SECRET APP_SECRET body")), patch.object(
            sys, "stdin", io.StringIO("{}")
        ), patch.object(sys, "stdout", stdout), patch.object(sys, "stderr", stderr):
            self.assertEqual(1, module.main())
        self.assertEqual("", stdout.getvalue())
        self.assertIn("RuntimeError", stderr.getvalue())
        self.assertNotIn("SECRET", stderr.getvalue())

    def test_entrypoint_rejects_non_object_and_malformed_input_without_echo(self):
        spec = importlib.util.spec_from_file_location("datadog_action_input_test", ROOT / "actions" / "datadog_action.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        for raw in ("[]", '{"api_key":"SECRET"'):
            stdout, stderr = io.StringIO(), io.StringIO()
            with patch.object(sys, "stdin", io.StringIO(raw)), patch.object(sys, "stdout", stdout), patch.object(sys, "stderr", stderr):
                self.assertEqual(1, module.main())
            self.assertEqual("", stdout.getvalue())
            self.assertNotIn("SECRET", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()

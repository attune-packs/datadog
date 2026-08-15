"""Hardened REST client and operations for the Datadog Attune pack."""

from __future__ import annotations

import json
import math
import time
from collections.abc import Callable, Mapping, Sequence
from typing import Any
from urllib.parse import quote


class DatadogPackError(RuntimeError):
    """An operator-facing error that is safe to print."""


SITE_HOSTS = {
    "datadoghq.com": ("api.datadoghq.com", "event-management-intake.datadoghq.com"),
    "us3.datadoghq.com": ("api.us3.datadoghq.com", "event-management-intake.us3.datadoghq.com"),
    "us5.datadoghq.com": ("api.us5.datadoghq.com", "event-management-intake.us5.datadoghq.com"),
    "datadoghq.eu": ("api.datadoghq.eu", "event-management-intake.datadoghq.eu"),
    "ddog-gov.com": ("api.ddog-gov.com", "event-management-intake.ddog-gov.com"),
    "us2.ddog-gov.com": ("api.us2.ddog-gov.com", "event-management-intake.us2.ddog-gov.com"),
    "ap1.datadoghq.com": ("api.ap1.datadoghq.com", "event-management-intake.ap1.datadoghq.com"),
    "ap2.datadoghq.com": ("api.ap2.datadoghq.com", "event-management-intake.ap2.datadoghq.com"),
    "uk1.datadoghq.com": ("api.uk1.datadoghq.com", "event-management-intake.uk1.datadoghq.com"),
}


def _number(config: Mapping[str, Any], name: str, default: float, low: float, high: float) -> float:
    value = config.get(name, default)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise DatadogPackError(f"{name} must be a number")
    result = float(value)
    if not math.isfinite(result) or not low <= result <= high:
        raise DatadogPackError(f"{name} must be between {low:g} and {high:g}")
    return result


def _integer(params: Mapping[str, Any], name: str, default: int, low: int, high: int) -> int:
    value = params.get(name, default)
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        raise DatadogPackError(f"{name} must be an integer between {low} and {high}")
    return value


def _required_string(params: Mapping[str, Any], name: str) -> str:
    value = params.get(name)
    if not isinstance(value, str) or not value.strip():
        raise DatadogPackError(f"{name} must be a non-empty string")
    return value


def _required_object(params: Mapping[str, Any], name: str) -> dict[str, Any]:
    value = params.get(name)
    if not isinstance(value, dict):
        raise DatadogPackError(f"{name} must be an object")
    return dict(value)


def _required_array(params: Mapping[str, Any], name: str) -> list[Any]:
    value = params.get(name)
    if not isinstance(value, list) or not value:
        raise DatadogPackError(f"{name} must be a non-empty array")
    return list(value)


def _identifier(params: Mapping[str, Any], name: str) -> str:
    value = params.get(name)
    if isinstance(value, bool) or not isinstance(value, (str, int)) or not str(value) or str(value) in {".", ".."}:
        raise DatadogPackError(f"{name} must be a non-empty string or integer")
    return quote(str(value), safe="")


def _fetch_key(ref: str) -> dict[str, Any]:
    if not isinstance(ref, str) or not ref.strip():
        raise DatadogPackError("credential_key must be a non-empty string")
    try:
        import attune
        from attune.api_client.api.secrets import get_key
    except ImportError as exc:
        raise DatadogPackError("attune-sdk is required to resolve credential_key") from exc
    try:
        response = get_key.sync_detailed(ref, client=attune.context.client, decrypt=True)
    except Exception as exc:
        raise DatadogPackError(f"unable to read credential Key {ref!r}") from exc
    status = int(response.status_code)
    if status == 404:
        raise DatadogPackError(f"credential Key {ref!r} was not found")
    if status >= 400 or not response.parsed:
        raise DatadogPackError(f"credential Key lookup failed with status {status}")
    value = response.parsed.data.value
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except json.JSONDecodeError as exc:
            raise DatadogPackError("credential Key must contain a JSON object") from exc
    if not isinstance(value, dict):
        raise DatadogPackError("credential Key must contain an object")
    return value


class DatadogClient:
    """Small current Datadog v1/v2 client with a fixed destination policy."""

    def __init__(
        self,
        config: Mapping[str, Any],
        *,
        session: Any = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        api_key = config.get("api_key")
        application_key = config.get("application_key")
        if not isinstance(api_key, str) or not api_key:
            raise DatadogPackError("credential Key requires api_key")
        if not isinstance(application_key, str) or not application_key:
            raise DatadogPackError("credential Key requires application_key")
        site = config.get("site", "datadoghq.com")
        if not isinstance(site, str) or site not in SITE_HOSTS:
            raise DatadogPackError("site must be a supported Datadog site parameter")
        timeout = _number(config, "timeout_seconds", 30, 1, 60)
        self.timeout = (min(10.0, timeout), timeout)
        self.max_response_bytes = int(_number(config, "max_response_bytes", 2_097_152, 1024, 10_485_760))
        retries = config.get("read_rate_limit_retries", 2)
        if isinstance(retries, bool) or not isinstance(retries, int) or not 0 <= retries <= 3:
            raise DatadogPackError("read_rate_limit_retries must be an integer between 0 and 3")
        self.read_rate_limit_retries = retries
        self.max_retry_wait = _number(config, "max_retry_wait_seconds", 5, 0, 10)
        self.api_base = f"https://{SITE_HOSTS[site][0]}"
        self.intake_base = f"https://{SITE_HOSTS[site][1]}"
        if session is None:
            import requests

            session = requests.Session()
        self.session = session
        self.session.trust_env = False
        self.session.headers.update(
            {
                "Accept": "application/json",
                "Content-Type": "application/json",
                "DD-API-KEY": api_key,
                "DD-APPLICATION-KEY": application_key,
                "User-Agent": "attune-datadog/0.1.0",
            }
        )
        self.sleep = sleep

    def _retry_delay(self, headers: Mapping[str, Any]) -> float:
        for name in ("Retry-After", "X-RateLimit-Reset"):
            if headers.get(name) is None:
                continue
            try:
                return min(max(0.0, float(headers[name])), self.max_retry_wait)
            except (TypeError, ValueError):
                continue
        return 0.0

    def _decode(self, response: Any) -> Any:
        if response.status_code == 204:
            response.close()
            return None
        length = response.headers.get("Content-Length")
        try:
            if length is not None and int(length) > self.max_response_bytes:
                response.close()
                raise DatadogPackError("Datadog response exceeds max_response_bytes")
        except ValueError:
            pass
        chunks: list[bytes] = []
        size = 0
        try:
            for chunk in response.iter_content(chunk_size=65_536):
                if not chunk:
                    continue
                size += len(chunk)
                if size > self.max_response_bytes:
                    raise DatadogPackError("Datadog response exceeds max_response_bytes")
                chunks.append(chunk)
        finally:
            response.close()
        if not chunks:
            return None
        try:
            value = json.loads(b"".join(chunks))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise DatadogPackError("Datadog returned invalid JSON") from exc
        if not isinstance(value, (dict, list)):
            raise DatadogPackError("Datadog returned an invalid JSON document")
        return value

    def request(
        self,
        method: str,
        path: str,
        *,
        params: Sequence[tuple[str, Any]] | None = None,
        body: Any = None,
        intake: bool = False,
    ) -> Any:
        if not path.startswith("/api/") or "?" in path or "#" in path:
            raise DatadogPackError("invalid internal Datadog API path")
        method = method.upper()
        url = (self.intake_base if intake else self.api_base) + path
        attempts = 1 + (self.read_rate_limit_retries if method == "GET" else 0)
        for attempt in range(attempts):
            try:
                response = self.session.request(
                    method,
                    url,
                    params=params,
                    json=body,
                    timeout=self.timeout,
                    verify=True,
                    allow_redirects=False,
                    stream=True,
                )
            except Exception as exc:
                raise DatadogPackError("Datadog request failed") from exc
            if response.status_code == 429 and method == "GET" and attempt + 1 < attempts:
                delay = self._retry_delay(response.headers)
                response.close()
                self.sleep(delay)
                continue
            if not 200 <= response.status_code < 300:
                status = response.status_code
                response.close()
                raise DatadogPackError(f"Datadog request failed with HTTP status {status}")
            return self._decode(response)
        raise DatadogPackError("Datadog read remained rate limited")


def _query(params: Mapping[str, Any], names: Sequence[str]) -> list[tuple[str, Any]]:
    result: list[tuple[str, Any]] = []
    for name in names:
        value = params.get(name)
        if value is None:
            continue
        if isinstance(value, list):
            result.extend((name, item) for item in value)
        else:
            result.append((name, value))
    return result


def _collection(items: list[Any], maximum: int, *, next_cursor: str | None = None) -> dict[str, Any]:
    truncated = len(items) > maximum or next_cursor is not None
    result: dict[str, Any] = {"items": items[:maximum], "count": min(len(items), maximum), "truncated": truncated}
    if next_cursor is not None:
        result["next_cursor"] = next_cursor
    return result


def monitor_list(client: DatadogClient, params: Mapping[str, Any]) -> dict[str, Any]:
    maximum = _integer(params, "max_results", 100, 1, 1000)
    base = _query(params, ("group_states", "name", "tags", "monitor_tags", "with_downtimes"))
    items: list[Any] = []
    page = 0
    while len(items) <= maximum:
        size = min(100, maximum + 1 - len(items))
        value = client.request("GET", "/api/v1/monitor", params=base + [("page", page), ("page_size", size)])
        if not isinstance(value, list):
            raise DatadogPackError("Datadog monitor list response is invalid")
        items.extend(value)
        if len(value) < size:
            break
        page += 1
    return _collection(items, maximum)


def monitor_get(client: DatadogClient, params: Mapping[str, Any]) -> dict[str, Any]:
    query = _query(params, ("group_states", "with_downtimes"))
    value = client.request("GET", f"/api/v1/monitor/{_identifier(params, 'monitor_id')}", params=query)
    if not isinstance(value, dict):
        raise DatadogPackError("Datadog monitor response is invalid")
    return value


def monitor_create(client: DatadogClient, params: Mapping[str, Any]) -> dict[str, Any]:
    value = client.request("POST", "/api/v1/monitor", body=_required_object(params, "body"))
    return value if isinstance(value, dict) else {"accepted": True}


def monitor_update(client: DatadogClient, params: Mapping[str, Any]) -> dict[str, Any]:
    path = f"/api/v1/monitor/{_identifier(params, 'monitor_id')}"
    value = client.request("PUT", path, body=_required_object(params, "body"))
    return value if isinstance(value, dict) else {"updated": True}


def monitor_delete(client: DatadogClient, params: Mapping[str, Any]) -> dict[str, Any]:
    query = [("force", "true" if params["force"] else "false")] if params.get("force") is not None else None
    client.request("DELETE", f"/api/v1/monitor/{_identifier(params, 'monitor_id')}", params=query)
    return {"deleted": True, "monitor_id": params["monitor_id"]}


def monitor_mute(client: DatadogClient, params: Mapping[str, Any]) -> dict[str, Any]:
    monitor_id = params.get("monitor_id")
    if isinstance(monitor_id, bool) or not isinstance(monitor_id, int) or monitor_id < 1:
        raise DatadogPackError("monitor_id must be a positive integer")
    attributes: dict[str, Any] = {
        "monitor_identifier": {"monitor_id": monitor_id},
        "scope": params.get("scope", "*"),
    }
    if not isinstance(attributes["scope"], str) or not attributes["scope"]:
        raise DatadogPackError("scope must be a non-empty string")
    for name in ("message", "schedule"):
        if params.get(name) is not None:
            attributes[name] = params[name]
    body = {"data": {"type": "downtime", "attributes": attributes}}
    value = client.request("POST", "/api/v2/downtime", body=body)
    if not isinstance(value, dict):
        raise DatadogPackError("Datadog downtime response is invalid")
    return value


def monitor_unmute(client: DatadogClient, params: Mapping[str, Any]) -> dict[str, Any]:
    client.request("DELETE", f"/api/v2/downtime/{_identifier(params, 'downtime_id')}")
    return {"unmuted": True, "downtime_id": params["downtime_id"]}


def downtime_schedule(client: DatadogClient, params: Mapping[str, Any]) -> dict[str, Any]:
    value = client.request("POST", "/api/v2/downtime", body=_required_object(params, "body"))
    if not isinstance(value, dict):
        raise DatadogPackError("Datadog downtime response is invalid")
    return value


def downtime_list(client: DatadogClient, params: Mapping[str, Any]) -> dict[str, Any]:
    maximum = _integer(params, "max_results", 100, 1, 1000)
    base: list[tuple[str, Any]] = []
    if params.get("current_only") is not None:
        base.append(("current_only", params["current_only"]))
    if params.get("include") is not None:
        base.append(("include", params["include"]))
    items: list[Any] = []
    offset = 0
    while len(items) <= maximum:
        size = min(100, maximum + 1 - len(items))
        value = client.request("GET", "/api/v2/downtime", params=base + [("page[offset]", offset), ("page[limit]", size)])
        page = value.get("data") if isinstance(value, dict) else None
        if not isinstance(page, list):
            raise DatadogPackError("Datadog downtime list response is invalid")
        items.extend(page)
        if len(page) < size:
            break
        offset += len(page)
    return _collection(items, maximum)


def downtime_get(client: DatadogClient, params: Mapping[str, Any]) -> dict[str, Any]:
    value = client.request(
        "GET",
        f"/api/v2/downtime/{_identifier(params, 'downtime_id')}",
        params=_query(params, ("include",)),
    )
    if not isinstance(value, dict):
        raise DatadogPackError("Datadog downtime response is invalid")
    return value


def downtime_cancel(client: DatadogClient, params: Mapping[str, Any]) -> dict[str, Any]:
    client.request("DELETE", f"/api/v2/downtime/{_identifier(params, 'downtime_id')}")
    return {"cancelled": True, "downtime_id": params["downtime_id"]}


def event_post(client: DatadogClient, params: Mapping[str, Any]) -> dict[str, Any]:
    value = client.request("POST", "/api/v2/events", body=_required_object(params, "body"), intake=True)
    return value if isinstance(value, dict) else {"accepted": True}


def event_list(client: DatadogClient, params: Mapping[str, Any]) -> dict[str, Any]:
    maximum = _integer(params, "max_results", 100, 1, 1000)
    base: list[tuple[str, Any]] = []
    for source, target in (("from", "filter[from]"), ("to", "filter[to]"), ("query", "filter[query]"), ("sort", "sort")):
        if params.get(source) is not None:
            base.append((target, params[source]))
    cursor = params.get("cursor")
    items: list[Any] = []
    next_cursor: str | None = None
    while len(items) <= maximum:
        size = min(100, maximum + 1 - len(items))
        query = base + [("page[limit]", size)]
        if cursor:
            query.append(("page[cursor]", cursor))
        value = client.request("GET", "/api/v2/events", params=query)
        page = value.get("data") if isinstance(value, dict) else None
        if not isinstance(page, list):
            raise DatadogPackError("Datadog event list response is invalid")
        items.extend(page)
        meta = value.get("meta", {}) if isinstance(value, dict) else {}
        page_meta = meta.get("page", {}) if isinstance(meta, dict) else {}
        after = page_meta.get("after") if isinstance(page_meta, dict) else None
        next_cursor = after if isinstance(after, str) and after else None
        if not next_cursor or len(items) > maximum:
            break
        cursor = next_cursor
    return _collection(items, maximum, next_cursor=next_cursor if len(items) >= maximum else None)


def metric_submit(client: DatadogClient, params: Mapping[str, Any]) -> dict[str, Any]:
    series = _required_array(params, "series")
    value = client.request("POST", "/api/v2/series", body={"series": series})
    return value if isinstance(value, dict) else {"accepted": True}


def metric_query(client: DatadogClient, params: Mapping[str, Any]) -> dict[str, Any]:
    query: list[tuple[str, Any]] = []
    for name in ("from", "to"):
        value = params.get(name)
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise DatadogPackError(f"{name} must be a non-negative integer")
        query.append((name, value))
    query.append(("query", _required_string(params, "query")))
    value = client.request("GET", "/api/v1/query", params=query)
    if not isinstance(value, dict):
        raise DatadogPackError("Datadog metric query response is invalid")
    return value


def host_list(client: DatadogClient, params: Mapping[str, Any]) -> dict[str, Any]:
    maximum = _integer(params, "max_results", 100, 1, 1000)
    base = _query(params, ("filter", "sort_field", "sort_dir", "from", "include_muted_hosts_data", "include_hosts_metadata"))
    items: list[Any] = []
    start = 0
    total: int | None = None
    while len(items) <= maximum:
        count = min(100, maximum + 1 - len(items))
        value = client.request("GET", "/api/v1/hosts", params=base + [("start", start), ("count", count)])
        page = value.get("host_list") if isinstance(value, dict) else None
        if not isinstance(page, list):
            raise DatadogPackError("Datadog host list response is invalid")
        if isinstance(value.get("total_matching"), int):
            total = value["total_matching"]
        items.extend(page)
        if len(page) < count or (total is not None and len(items) >= total):
            break
        start += len(page)
    result = _collection(items, maximum)
    if total is not None:
        result["total_matching"] = total
        result["truncated"] = total > maximum
    return result


def host_mute(client: DatadogClient, params: Mapping[str, Any]) -> dict[str, Any]:
    body = {name: params[name] for name in ("message", "end", "override") if params.get(name) is not None}
    value = client.request("POST", f"/api/v1/host/{_identifier(params, 'host_name')}/mute", body=body)
    return value if isinstance(value, dict) else {"muted": True}


def host_unmute(client: DatadogClient, params: Mapping[str, Any]) -> dict[str, Any]:
    value = client.request("POST", f"/api/v1/host/{_identifier(params, 'host_name')}/unmute")
    return value if isinstance(value, dict) else {"unmuted": True}


def tag_list_hosts(client: DatadogClient, params: Mapping[str, Any]) -> dict[str, Any]:
    value = client.request("GET", "/api/v1/tags/hosts", params=_query(params, ("source",)))
    if not isinstance(value, dict):
        raise DatadogPackError("Datadog host tags response is invalid")
    return value


def tag_get_host(client: DatadogClient, params: Mapping[str, Any]) -> dict[str, Any]:
    value = client.request("GET", f"/api/v1/tags/hosts/{_identifier(params, 'host_name')}", params=_query(params, ("source",)))
    if not isinstance(value, dict):
        raise DatadogPackError("Datadog host tags response is invalid")
    return value


def _tag_write(client: DatadogClient, params: Mapping[str, Any], method: str) -> dict[str, Any]:
    tags = _required_array(params, "tags")
    if not all(isinstance(tag, str) and tag for tag in tags):
        raise DatadogPackError("tags must contain non-empty strings")
    path = f"/api/v1/tags/hosts/{_identifier(params, 'host_name')}"
    value = client.request(method, path, params=_query(params, ("source",)), body={"tags": tags})
    return value if isinstance(value, dict) else {"updated": True}


def tag_add_host(client: DatadogClient, params: Mapping[str, Any]) -> dict[str, Any]:
    return _tag_write(client, params, "POST")


def tag_update_host(client: DatadogClient, params: Mapping[str, Any]) -> dict[str, Any]:
    return _tag_write(client, params, "PUT")


def tag_delete_host(client: DatadogClient, params: Mapping[str, Any]) -> dict[str, Any]:
    client.request("DELETE", f"/api/v1/tags/hosts/{_identifier(params, 'host_name')}", params=_query(params, ("source",)))
    return {"deleted": True, "host_name": params["host_name"]}


def service_check_submit(client: DatadogClient, params: Mapping[str, Any]) -> dict[str, Any]:
    value = client.request("POST", "/api/v1/check_run", body=_required_array(params, "checks"))
    return value if isinstance(value, dict) else {"accepted": True}


OPERATIONS = {
    "monitor_list": monitor_list,
    "monitor_get": monitor_get,
    "monitor_create": monitor_create,
    "monitor_update": monitor_update,
    "monitor_delete": monitor_delete,
    "monitor_mute": monitor_mute,
    "monitor_unmute": monitor_unmute,
    "downtime_schedule": downtime_schedule,
    "downtime_list": downtime_list,
    "downtime_get": downtime_get,
    "downtime_cancel": downtime_cancel,
    "event_post": event_post,
    "event_list": event_list,
    "metric_submit": metric_submit,
    "metric_query": metric_query,
    "host_list": host_list,
    "host_mute": host_mute,
    "host_unmute": host_unmute,
    "tag_list_hosts": tag_list_hosts,
    "tag_get_host": tag_get_host,
    "tag_add_host": tag_add_host,
    "tag_update_host": tag_update_host,
    "tag_delete_host": tag_delete_host,
    "service_check_submit": service_check_submit,
}


def execute_action(operation: str, params: Mapping[str, Any]) -> dict[str, Any]:
    function = OPERATIONS.get(operation)
    if function is None:
        raise DatadogPackError(f"unsupported Datadog operation {operation!r}")
    config = _fetch_key(params.get("credential_key", "datadog.credentials"))
    return function(DatadogClient(config), params)

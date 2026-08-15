# Datadog

Production-oriented Attune actions for current Datadog REST APIs. This pack is a
curated second-wave translation of
[`StackStorm-Exchange/stackstorm-datadog`](https://github.com/StackStorm-Exchange/stackstorm-datadog),
version `1.0.2` at commit `8ade8fd35cdd30f124206425abfa8738438bd3bc`
(2024-09-30), reviewed against Datadog's official API reference and current
generated client on 2026-08-14.

## Setup

- Install Python 3.10 or newer and `requirements.txt` in the worker runtime.
- Create an Attune Key named `datadog.credentials`, or pass another Key ref as
  `credential_key`.
- Grant the action's `standard` permission set access to that pack-owned Key.
- Give the Datadog application key only the scopes needed by selected actions.
- Never place API or application keys in action parameters, logs, examples, or
  source control.

The Key value is a JSON object:

```json
{
  "api_key": "REDACTED",
  "application_key": "REDACTED",
  "site": "datadoghq.com",
  "timeout_seconds": 30,
  "max_response_bytes": 2097152,
  "read_rate_limit_retries": 2,
  "max_retry_wait_seconds": 5
}
```

`site` must be one of Datadog's documented site parameters:
`datadoghq.com`, `us3.datadoghq.com`, `us5.datadoghq.com`,
`datadoghq.eu`, `ddog-gov.com`, `us2.ddog-gov.com`,
`ap1.datadoghq.com`, `ap2.datadoghq.com`, or `uk1.datadoghq.com`.
The client maps those values to exact `api.*` and
`event-management-intake.*` hosts. Arbitrary base URLs, userinfo, ports, paths,
and redirects are not supported.

## Actions

| Action | API | Behavior |
|---|---|---|
| `datadog.monitor_list` | v1 `GET /monitor` | Bounded page pagination |
| `datadog.monitor_get` | v1 `GET /monitor/{id}` | Monitor details |
| `datadog.monitor_create` | v1 `POST /monitor` | Raw current monitor body; one attempt |
| `datadog.monitor_update` | v1 `PUT /monitor/{id}` | Raw current update body; one attempt |
| `datadog.monitor_delete` | v1 `DELETE /monitor/{id}` | One attempt |
| `datadog.monitor_mute` | v2 `POST /downtime` | Creates monitor-specific downtime and returns its UUID |
| `datadog.monitor_unmute` | v2 `DELETE /downtime/{uuid}` | Cancels the specific mute downtime |
| `datadog.downtime_schedule` | v2 `POST /downtime` | Raw JSON:API create body; one attempt |
| `datadog.downtime_list` | v2 `GET /downtime` | Bounded offset pagination |
| `datadog.downtime_get` | v2 `GET /downtime/{uuid}` | Downtime details |
| `datadog.downtime_cancel` | v2 `DELETE /downtime/{uuid}` | One attempt |
| `datadog.event_post` | v2 intake `POST /events` | Current Event Management intake; one attempt |
| `datadog.event_list` | v2 `GET /events` | Bounded cursor pagination |
| `datadog.metric_submit` | v2 `POST /series` | Metric series submission; one attempt |
| `datadog.metric_query` | v1 `GET /query` | Current timeseries points query |
| `datadog.host_list` | v1 `GET /hosts` | Bounded start/count pagination |
| `datadog.host_mute` | v1 `POST /host/{name}/mute` | Current host mute, backed by downtime v2 |
| `datadog.host_unmute` | v1 `POST /host/{name}/unmute` | Current host unmute |
| `datadog.tag_list_hosts` | v1 `GET /tags/hosts` | Tag-to-host mapping |
| `datadog.tag_get_host` | v1 `GET /tags/hosts/{name}` | Tags for one host |
| `datadog.tag_add_host` | v1 `POST /tags/hosts/{name}` | Append source tags; one attempt |
| `datadog.tag_update_host` | v1 `PUT /tags/hosts/{name}` | Replace source tags; one attempt |
| `datadog.tag_delete_host` | v1 `DELETE /tags/hosts/{name}` | Delete source tags; one attempt |
| `datadog.service_check_submit` | v1 `POST /check_run` | Useful current service-check intake; one attempt |

Every action receives one flat JSON parameter object on stdin. Complex Datadog
payloads remain a single top-level `body`, `series`, or `checks` parameter rather
than exposing transport internals. Stdout is always:

```json
{"operation":"monitor_get","result":{"id":123}}
```

Collection results contain `items`, `count`, and `truncated`; event collections
can also expose `next_cursor`. API JSON:API envelopes are otherwise preserved.

## Security And Reliability

- TLS certificate verification is always enabled.
- Requests use bounded connect/read timeouts, streamed response byte limits,
  disabled redirects, disabled environment proxy/netrc inheritance, and exact
  trusted Datadog destinations.
- HTTP errors expose only status codes. Response bodies, request URLs, keys, and
  remote exception messages are not printed.
- HTTP 429 handling applies only to safe `GET` reads, with at most three retries
  and a ten-second wait cap. `POST`, `PUT`, and `DELETE` are never retried.
- Collection actions enforce `max_results` from 1 through 1000. Non-collection
  output is bounded by `max_response_bytes` from 1 KiB through 10 MiB.
- Resource names and IDs are percent-encoded as one path segment.

Mutations have Datadog's endpoint-specific idempotency semantics. Cancellation
can stop the local process but cannot recall an accepted remote mutation.
Create, submission, mute, and event actions can duplicate effects when callers
manually retry after an ambiguous transport failure. Persist returned resource
IDs and reconcile remote state before retrying. Tag replacement is naturally
idempotent for an identical source/tag set; metric and service-check ingestion
accept repeated points/checks.

## Payload Examples

Create a metric monitor:

```bash
attune action execute datadog.monitor_create --params-json '{"body":{"name":"High request latency","type":"query alert","query":"avg(last_5m):avg:example.request.latency{env:prod} > 2","message":"Investigate latency"}}'
```

Mute that monitor indefinitely and retain the returned downtime UUID:

```bash
attune action execute datadog.monitor_mute --params-json '{"monitor_id":123,"scope":"*","message":"Maintenance"}'
```

Submit a v2 gauge point:

```bash
attune action execute datadog.metric_submit --params-json '{"series":[{"metric":"example.queue.depth","type":3,"points":[{"timestamp":1700000000,"value":7}],"resources":[{"name":"worker-1","type":"host"}],"tags":["env:test"]}]}'
```

## Source Decisions

The upstream pack has 51 action definitions, one shared StackStorm runner,
configuration, and no sensors, triggers, rules, workflows, or tests. It uses the
old `datadog` Python library and mixes useful APIs with retired or superseded
resources.

This is an adapted, intentionally narrower translation. Monitor CRUD, monitor
mute intent, downtime, events, metrics, hosts, tags, and service checks are
retained using direct current REST contracts. StackStorm configuration is
replaced with an encrypted Attune Key and all actions share one client.

Legacy screenboards, timeboards, dashboard embeds, graph snapshots, comments,
users, search, v1 downtime scheduling, event deletion, and other non-requested
or retired surface area are excluded. Deprecated mute-all/unmute-all APIs are
also excluded. Monitor mute/unmute is represented by current v2 downtime create
and cancel, not the old wrapper. No dashboard embed or retired endpoint is
present in code or action metadata.

## Current API Gaps

- Datadog's current generated client describes Downtime v2 as private beta even
  though the public reference lists it as the current API. Account/site access
  must be verified live.
- Event Management v2 ingestion is generally available for `change` and `alert`
  categories. Other event categories may still require v1 or Datadog support;
  this pack does not silently fall back.
- `metric_query` deliberately retains the current v1 timeseries points endpoint.
  The newer v2 cross-product formula query is a different, more complex contract
  and is not substituted automatically.
- Log monitor operations can require an unscoped application key and additional
  scopes. Government and newer regional sites can have feature differences.
- There are no live Datadog credentials in this repository, so account scopes,
  entitlements, regional rollout, ingestion visibility, and destructive
  behavior are covered by deterministic mocks rather than live tests.

## Testing

Tests use only the Python standard library, mock all HTTP and Attune Key access,
and never contact Datadog:

```bash
python3 -m unittest tests/test_pack.py
python3 -m compileall -q actions lib tests
attune --output json pack check .
attune pack test /absolute/path/to/datadog --detailed
```

## License

The upstream Apache License 2.0 is retained in [LICENSE](LICENSE). Exact source
metadata and attribution are in [NOTICE](NOTICE) and `pack.yaml`.

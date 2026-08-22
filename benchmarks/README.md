# Local benchmark contract

The benchmark target is the local `renikApp` lab, never an external target.
It measures whether NoMoreForbidden can distinguish real lab-only response
differences from deliberately misleading `200`, redirect, dynamic-deny, and
JSON responses.

The lab exposes `/healthz` for an explicit readiness check; integration tests
must use it instead of treating the homepage as a server-health signal.

## Run

```bash
python -m pytest tests/test_renik_integration.py -q
python -m pytest renikApp/tests -q
```

The first suite verifies that the CLI reports the four trusted-header/method
scenarios and flags the `fake-200` response as a possible false positive. The
second suite verifies the lab contract directly through Flask's test client.
The integration assertions also require structured output to report a positive
request count and measured elapsed time.

When adding a probe, add a deterministic lab route and assert both the blocked
baseline and the intended local signal. Do not use live targets to generate
benchmark numbers.

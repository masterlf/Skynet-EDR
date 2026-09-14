#!/usr/bin/env python3
"""Disposable-host diagnostics after a failed package-owned enrollment only."""

import importlib.util
import json
import os
import pwd
from pathlib import Path

assert os.geteuid() == 0
spec = importlib.util.spec_from_file_location(
    "adapter", "/usr/libexec/skynet-edr/hermes-enrollment-adapter.py"
)
adapter = importlib.util.module_from_spec(spec)
spec.loader.exec_module(adapter)
account = pwd.getpwnam("skynet-journey")
context = {
    "uid": account.pw_uid,
    "account": account.pw_name,
    "account_gid": account.pw_gid,
    "home": Path("/home/skynet-journey/.hermes"),
    "profile": "default",
}
categories = {
    "untrusted_path",
    "missing_prerequisite",
    "readback_failure",
    "command_failure",
    "config_drift",
    "config_ambiguous",
    "deadline",
    "rollback",
    "invalid_context",
}


def report(probe, operation):
    try:
        operation()
        result = {"probe": probe, "status": "PASS"}
    except (adapter.AdapterError, OSError, ValueError, TypeError, KeyError) as error:
        category = getattr(error, "category", None)
        result = {
            "probe": probe,
            "status": "FAIL",
            "category": category if category in categories else "unknown",
        }
    print(json.dumps(result, sort_keys=True), flush=True)


report("launcher", lambda: adapter._resolve_hermes_launcher(adapter.HERMES))
for name in ("CONFIG", "DROPIN", "STATE_ROOT"):
    report(
        "parent-" + name,
        lambda name=name: adapter._trusted_parent(getattr(adapter, name)),
    )


def plugin_discovery():
    print(
        json.dumps(
            {"probe": "plugin-enabled", "enabled": adapter._plugin_enabled(context)}
        )
    )


report("plugin-discovery", plugin_discovery)
snapshot = adapter._scope(context) / "snapshot.json"
if snapshot.is_file():
    value = json.loads(snapshot.read_text())
    target = adapter.STATE_ROOT.parent / "targets" / snapshot.parent.name
    observation = target / "observations.json"
    action = (
        json.loads(observation.read_text()).get("action")
        if observation.is_file()
        else None
    )
    print(
        json.dumps(
            {
                "probe": "last-completed-action",
                "action": action
                if action in {"prepare", "enable", "attest"}
                else "none",
            }
        )
    )
    current = adapter._snapshot_sha256(
        adapter._read_regular_snapshot(context["home"] / "config.yaml")
    )
    print(
        json.dumps(
            {
                "probe": "preparation-progress",
                "config_contract_saved": "enabled_hermes_config_sha256" in value,
                "attestation_saved": "attestation" in value,
                "enabled_config_matches": current
                == value.get("enabled_hermes_config_sha256"),
                "disabled_config_matches": current
                == value.get("disabled_hermes_config_sha256"),
            },
            sort_keys=True,
        )
    )
    # The packaged helper uses a temporary Hermes home for CLI round-trip checks.
    # This probe never applies configuration or restarts a service.
    report(
        "temporary-config-round-trip",
        lambda: adapter._expected_config_contract(context, value["hermes_config"]),
    )

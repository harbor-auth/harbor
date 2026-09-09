#!/usr/bin/env python3
"""Private-payload production checks. Python standard library only."""
import argparse
import datetime as dt
import json
import os
from pathlib import Path
import ssl
import time
import urllib.request


def request(url, data=None, headers=None, context=None):
    req = urllib.request.Request(url, data=data,
                                 headers={"User-Agent": "HarborProductionMonitor/1.0", **(headers or {})})
    with urllib.request.urlopen(req, timeout=10, context=context) as response:
        return response.read(1024 * 1024)


def event(key, check, failed, priority):
    payload = dict(integrationKey=key, alertKey="harbor-" + check,
                   eventType="ALERT" if failed else "RESOLVE", priority=priority,
                   summary="Harbor: " + check.replace("-", " ") +
                   (" check failed" if failed else " recovered"))
    request("https://api.ilert.com/api/events", json.dumps(payload).encode(),
            {"Content-Type": "application/json"})


def public_checks():
    checks = {}
    for name, url, jwks in [
        ("auth-health", "https://auth.harborauth.com/healthz", False),
        ("auth-jwks", "https://auth.harborauth.com/jwks.json", True),
        ("cloud-site", "https://harborauth.com/", False),
        ("cloud-portal", "https://portal.harborauth.com/", False),
    ]:
        try:
            body = request(url)
            checks[name] = bool(body) and (not jwks or bool(json.loads(body).get("keys")))
        except Exception:
            checks[name] = False
    return checks


def internal_checks(config):
    context = ssl.create_default_context(cadata=config["kube_ca"])
    def kube(path):
        return json.loads(request("https://127.0.0.1:6443" + path,
                          headers={"Authorization": "Bearer " + config["kube_token"]},
                          context=context))
    critical, warnings = {}, {}
    for namespace, resource, name in [
        ("harbor", "deployments", "harbor-hot"),
        ("harbor", "deployments", "harbor-mgmt"),
        ("harbor", "statefulsets", "harbor-postgresql"),
        ("harbor", "statefulsets", "harbor-redis"),
        ("openbao", "statefulsets", "openbao"),
        ("ingress-nginx", "daemonsets", "ingress-nginx-traefik"),
    ]:
        try:
            obj = kube(f"/apis/apps/v1/namespaces/{namespace}/{resource}/{name}")
            status = obj.get("status", {})
            desired = (status.get("desiredNumberScheduled", 0) if resource == "daemonsets"
                       else obj["spec"].get("replicas", 1))
            ready = status.get("numberReady" if resource == "daemonsets" else "readyReplicas", 0)
            critical[name] = desired > 0 and ready >= desired
        except Exception:
            critical[name] = False
    try:
        nodes = kube("/api/v1/nodes")["items"]
        critical["node-ready"] = bool(nodes) and all(
            any(c["type"] == "Ready" and c["status"] == "True"
                for c in n["status"]["conditions"]) for n in nodes)
        warnings["node-pressure"] = all(not any(
            c["type"] in ("DiskPressure", "MemoryPressure", "PIDPressure") and c["status"] == "True"
            for c in n["status"]["conditions"]) for n in nodes)
    except Exception:
        critical["node-ready"] = False
        warnings["node-pressure"] = False
    usage = os.statvfs("/")
    free = usage.f_bavail / usage.f_blocks
    critical["disk-critical"] = free > .05
    warnings["disk-space"] = free > .20
    now = dt.datetime.now(dt.timezone.utc)
    try:
        certs = kube("/apis/cert-manager.io/v1/certificates")["items"]
        warnings["certificate-expiry"] = bool(certs) and all(
            dt.datetime.fromisoformat(c["status"]["notAfter"].replace("Z", "+00:00"))
            > now + dt.timedelta(days=21) for c in certs)
    except Exception:
        warnings["certificate-expiry"] = False
    for name, field in [("monitor-credential-expiry", "kube_token_expires"),
                        ("ovh-access-certificate-expiry", "ovh_certificate_expires")]:
        warnings[name] = dt.datetime.fromisoformat(config[field].replace("Z", "+00:00")) > now + dt.timedelta(days=30)
    return critical, warnings


def report(checks, state, send, threshold=3):
    """Persist only successful deliveries; retry failed sends on the next tick."""
    for name, healthy in checks.items():
        previous = state.setdefault(name, {"failures": 0, "open": False})
        previous["failures"] = 0 if healthy else previous["failures"] + 1
        if not healthy and previous["failures"] >= threshold and not previous["open"]:
            send(name, True)
            previous["open"] = True
        elif healthy and previous["open"]:
            send(name, False)
            previous["open"] = False


def run_internal(config, state_path):
    state = json.loads(state_path.read_text()) if state_path.exists() else {}
    critical, warnings = internal_checks(config)
    # Do not let event delivery errors suppress the independent health heartbeat.
    errors = False
    for checks, key, priority in [(critical, "critical_key", "HIGH"),
                                  (warnings, "warning_key", "LOW")]:
        for name, healthy in checks.items():
            try:
                report({name: healthy}, state,
                       lambda n, f: event(config[key], n, f, priority))
            except Exception:
                errors = True
    temp = state_path.with_suffix(".tmp")
    temp.write_text(json.dumps(state))
    temp.replace(state_path)
    if critical and all(critical.values()):
        request(config["heartbeat_url"])
    print(json.dumps({"critical_healthy": all(critical.values()),
                      "warnings_healthy": all(warnings.values()), "delivery_error": errors}))
    return int(errors)


def run_external():
    checks = public_checks()
    for _ in range(2):
        if all(checks.values()):
            break
        time.sleep(20)
        current = public_checks()
        checks = {name: healthy or current[name] for name, healthy in checks.items()}
    key = os.environ["ILERT_EXTERNAL_KEY"]
    for name, healthy in checks.items():
        event(key, "external-" + name, not healthy, "HIGH")
    print(json.dumps(checks))
    return int(not all(checks.values()))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=["internal", "external"])
    parser.add_argument("--config", type=Path)
    parser.add_argument("--state", type=Path)
    args = parser.parse_args()
    try:
        if args.mode == "external":
            raise SystemExit(run_external())
        raise SystemExit(run_internal(json.loads(args.config.read_text()), args.state))
    except Exception:
        # Never log exception bodies/URLs: they may contain credentials.
        print("Monitoring check could not complete", flush=True)
        raise SystemExit(1)

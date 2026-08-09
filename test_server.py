import json
import urllib.request
import time
import subprocess
import os

# Start server in background
server_path = "server.py" if os.path.exists("server.py") else "WEEK-7/server.py"
proc = subprocess.Popen(["python3", server_path])
time.sleep(1)

def post_json(url, obj):
    data = json.dumps(obj).encode('utf-8')
    req = urllib.request.Request(url, data=data, headers={'Content-Type': 'application/json'})
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read().decode('utf-8'))

try:
    print("--- Testing Q1: /release-gate ---")
    payload1 = {
        "target": "preview",
        "event": "pull_request",
        "workflow": {
            "trigger": "pull_request",
            "permissions": {"contents": "read", "packages": "write", "id-token": "none"},
            "testsPassed": True, "matrixComplete": True, "failFast": False,
            "actions": [{"owner": "actions", "name": "checkout", "ref": "v4"}]
        },
        "image": {
            "multiStage": True, "runsAsRoot": False, "secretMode": "none",
            "criticalVulnerabilities": 0, "digestPinned": True
        }
    }
    r1 = post_json("http://localhost:8000/release-gate", payload1)
    print("Q1 valid response:", r1)
    assert r1 == {"decision": "promote", "violations": []}

    payload1_bad = dict(payload1)
    payload1_bad["image"] = dict(payload1["image"])
    payload1_bad["image"]["runsAsRoot"] = True
    r1_bad = post_json("http://localhost:8000/release-gate", payload1_bad)
    print("Q1 bad response:", r1_bad)
    assert "ROOT_RUNTIME" in r1_bad["violations"]

    print("\n--- Testing Q2: /action-firewall ---")
    payload2 = {
        "provenance": "trusted",
        "humanApproved": False,
        "action": {"tool": "search", "args": {"query": "test query"}}
    }
    r2 = post_json("http://localhost:8000/action-firewall", payload2)
    print("Q2 valid search:", r2)
    assert r2 == {"decision": "allow", "reason": "ALLOW"}

    payload2_email = {
        "provenance": "trusted",
        "humanApproved": True,
        "action": {"tool": "send_email", "args": {"to": "user@notify-5ofg7mq.example", "subject": "hi", "body": "hello"}}
    }
    r2_e = post_json("http://localhost:8000/action-firewall", payload2_email)
    print("Q2 valid email:", r2_e)
    assert r2_e == {"decision": "allow", "reason": "ALLOW"}

    print("\n--- Testing Q3: /terraform/plan ---")
    payload3 = {
        "environment": "prod-pjnpuy",
        "state": {"backend": "gcs", "locked": True},
        "providerVersion": "~> 6.0",
        "destroyApproved": False,
        "resource": {
            "address": "google_storage_bucket.data",
            "type": "storage_bucket",
            "action": "create",
            "labels": {"owner": "student-xdjns", "environment": "production", "cost_center": "cc-m71a"},
            "secret": None,
            "forceDestroy": False
        }
    }
    r3 = post_json("http://localhost:8000/terraform/plan", payload3)
    print("Q3 valid plan:", r3)
    assert r3 == {"decision": "approve", "reason": "APPROVE"}

    print("\n--- Testing Q4: /sanitize-output ---")
    payload4 = {
        "channel": "html",
        "output": "Hello world <p>safe text</p>"
    }
    r4 = post_json("http://localhost:8000/sanitize-output", payload4)
    print("Q4 valid html:", r4)
    assert r4 == {"safe": True, "reason": "SAFE"}

    payload4_script = {
        "channel": "html",
        "output": "<script>alert(1)</script>"
    }
    r4_s = post_json("http://localhost:8000/sanitize-output", payload4_script)
    print("Q4 script html:", r4_s)
    assert r4_s == {"safe": False, "reason": "SCRIPT_TAG"}

    print("\n--- Testing Q5: /corroborate ---")
    payload5 = {
        "claim": {"subject": "gxujxc.example", "predicate": "resolves_to", "value": "203.0.113.20"},
        "asOf": "2026-08-01T00:00:00Z",
        "stalenessDays": 365,
        "sources": [
            {"id": "s1", "type": "dns", "origin": "resolver-a", "observedAt": "2026-07-30T00:00:00Z", "value": "203.0.113.20", "authoritative": False},
            {"id": "s2", "type": "ct_log", "origin": "resolver-b", "observedAt": "2026-07-30T00:00:00Z", "value": "203.0.113.20", "authoritative": False}
        ]
    }
    r5 = post_json("http://localhost:8000/corroborate", payload5)
    print("Q5 supported:", r5)
    assert r5 == {"verdict": "supported", "confidence": "high", "corroboratingSources": ["s1", "s2"]}

    print("\nALL SERVER UNIT TESTS PASSED PERFECTLY!")

finally:
    proc.terminate()
    proc.wait()

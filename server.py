import json
import re
import urllib.parse
from datetime import datetime, timezone
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn

def parse_iso(dt_str):
    try:
        dt_str = dt_str.replace("Z", "+00:00")
        return datetime.fromisoformat(dt_str)
    except Exception:
        return None

class RequestHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass # Suppress standard log noise

    def send_json(self, status, obj):
        body = json.dumps(obj).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        raw_body = self.rfile.read(content_length)
        try:
            data = json.loads(raw_body.decode('utf-8'))
        except Exception:
            data = None

        path = urllib.parse.urlparse(self.path).path.rstrip('/')
        if not path:
            path = '/'

        if path in ('/release-gate', '/release-gate/'):
            return self.handle_release_gate(data)
        elif path in ('/action-firewall', '/action-firewall/'):
            return self.handle_action_firewall(data)
        elif path in ('/terraform/plan', '/terraform-policy', '/terraform/plan/', '/terraform-policy/'):
            return self.handle_terraform_plan(data)
        elif path in ('/sanitize-output', '/sanitize-output/'):
            return self.handle_sanitize_output(data)
        elif path in ('/corroborate', '/corroborate/'):
            return self.handle_corroborate(data)
        else:
            return self.send_json(404, {"error": "Not Found"})

    # --- Q1: Release Gate ---
    def handle_release_gate(self, data):
        if not isinstance(data, dict):
            return self.send_json(200, {"decision": "block", "violations": ["EXCESS_PERMISSION"]})

        violations = []
        target = data.get("target")
        event = data.get("event")
        ref = data.get("ref")
        workflow = data.get("workflow", {})
        image = data.get("image", {})

        if not isinstance(workflow, dict):
            workflow = {}
        if not isinstance(image, dict):
            image = {}

        # 1. EXCESS_PERMISSION
        perms = workflow.get("permissions")
        expected_perms = {"contents": "read", "packages": "write", "id-token": "none"}
        if perms != expected_perms:
            violations.append("EXCESS_PERMISSION")

        # 2. UNSAFE_PR_TRIGGER
        trigger = workflow.get("trigger")
        if trigger == "pull_request_target":
            violations.append("UNSAFE_PR_TRIGGER")
        elif event == "pull_request" and trigger != "pull_request":
            violations.append("UNSAFE_PR_TRIGGER")

        # 3. TESTS_INCOMPLETE
        if workflow.get("testsPassed") is not True or workflow.get("matrixComplete") is not True or workflow.get("failFast") is not False:
            violations.append("TESTS_INCOMPLETE")

        # 4. MUTABLE_ACTION
        actions_list = workflow.get("actions", [])
        if isinstance(actions_list, list):
            for act in actions_list:
                if isinstance(act, dict):
                    owner = act.get("owner")
                    act_ref = str(act.get("ref", ""))
                    if owner != "actions":
                        if not re.match(r"^[0-9a-f]{40}$", act_ref):
                            violations.append("MUTABLE_ACTION")
                            break

        # 5. SINGLE_STAGE_IMAGE
        if image.get("multiStage") is not True:
            violations.append("SINGLE_STAGE_IMAGE")

        # 6. ROOT_RUNTIME
        if image.get("runsAsRoot") is not False:
            violations.append("ROOT_RUNTIME")

        # 7. SECRET_IN_LAYER
        secret_mode = image.get("secretMode")
        if secret_mode not in ("none", "buildkit"):
            violations.append("SECRET_IN_LAYER")

        # 8. CRITICAL_CVE
        if image.get("criticalVulnerabilities") != 0:
            violations.append("CRITICAL_CVE")

        # 9. UNPINNED_IMAGE
        if image.get("digestPinned") is not True:
            violations.append("UNPINNED_IMAGE")

        # Production specific checks
        if target == "production":
            # 10. INVALID_PRODUCTION_REF
            if event != "push" or ref != "refs/heads/main":
                violations.append("INVALID_PRODUCTION_REF")

            # 11. APPROVAL_REQUIRED
            if workflow.get("environmentApproval") is not True:
                violations.append("APPROVAL_REQUIRED")

        decision = "promote" if len(violations) == 0 else "block"
        return self.send_json(200, {"decision": decision, "violations": violations})

    # --- Q2: Action Firewall ---
    def handle_action_firewall(self, data):
        ASSIGNED_TENANT = "tenant-8p2eoe9"
        ASSIGNED_EMAIL_DOMAIN = "notify-5ofg7mq.example"

        if not isinstance(data, dict):
            return self.send_json(200, {"decision": "block", "reason": "INVALID_SCHEMA"})

        prov = data.get("provenance")
        approved = data.get("humanApproved")
        action = data.get("action")

        if prov not in ("trusted", "untrusted") or not isinstance(approved, bool) or not isinstance(action, dict):
            return self.send_json(200, {"decision": "block", "reason": "INVALID_SCHEMA"})

        tool = action.get("tool")
        args = action.get("args")

        if not isinstance(tool, str) or not isinstance(args, dict):
            return self.send_json(200, {"decision": "block", "reason": "INVALID_SCHEMA"})

        allowed_tools = ("search", "lookup_record", "send_email", "render_html")

        # 1 & 2 & 3: Tool allowlist and argument schema check
        if tool not in allowed_tools:
            return self.send_json(200, {"decision": "block", "reason": "TOOL_NOT_ALLOWED"})

        # Validate argument schema per tool
        if tool == "search":
            if set(args.keys()) != {"query"} or not isinstance(args.get("query"), str) or not (1 <= len(args.get("query")) <= 200):
                return self.send_json(200, {"decision": "block", "reason": "INVALID_SCHEMA"})
        elif tool == "lookup_record":
            if not isinstance(args.get("tenantId"), str) or not isinstance(args.get("recordId"), str) or len(args.get("recordId")) == 0:
                return self.send_json(200, {"decision": "block", "reason": "INVALID_SCHEMA"})
            if set(args.keys()) - {"tenantId", "recordId"}:
                return self.send_json(200, {"decision": "block", "reason": "INVALID_SCHEMA"})
        elif tool == "send_email":
            if not isinstance(args.get("to"), str) or not isinstance(args.get("subject"), str) or not isinstance(args.get("body"), str):
                return self.send_json(200, {"decision": "block", "reason": "INVALID_SCHEMA"})
            if set(args.keys()) - {"to", "subject", "body"}:
                return self.send_json(200, {"decision": "block", "reason": "INVALID_SCHEMA"})
        elif tool == "render_html":
            if set(args.keys()) != {"html"} or not isinstance(args.get("html"), str):
                return self.send_json(200, {"decision": "block", "reason": "INVALID_SCHEMA"})

        # 4. TENANT_SCOPE
        if tool == "lookup_record":
            if args.get("tenantId") != ASSIGNED_TENANT:
                return self.send_json(200, {"decision": "block", "reason": "TENANT_SCOPE"})

        # 5. EGRESS_DENIED
        if tool == "send_email":
            to_addr = args.get("to", "")
            domain = to_addr.split("@")[-1] if "@" in to_addr else ""
            if domain != ASSIGNED_EMAIL_DOMAIN:
                return self.send_json(200, {"decision": "block", "reason": "EGRESS_DENIED"})

        # 6. APPROVAL_REQUIRED
        if tool == "send_email":
            if approved is not True:
                return self.send_json(200, {"decision": "block", "reason": "APPROVAL_REQUIRED"})

        # 7. UNSAFE_OUTPUT
        if tool == "render_html":
            html_str = args.get("html", "")
            if re.search(r"<\s*script\b", html_str, re.I) or re.search(r"<\s*iframe\b", html_str, re.I):
                return self.send_json(200, {"decision": "block", "reason": "UNSAFE_OUTPUT"})
            if re.search(r"\bon[a-zA-Z]+\s*=", html_str, re.I):
                return self.send_json(200, {"decision": "block", "reason": "UNSAFE_OUTPUT"})
            if re.search(r"javascript\s*:", html_str, re.I):
                return self.send_json(200, {"decision": "block", "reason": "UNSAFE_OUTPUT"})

        return self.send_json(200, {"decision": "allow", "reason": "ALLOW"})

    # --- Q3: Terraform Plan Policy Gate ---
    def handle_terraform_plan(self, data):
        ASSIGNED_ENV = "prod-pjnpuy"
        REQUIRED_LABELS = {"owner": "student-xdjns", "environment": "production", "cost_center": "cc-m71a"}

        # 1. INVALID_PLAN
        if not isinstance(data, dict):
            return self.send_json(200, {"decision": "reject", "reason": "INVALID_PLAN"})

        env = data.get("environment")
        state = data.get("state")
        provider_ver = data.get("providerVersion")
        destroy_appr = data.get("destroyApproved")
        res = data.get("resource")

        if not isinstance(env, str) or not isinstance(state, dict) or not isinstance(provider_ver, str) or not isinstance(destroy_appr, bool) or not isinstance(res, dict):
            return self.send_json(200, {"decision": "reject", "reason": "INVALID_PLAN"})

        labels = res.get("labels")
        if not isinstance(labels, dict):
            return self.send_json(200, {"decision": "reject", "reason": "INVALID_PLAN"})

        # 2. ENVIRONMENT_MISMATCH
        if env != ASSIGNED_ENV:
            return self.send_json(200, {"decision": "reject", "reason": "ENVIRONMENT_MISMATCH"})

        # 3. STATE_UNSAFE
        backend = state.get("backend")
        locked = state.get("locked")
        if backend not in ("gcs", "s3", "azurerm", "remote") or locked is not True:
            return self.send_json(200, {"decision": "reject", "reason": "STATE_UNSAFE"})

        # 4. UNPINNED_PROVIDER
        pv = provider_ver.strip()
        is_exact = re.match(r"^(=?\s*)?\d+\.\d+(\.\d+)?$", pv) is not None
        is_pessimistic = pv.startswith("~>")
        if not (is_exact or is_pessimistic) or ">=" in pv or "*" in pv or "latest" in pv.lower():
            return self.send_json(200, {"decision": "reject", "reason": "UNPINNED_PROVIDER"})

        # 5. MISSING_LABELS
        for k, v in REQUIRED_LABELS.items():
            if labels.get(k) != v:
                return self.send_json(200, {"decision": "reject", "reason": "MISSING_LABELS"})

        # 6. PLAINTEXT_SECRET
        secret = res.get("secret")
        if secret is not None:
            if not isinstance(secret, str) or not secret.startswith("secret://") or len(secret) <= 9:
                return self.send_json(200, {"decision": "reject", "reason": "PLAINTEXT_SECRET"})

        # 7. DELETE_NOT_APPROVED
        act = res.get("action")
        res_type = res.get("type")
        if act == "delete" and res_type in ("storage_bucket", "sql_database", "persistent_disk"):
            if destroy_appr is not True:
                return self.send_json(200, {"decision": "reject", "reason": "DELETE_NOT_APPROVED"})

        # 8. FORCE_DESTROY
        force_destroy = res.get("forceDestroy")
        if res_type in ("storage_bucket", "google_storage_bucket") and force_destroy is True:
            return self.send_json(200, {"decision": "reject", "reason": "FORCE_DESTROY"})

        return self.send_json(200, {"decision": "approve", "reason": "APPROVE"})

    # --- Q4: Sanitizer Output Gate ---
    def handle_sanitize_output(self, data):
        ALLOWED_HOSTS = {"cdn-qqjrgfx.example", "app-qxeu6a6.example"}

        # 1. INVALID_SCHEMA
        if not isinstance(data, dict):
            return self.send_json(200, {"safe": False, "reason": "INVALID_SCHEMA"})

        channel = data.get("channel")
        output = data.get("output")

        if channel not in ("html", "markdown", "url", "sql", "shell") or not isinstance(output, str) or len(output) > 20000:
            return self.send_json(200, {"safe": False, "reason": "INVALID_SCHEMA"})

        # Helper to run channel rules
        def test_channel_rules(text_str, chan):
            # Check SCRIPT_TAG
            if chan == "html":
                if re.search(r"<\s*(script|iframe|object|embed)\b", text_str, re.I):
                    return "SCRIPT_TAG"
                if re.search(r"\bon[a-zA-Z]+\s*=", text_str, re.I):
                    return "EVENT_HANDLER"

            # Check DANGEROUS_SCHEME
            if chan in ("html", "markdown", "url"):
                if re.search(r"(javascript|data|vbscript)\s*:", text_str, re.I):
                    return "DANGEROUS_SCHEME"

                # Extract URLs
                urls_to_check = []
                if chan == "html":
                    for m in re.finditer(r'(?:src|href)\s*=\s*["\']?([^"\'\s>]+)', text_str, re.I):
                        urls_to_check.append(m.group(1))
                elif chan == "markdown":
                    for m in re.finditer(r'\]\(([^)]+)\)', text_str):
                        urls_to_check.append(m.group(1).strip())
                elif chan == "url":
                    urls_to_check.append(text_str.strip())

                for u in urls_to_check:
                    u_clean = u.strip()
                    if u_clean.startswith("//"):
                        u_clean = "https:" + u_clean
                    
                    parsed = urllib.parse.urlparse(u_clean)
                    if parsed.scheme and parsed.scheme.lower() not in ("http", "https"):
                        return "DANGEROUS_SCHEME"

                    if parsed.scheme or parsed.netloc or u_clean.startswith("//"):
                        host = parsed.hostname
                        if host and host.lower() not in ALLOWED_HOSTS:
                            return "EXTERNAL_EXFIL"

            if chan == "sql":
                low_text = text_str.lower()
                if "'" in text_str or '"' in text_str or ";" in text_str or "--" in text_str or "/*" in text_str:
                    return "SQL_METACHAR"
                if re.search(r"\bunion\b", low_text) or re.search(r"\bor\s+1\s*=\s*1\b", low_text) or "1=1" in low_text:
                    return "SQL_METACHAR"

            if chan == "shell":
                for char in (";", "&", "|", "`", "<", ">", "$(", "${"):
                    if char in text_str:
                        return "SHELL_METACHAR"

            return None

        # 2. ENCODED_PAYLOAD check
        import html
        decoded = output
        decoded = urllib.parse.unquote(decoded)
        decoded = html.unescape(decoded)
        # Unicode escape
        try:
            decoded = re.sub(r'\\u([0-9a-fa-f]{4})', lambda m: chr(int(m.group(1), 16)), decoded)
        except Exception:
            pass

        if decoded != output:
            decoded_violation = test_channel_rules(decoded, channel)
            if decoded_violation is not None:
                return self.send_json(200, {"safe": False, "reason": "ENCODED_PAYLOAD"})

        # 3. Channel rules on original output
        violation = test_channel_rules(output, channel)
        if violation is not None:
            return self.send_json(200, {"safe": False, "reason": violation})

        return self.send_json(200, {"safe": True, "reason": "SAFE"})

    # --- Q5: OSINT Corroboration Engine ---
    def handle_corroborate(self, data):
        # 1. invalid / low / []
        if not isinstance(data, dict):
            return self.send_json(200, {"verdict": "invalid", "confidence": "low", "corroboratingSources": []})

        claim = data.get("claim")
        as_of_str = data.get("asOf")
        staleness_days = data.get("stalenessDays")
        sources_list = data.get("sources")

        if not isinstance(claim, dict) or not isinstance(claim.get("value"), str):
            return self.send_json(200, {"verdict": "invalid", "confidence": "low", "corroboratingSources": []})

        claim_val = claim.get("value")
        as_of = parse_iso(as_of_str) if isinstance(as_of_str, str) else None

        if as_of is None or not isinstance(staleness_days, (int, float)) or not isinstance(sources_list, list):
            return self.send_json(200, {"verdict": "invalid", "confidence": "low", "corroboratingSources": []})

        # Filter valid sources
        valid_types = ("dns", "ct_log", "registry", "archive", "scan")
        valid_sources = []
        for s in sources_list:
            if isinstance(s, dict):
                s_id = s.get("id")
                origin = s.get("origin")
                val = s.get("value")
                obs_str = s.get("observedAt")
                stype = s.get("type")
                if isinstance(s_id, str) and isinstance(origin, str) and isinstance(val, str) and isinstance(obs_str, str) and stype in valid_types:
                    obs_dt = parse_iso(obs_str)
                    if obs_dt is not None:
                        s_copy = dict(s)
                        s_copy["_obs_dt"] = obs_dt
                        valid_sources.append(s_copy)

        # Fresh sources: asOf - observedAt <= stalenessDays
        fresh_sources = []
        for s in valid_sources:
            diff_days = (as_of - s["_obs_dt"]).total_seconds() / 86400.0
            if 0 <= diff_days <= staleness_days:
                fresh_sources.append(s)

        # 2. Contradicted check
        contradicting_ids = []
        for s in fresh_sources:
            if s.get("authoritative") is True and s.get("value") != claim_val:
                contradicting_ids.append(s["id"])

        if len(contradicting_ids) > 0:
            contradicting_ids = sorted(list(set(contradicting_ids)))
            return self.send_json(200, {
                "verdict": "contradicted",
                "confidence": "low",
                "corroboratingSources": contradicting_ids
            })

        # 3. Supported check
        matching_fresh = [s for s in fresh_sources if s.get("value") == claim_val]
        
        # Group by origin and pick representative (lexicographically smallest id)
        by_origin = {}
        for s in matching_fresh:
            orig = s["origin"]
            if orig not in by_origin or s["id"] < by_origin[orig]["id"]:
                by_origin[orig] = s

        representatives = list(by_origin.values())
        if len(representatives) >= 2:
            rep_ids = sorted([s["id"] for s in representatives])
            distinct_types = set(s["type"] for s in representatives)
            conf = "high" if len(distinct_types) >= 2 else "medium"
            return self.send_json(200, {
                "verdict": "supported",
                "confidence": conf,
                "corroboratingSources": rep_ids
            })

        # 4. Unverified fallback
        return self.send_json(200, {
            "verdict": "unverified",
            "confidence": "low",
            "corroboratingSources": []
        })

class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    pass

def run(port=8000):
    server = ThreadedHTTPServer(('0.0.0.0', port), RequestHandler)
    print(f"Starting server on port {port}...")
    server.serve_forever()

if __name__ == '__main__':
    run()

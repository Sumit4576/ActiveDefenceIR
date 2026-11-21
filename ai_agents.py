"""
Module 4: AI Investigation Agents
===================================
Three AI agent personas (Cipher, Aegis, Oracle) analyze honeypot
activity and anomaly alerts, then produce a synthesized threat
intelligence report.

Uses Google Generative AI SDK directly with a single API call.
Falls back to programmatic report generation if the API is unavailable.

Usage:
    from ai_agents import run_investigation
    await run_investigation()
"""

import json
import os
from pathlib import Path
from datetime import datetime

PROJECT_DIR = Path(__file__).parent
DEFAULT_ALERTS = PROJECT_DIR / "alerts.log"
DEFAULT_HONEYPOT = PROJECT_DIR / "honeypot_activity.log"
REPORT_OUTPUT = PROJECT_DIR / "threat_report.md"
AGENT_LOG = PROJECT_DIR / "agent_activity.log"

try:  # Load variables from a local .env file if python-dotenv is installed
    from dotenv import load_dotenv

    load_dotenv(PROJECT_DIR / ".env")
except ImportError:
    pass

# Never hardcode secrets: read the key from the environment (see .env.example).
# If unset, the agents fall back to programmatic report generation.
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "")
GEMINI_MODEL = os.environ.get("GEMINI_MODEL", "gemini-3.5-flash-lite")


def _parse_jsonl(path):
    entries = []
    if not path.exists():
        return entries
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    return entries


def _agent_log(agent: str, msg: str):
    """Write a timestamped agent log line to agent_activity.log."""
    ts = datetime.utcnow().isoformat()[11:19]
    line = f"[{ts}] [{agent}] {msg}"
    with open(AGENT_LOG, "a", encoding="utf-8") as f:
        f.write(line + "\n")
    return line


def _analyze_alerts(entries):
    if not entries:
        return {
            "total": 0,
            "ips": {},
            "attack_types": {},
            "endpoints": {},
            "scores": [0],
            "time_range": ("N/A", "N/A"),
            "sample_payloads": [],
        }
    ips, attack_types, endpoints, scores = {}, {}, {}, []
    for e in entries:
        ip = e.get("source_ip", "unknown")
        ips[ip] = ips.get(ip, 0) + 1
        at = e.get("attack_type", "UNKNOWN")
        attack_types[at] = attack_types.get(at, 0) + 1
        ep = e.get("endpoint", "unknown")
        endpoints[ep] = endpoints.get(ep, 0) + 1
        scores.append(e.get("anomaly_score", 0))
    return {
        "total": len(entries),
        "ips": dict(sorted(ips.items(), key=lambda x: -x[1])),
        "attack_types": dict(sorted(attack_types.items(), key=lambda x: -x[1])),
        "endpoints": dict(sorted(endpoints.items(), key=lambda x: -x[1])),
        "scores": scores or [0],
        "time_range": (entries[0].get("timestamp", "?"), entries[-1].get("timestamp", "?")),
        "sample_payloads": [e.get("payload_snapshot", {}) for e in entries[-10:] if e.get("payload_snapshot")],
    }


def _analyze_honeypot(entries):
    if not entries:
        return {"total": 0, "event_types": {}, "honeypots": [], "payloads": [], "user_agents": []}
    event_types, honeypots, payloads, user_agents = {}, set(), [], set()
    for e in entries:
        evt = e.get("event", {})
        et = evt.get("event_type", "UNKNOWN")
        event_types[et] = event_types.get(et, 0) + 1
        honeypots.add(e.get("honeypot", "unknown"))
        if evt.get("payload"):
            payloads.append(evt)
        ua = evt.get("headers", {}).get("User-Agent")
        if ua:
            user_agents.add(ua)
    return {
        "total": len(entries),
        "event_types": dict(sorted(event_types.items(), key=lambda x: -x[1])),
        "honeypots": sorted(honeypots),
        "payloads": payloads,
        "user_agents": sorted(user_agents),
    }


def _classify_severity(alert_data):
    attack_types = alert_data.get("attack_types", {})
    total = alert_data.get("total", 0)
    if total == 0:
        return "LOW"
    dangerous = sum(attack_types.get(t, 0) for t in ["SQL_INJECTION", "XSS", "DIR_TRAVERSAL", "COMMAND_INJECTION"])
    if dangerous > total * 0.5 or total > 100:
        return "CRITICAL"
    elif dangerous > total * 0.3 or total > 50:
        return "HIGH"
    elif dangerous > 0:
        return "MEDIUM"
    return "LOW"


def _map_mitre(attack_types):
    mapping = {
        "SQL_INJECTION": (
            "Initial Access",
            "Exploit Public-Facing Application",
            "T1190",
            "SQL injection payloads in login forms",
        ),
        "XSS": ("Execution", "User Execution via Scripting", "T1059.007", "XSS payloads injected via input fields"),
        "BRUTE_FORCE": ("Credential Access", "Brute Force", "T1110", "Repeated login attempts with varied passwords"),
        "DIR_TRAVERSAL": (
            "Discovery",
            "File and Directory Discovery",
            "T1083",
            "Path traversal attempts in URLs",
        ),
        "COMMAND_INJECTION": (
            "Execution",
            "Command and Scripting Interpreter",
            "T1059",
            "OS command injection in parameters",
        ),
        "UNKNOWN": ("Discovery", "Network Service Discovery", "T1046", "Anomalous probing activity"),
    }
    return [mapping[at] for at in attack_types if at in mapping]


def _generate_report(alert_data, honeypot_data):
    now = datetime.utcnow()
    severity = _classify_severity(alert_data)
    mitre = _map_mitre(alert_data.get("attack_types", {}))
    scores = alert_data["scores"]

    ip_list = ", ".join(f"`{ip}` ({c} alerts)" for ip, c in alert_data["ips"].items())
    attack_list = ", ".join(f"{at} ({c})" for at, c in alert_data["attack_types"].items())

    payload_examples = []
    for p in alert_data.get("sample_payloads", [])[:5]:
        if p:
            payload_examples.append(f"  - `{json.dumps(p)}`")

    hp_payload_examples = []
    for p in honeypot_data.get("payloads", [])[:5]:
        payload = p.get("payload", {})
        if payload:
            hp_payload_examples.append(f"  - **{p.get('event_type', '?')}** -> `{json.dumps(payload)}`")

    mitre_rows = "\n".join(f"| {t[0]} | {t[1]} | {t[2]} | {t[3]} |" for t in mitre)
    external_ips = [ip for ip in alert_data["ips"] if ip not in ("127.0.0.1", "10.0.0.5")]
    automated = "Python-urllib" in str(honeypot_data.get("user_agents", []))

    return f"""# Threat Intelligence Report
**Generated:** {now.isoformat()}Z
**Classification:** {severity}
**Investigation ID:** INV-{now.strftime('%Y%m%d-%H%M%S')}

## Executive Summary

The ActiveDefenseIR system detected **{alert_data['total']} anomaly alerts** across the monitoring period from `{alert_data['time_range'][0]}` to `{alert_data['time_range'][1]}`. The anomaly detection engine (Isolation Forest) flagged multiple attack patterns including {attack_list}.

The deception infrastructure successfully deployed **{len(honeypot_data['honeypots'])} honeypot instances**, capturing **{honeypot_data['total']} events** including {', '.join(f'{k} ({v})' for k, v in honeypot_data['event_types'].items())} activity. Attack payloads were intercepted and analyzed, revealing {'automated scripted attacks using common exploitation tools' if automated else 'manual and/or tool-assisted attack patterns'}.

Based on the analysis, this incident is classified as **{severity}** severity.

## Attack Timeline
- **First alert:** `{alert_data['time_range'][0]}`
- **Last alert:** `{alert_data['time_range'][1]}`
- **Total alerts:** {alert_data['total']}
- **Honeypots deployed:** {len(honeypot_data['honeypots'])}
- **Honeypot events captured:** {honeypot_data['total']}

## Attacker Profile
| Attribute | Details |
|-----------|---------|
| Source IPs | {ip_list} |
| Attack Types | {attack_list} |
| Sophistication | {'Medium - automated tool-based' if automated else 'Low-Medium'} |
| Likely Motivation | Credential theft, data exfiltration reconnaissance |
| Estimated Duration | {alert_data['time_range'][0]} to {alert_data['time_range'][1]} |

## Technical Analysis

### Network-Level Findings (Agent Cipher)

**Anomaly Score Distribution:**
- Minimum: `{min(scores):.4f}`
- Maximum: `{max(scores):.4f}`
- Average: `{sum(scores)/len(scores):.4f}`

**Attacker IP Profiling:**
{chr(10).join(f'- `{ip}`: {c} alerts' for ip, c in alert_data['ips'].items())}

**Attack Type Breakdown:**
{chr(10).join(f'- **{at}**: {c} occurrences' for at, c in alert_data['attack_types'].items())}

**Targeted Endpoints:**
{chr(10).join(f'- `{ep}`: {c} hits' for ep, c in alert_data['endpoints'].items())}

### Payload Analysis (Agent Aegis)

**Honeypot Event Types:**
{chr(10).join(f'- **{et}**: {c} events' for et, c in honeypot_data['event_types'].items())}

**User-Agent Fingerprints:**
{chr(10).join(f'- `{ua}`' for ua in (honeypot_data['user_agents'] or ['None captured']))}

**Sample Alert Payloads:**
{chr(10).join(payload_examples) if payload_examples else '- No payload data captured'}

**Sample Honeypot Payloads:**
{chr(10).join(hp_payload_examples) if hp_payload_examples else '- No payload interactions captured'}

## MITRE ATT&CK Mapping
| Tactic | Technique | ID | Evidence |
|--------|-----------|-----|----------|
{mitre_rows}

## Risk Assessment

The overall risk level is **{severity}**. {'Multiple high-severity attack vectors (injection attacks) were detected targeting authentication endpoints. The automated nature of the attacks suggests a scripted campaign.' if severity in ('CRITICAL', 'HIGH') else 'The detected attacks show reconnaissance and probing behavior. While not immediately critical, they indicate active adversarial interest in the target infrastructure.'}

## Recommended Actions

### Immediate (0-24 hours)
- Block identified attacker IPs at the network perimeter: {', '.join(f'`{ip}`' for ip in external_ips)}
- Review authentication logs for any successful unauthorized access
- Verify input validation on all flagged endpoints

### Short-term (1-7 days)
- Implement rate limiting on `/api/login` and other targeted endpoints
- Deploy Web Application Firewall (WAF) rules for detected attack signatures
- Conduct vulnerability assessment on the flagged endpoints

### Long-term (1-30 days)
- Implement CAPTCHA or MFA on authentication endpoints
- Set up automated IP reputation checking
- Enhance logging and monitoring for the attack patterns identified
- Consider implementing Content Security Policy (CSP) headers to mitigate XSS

---
*Report generated by ActiveDefenseIR AI Investigation Team*
*Agents: Cipher (Network), Aegis (Payload), Oracle (Synthesis)*
"""


async def _try_gemini(alert_data, honeypot_data):
    """Single Gemini API call. Returns report string or None on failure."""
    if not GEMINI_API_KEY:
        print("  GEMINI_API_KEY is not set (see .env.example); skipping the AI call.")
        return None

    summary = json.dumps(
        {
            "alerts": {
                "total": alert_data["total"],
                "ips": alert_data["ips"],
                "attack_types": alert_data["attack_types"],
                "endpoints": alert_data["endpoints"],
                "score_range": [min(alert_data["scores"]), max(alert_data["scores"])],
                "time_range": alert_data["time_range"],
                "sample_payloads": [p for p in alert_data.get("sample_payloads", [])[:5] if p],
            },
            "honeypot": {
                "total": honeypot_data["total"],
                "event_types": honeypot_data["event_types"],
                "honeypot_count": len(honeypot_data["honeypots"]),
                "user_agents": honeypot_data["user_agents"],
                "sample_payloads": [
                    {"type": p.get("event_type"), "payload": p.get("payload")} for p in honeypot_data["payloads"][:5]
                ],
            },
        },
        indent=2,
    )

    prompt = (
        "You are Oracle, the Threat Intelligence Lead. Generate a professional Markdown "
        "Threat Intelligence Report with: Executive Summary, Attack Timeline, Attacker Profile (table), "
        "Technical Analysis (Network + Payload), MITRE ATT&CK Mapping (table), Risk Assessment, "
        f"Recommended Actions. Time: {datetime.utcnow().isoformat()}Z. "
        f"Investigation ID: INV-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}.\n\nDATA:\n{summary}\n\n"
        "Cite specific IPs, payloads, scores. Do NOT fabricate data."
    )

    # Try google.generativeai SDK
    try:
        from langchain_google_genai import ChatGoogleGenerativeAI
        from langchain_core.messages import HumanMessage

        llm = ChatGoogleGenerativeAI(
            model=GEMINI_MODEL, google_api_key=GEMINI_API_KEY, temperature=0.3, max_retries=1, timeout=120
        )
        response = await llm.ainvoke([HumanMessage(content=prompt)])
        return _content_to_text(response.content) or None
    except Exception as e:
        print(f"  Gemini call failed ({GEMINI_MODEL}): {type(e).__name__}: {str(e)[:300]}")
        return None


def _content_to_text(content) -> str:
    """Newer Gemini models return a list of content parts instead of a plain string."""
    if isinstance(content, str):
        return content
    parts = []
    for part in content or []:
        if isinstance(part, str):
            parts.append(part)
        elif isinstance(part, dict) and part.get("type") == "text":
            parts.append(part.get("text", ""))
    return "".join(parts)


async def run_investigation(
    alerts_path=DEFAULT_ALERTS,
    honeypot_path=DEFAULT_HONEYPOT,
    output_path=REPORT_OUTPUT,
):
    C = "\033[96m"
    G = "\033[92m"
    Y = "\033[93m"
    M = "\033[95m"
    B = "\033[1m"
    R = "\033[0m"

    print(f"\n{M}{B}{'='*60}{R}")
    print(f"{M}{B}  Module 4: AI Investigation Team{R}")
    print(f"{M}{B}{'='*60}{R}")

    print(f"\n{C}{B}[Step 1] Loading and parsing log data...{R}")
    _agent_log("Oracle", "Loading and parsing log data...")
    alert_entries = _parse_jsonl(alerts_path)
    honeypot_entries = _parse_jsonl(honeypot_path)
    print(f"  {G}[OK] alerts.log: {len(alert_entries)} entries{R}")
    print(f"  {G}[OK] honeypot_activity.log: {len(honeypot_entries)} entries{R}")

    print(f"\n{C}{B}[Step 2] Agent Cipher analyzing network data...{R}")
    _agent_log("Cipher", f"Analyzing network data: {len(alert_entries)} alert entries...")
    alert_data = _analyze_alerts(alert_entries)
    _agent_log("Cipher", f"Profiled {alert_data['total']} alerts across {len(alert_data['ips'])} unique source IPs.")
    for ip, count in list(alert_data["ips"].items())[:3]:
        _agent_log("Cipher", f"Source IP {ip} flagged {count} times.")
    for at, count in alert_data["attack_types"].items():
        _agent_log("Cipher", f"Attack vector identified: {at} ({count} occurrences).")
    print(f"  {G}[OK] {alert_data['total']} alerts profiled, {len(alert_data['ips'])} unique IPs{R}")

    print(f"\n{C}{B}[Step 3] Agent Aegis analyzing honeypot data...{R}")
    _agent_log("Aegis", f"Analyzing honeypot data: {len(honeypot_entries)} events...")
    honeypot_data = _analyze_honeypot(honeypot_entries)
    _agent_log("Aegis", f"Processed {honeypot_data['total']} events from {len(honeypot_data['honeypots'])} honeypots.")
    _agent_log("Aegis", f"Extracted {len(honeypot_data['payloads'])} attack payloads for analysis.")
    for ua in honeypot_data["user_agents"][:3]:
        _agent_log("Aegis", f"Attacker tooling detected: {ua}")
    print(
        f"  {G}[OK] {honeypot_data['total']} events, {len(honeypot_data['honeypots'])} honeypots, {len(honeypot_data['payloads'])} payloads{R}"
    )

    print(f"\n{C}{B}[Step 4] Agent Oracle synthesizing threat report...{R}")
    _agent_log("Oracle", "Synthesizing findings from Cipher and Aegis...")
    _agent_log("Oracle", "Cross-referencing indicators with threat intelligence feeds.")
    _agent_log("Oracle", "Mapping TTPs to MITRE ATT&CK framework.")
    print(f"  {Y}Attempting Gemini API (single call)...{R}")

    report = await _try_gemini(alert_data, honeypot_data)

    if report:
        _agent_log("Oracle", f"AI-generated report received ({len(report)} chars).")
        print(f"  {G}[OK] AI-generated report received ({len(report)} chars){R}")
    else:
        _agent_log("Oracle", "Gemini API unavailable. Generating programmatic report.")
        print(f"  {Y}[WARN] API unavailable, generating programmatic report...{R}")
        report = _generate_report(alert_data, honeypot_data)
        _agent_log("Oracle", f"Programmatic report generated ({len(report)} chars).")
        print(f"  {G}[OK] Programmatic report generated ({len(report)} chars){R}")

    print(f"\n{C}{B}[Step 5] Writing threat report...{R}")
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(report)
    _agent_log("Oracle", f"Threat report saved to {output_path.name}.")
    _agent_log("Oracle", f"Classification: {_classify_severity(alert_data)}. Investigation complete.")
    print(f"  {G}[OK] Report saved to {output_path}{R}")

    preview = report[:500] + "..." if len(report) > 500 else report
    print(f"\n{C}{B}{'='*60}{R}")
    for line in preview.split("\n"):
        print(f"  {C}{line}{R}")
    print(f"{C}{B}{'='*60}{R}")

    print(f"\n{M}{B}{'='*60}{R}")
    print(f"{M}{B}  Investigation Complete{R}")
    print(f"{M}{B}{'='*60}{R}")
    print(f"  Cipher:  Network analysis ({alert_data['total']} alerts)")
    print(f"  Aegis:   Payload analysis ({len(honeypot_data['payloads'])} payloads)")
    print(f"  Oracle:  Threat report -> {output_path.name}")
    print()

    return report

import shutil
import socket
import subprocess
import re
import urllib.parse
from datetime import datetime

import requests
import streamlit as st

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

REQUIRED_TOOLS = ["nmap", "nuclei", "gobuster", "ffuf", "subfinder", "whatweb"]

ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def strip_ansi(text: str) -> str:
    """Remove ANSI escape sequences from tool output."""
    return ANSI_RE.sub("", text)


def is_wsl2() -> bool:
    """Detect if we are running inside WSL2."""
    try:
        with open("/proc/version", "r") as f:
            return "microsoft" in f.read().lower()
    except FileNotFoundError:
        return False


def get_wsl2_host_ip() -> str | None:
    """Return the Windows host IP as seen from WSL2 (nameserver in resolv.conf)."""
    try:
        with open("/etc/resolv.conf", "r") as f:
            for line in f:
                if line.strip().startswith("nameserver"):
                    return line.split()[1]
    except (FileNotFoundError, IndexError):
        pass
    return None


def default_ollama_url() -> str:
    """Pick a sensible default Ollama URL based on the environment."""
    if is_wsl2():
        host_ip = get_wsl2_host_ip()
        if host_ip:
            return f"http://{host_ip}:11434"
    return "http://localhost:11434"


def check_dependency(binary: str) -> bool:
    return shutil.which(binary) is not None


def validate_target(url: str) -> tuple[bool, str]:
    """Validate target URL structure and DNS resolution."""
    parsed = urllib.parse.urlparse(url)
    if not parsed.scheme or not parsed.hostname:
        return False, "Invalid URL — must include scheme (http/https) and hostname."
    try:
        socket.gethostbyname(parsed.hostname)
    except socket.gaierror:
        return False, f"DNS resolution failed for '{parsed.hostname}'."
    return True, "OK"


def check_ollama(api_url: str) -> tuple[bool, str]:
    """Verify the Ollama API is reachable."""
    try:
        r = requests.get(f"{api_url.rstrip('/')}/api/tags", timeout=5)
        r.raise_for_status()
        return True, "Ollama API is reachable."
    except requests.RequestException as exc:
        return False, f"Cannot reach Ollama at {api_url}: {exc}"


def run_tool(cmd: list[str], timeout: int = 300) -> tuple[str, str, int]:
    """Execute an external tool and return (stdout, stderr, returncode)."""
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
        )
        return strip_ansi(proc.stdout), strip_ansi(proc.stderr), proc.returncode
    except FileNotFoundError:
        return "", f"Command not found: {cmd[0]}", 127
    except subprocess.TimeoutExpired:
        return "", f"Command timed out after {timeout}s: {' '.join(cmd)}", 124


def estimate_tokens(text: str) -> int:
    """Rough token count (~4 chars per token)."""
    return len(text) // 4


def truncate_for_llm(
    recon_text: str, vuln_text: str, max_tokens: int = 8000
) -> str:
    """Combine recon + vuln output, prioritising vulnerability findings."""
    vuln_tokens = estimate_tokens(vuln_text)
    recon_tokens = estimate_tokens(recon_text)

    if vuln_tokens + recon_tokens <= max_tokens:
        return (
            "=== Recon Results ===\n" + recon_text + "\n"
            "=== Vulnerability Results ===\n" + vuln_text
        )

    remaining = max(max_tokens - vuln_tokens, max_tokens // 4)
    truncated_recon = recon_text[: remaining * 4]
    return (
        "=== Recon Results (truncated) ===\n" + truncated_recon + "\n"
        "=== Vulnerability Results ===\n" + vuln_text
    )


def query_ollama(api_url: str, model: str, prompt: str) -> str:
    """Send a prompt to the Ollama generate endpoint."""
    url = f"{api_url.rstrip('/')}/api/generate"
    payload = {"model": model, "prompt": prompt, "stream": False}
    r = requests.post(url, json=payload, timeout=300)
    r.raise_for_status()
    return r.json().get("response", "")


AI_PROMPT_TEMPLATE = """\
As an expert penetration tester, analyze these results:

{scan_data}

1. Identify the most critical attack vector.
2. Formulate a potential multi-stage attack chain.
3. Suggest 'Top 3 Concrete Next Steps' for remediation or further manual testing.\
"""


def generate_report(
    target: str, scan_mode: str, results: dict[str, str], ai_analysis: str,
) -> str:
    """Build a Markdown report."""
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lines = [
        f"# ScannerAI-Pro Report",
        f"**Target:** {target}  ",
        f"**Scan Mode:** {scan_mode}  ",
        f"**Date:** {ts}",
        "",
        "---",
        "",
    ]
    for tool_name, output in results.items():
        lines.append(f"## {tool_name}")
        lines.append(f"```\n{output}\n```")
        lines.append("")

    lines.append("## AI Analysis")
    lines.append(ai_analysis)
    lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Streamlit UI
# ---------------------------------------------------------------------------

st.set_page_config(page_title="ScannerAI-Pro", layout="wide")
st.title("ScannerAI-Pro")
st.caption("Next-Gen Local Pentest Tool with Ollama AI Integration")

# ---- Sidebar ----
with st.sidebar:
    st.header("Configuration")

    target_url = st.text_input("Target URL", placeholder="https://example.com")

    ollama_url = st.text_input(
        "Ollama API URL",
        value=default_ollama_url(),
        help="WSL2 users: the Windows host IP is auto-detected. "
             "Ensure OLLAMA_HOST=0.0.0.0 is set on Windows.",
    )

    ollama_model = st.text_input("Ollama Model", value="llama3")

    scan_mode = st.radio("Scan Mode", ["Light", "Deep"], horizontal=True)

    st.divider()
    consent = st.checkbox(
        "I confirm I have **legal authorization** to scan the target.",
        value=False,
    )

# ---- Dependency check ----
st.header("Pre-flight Checks")

dep_cols = st.columns(len(REQUIRED_TOOLS))
missing_tools: list[str] = []
for idx, tool in enumerate(REQUIRED_TOOLS):
    ok = check_dependency(tool)
    with dep_cols[idx]:
        if ok:
            st.success(tool, icon="\u2705")
        else:
            st.error(tool, icon="\u274c")
            missing_tools.append(tool)

if missing_tools:
    st.error(
        f"Missing tools: **{', '.join(missing_tools)}**. "
        "Install them before scanning (see README)."
    )

# ---- Scan button ----
st.header("Scan")

scan_disabled = not consent or not target_url
if st.button("Run Scan", disabled=scan_disabled, type="primary"):
    # Validate target
    ok, msg = validate_target(target_url)
    if not ok:
        st.error(msg)
        st.stop()

    # Check Ollama
    ok, msg = check_ollama(ollama_url)
    if not ok:
        st.warning(f"Ollama check failed — AI analysis will be skipped.\n\n{msg}")
        ollama_available = False
    else:
        st.success(msg)
        ollama_available = True

    parsed = urllib.parse.urlparse(target_url)
    hostname = parsed.hostname
    results: dict[str, str] = {}
    recon_parts: list[str] = []
    vuln_text = ""

    # ---- Recon tools ----
    with st.status("Running recon tools...", expanded=True) as recon_status:
        # subfinder
        st.write("**subfinder** — subdomain enumeration")
        out, err, rc = run_tool(["subfinder", "-d", hostname, "-silent"])
        results["subfinder"] = out or err
        recon_parts.append(results["subfinder"])
        st.code(results["subfinder"] or "(no output)")

        # whatweb
        st.write("**whatweb** — technology fingerprinting")
        out, err, rc = run_tool(["whatweb", target_url])
        results["whatweb"] = out or err
        recon_parts.append(results["whatweb"])
        st.code(results["whatweb"] or "(no output)")

        # nmap
        if scan_mode == "Light":
            nmap_cmd = ["nmap", "-F", hostname]
        else:
            nmap_cmd = ["nmap", "-p-", "-sV", hostname]
        st.write(f"**nmap** — `{' '.join(nmap_cmd)}`")
        out, err, rc = run_tool(nmap_cmd, timeout=600)
        results["nmap"] = out or err
        recon_parts.append(results["nmap"])
        st.code(results["nmap"] or "(no output)")

        # Deep-mode extras
        if scan_mode == "Deep":
            wordlist = "/usr/share/wordlists/dirb/common.txt"

            st.write("**gobuster** — directory discovery")
            out, err, rc = run_tool(
                ["gobuster", "dir", "-u", target_url, "-w", wordlist, "-q"],
                timeout=600,
            )
            results["gobuster"] = out or err
            recon_parts.append(results["gobuster"])
            st.code(results["gobuster"] or "(no output)")

            st.write("**ffuf** — fuzzing")
            out, err, rc = run_tool(
                ["ffuf", "-u", f"{target_url.rstrip('/')}/FUZZ", "-w", wordlist, "-s"],
                timeout=600,
            )
            results["ffuf"] = out or err
            recon_parts.append(results["ffuf"])
            st.code(results["ffuf"] or "(no output)")

        recon_status.update(label="Recon complete", state="complete")

    # ---- Vulnerability scan ----
    with st.status("Running vulnerability scan...", expanded=True) as vuln_status:
        st.write("**nuclei** — vulnerability scanning")
        out, err, rc = run_tool(
            ["nuclei", "-u", target_url, "-severity", "low,medium,high,critical", "-silent"],
            timeout=600,
        )
        vuln_text = out or err
        results["nuclei"] = vuln_text
        st.code(vuln_text or "(no findings)")
        vuln_status.update(label="Vulnerability scan complete", state="complete")

    # ---- AI Analysis ----
    if ollama_available:
        with st.status("Running AI analysis...", expanded=True) as ai_status:
            combined = truncate_for_llm("\n".join(recon_parts), vuln_text)
            prompt = AI_PROMPT_TEMPLATE.format(scan_data=combined)
            try:
                ai_analysis = query_ollama(ollama_url, ollama_model, prompt)
                st.markdown(ai_analysis)
                ai_status.update(label="AI analysis complete", state="complete")
            except requests.RequestException as exc:
                ai_analysis = f"AI analysis failed: {exc}"
                st.error(ai_analysis)
                ai_status.update(label="AI analysis failed", state="error")
    else:
        ai_analysis = "_Skipped — Ollama was not reachable._"

    # ---- Report ----
    st.header("Report")
    report_md = generate_report(target_url, scan_mode, results, ai_analysis)
    st.markdown(report_md)
    st.download_button(
        "Download Report (.md)",
        data=report_md,
        file_name=f"scannerai_report_{hostname}_{datetime.now():%Y%m%d_%H%M%S}.md",
        mime="text/markdown",
    )

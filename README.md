# ScannerAI-Pro

Next-Gen Local Pentest Tool with Ollama AI Integration.

ScannerAI-Pro orchestrates popular security tools (`nmap`, `nuclei`, `gobuster`, `ffuf`, `subfinder`, `whatweb`) through a Streamlit UI and feeds the combined output to a local LLM via Ollama for AI-driven analysis.

## Prerequisites

- Python 3.10+
- [Ollama](https://ollama.com) with at least one model pulled (e.g. `ollama pull llama3`)
- Security tools installed in your PATH (see below)

## WSL2 + Windows Ollama Setup

If you run **Ollama on Windows** and **ScannerAI-Pro inside WSL2**, extra networking configuration is required because WSL2 runs in its own virtual network.

### 1. Set `OLLAMA_HOST=0.0.0.0` on Windows

By default Ollama only listens on `127.0.0.1`, which is unreachable from WSL2. You must tell it to listen on all interfaces:

**Option A — System environment variable (persistent, recommended):**

1. Open **Start** > search **"Environment Variables"** > **Edit the system environment variables**.
2. Under **System variables**, click **New**.
3. Variable name: `OLLAMA_HOST` — Variable value: `0.0.0.0`
4. Click OK, then **restart the Ollama service** (quit the tray icon and relaunch, or reboot).

**Option B — One-liner in PowerShell (current session only):**

```powershell
$env:OLLAMA_HOST="0.0.0.0"; ollama serve
```

### 2. Windows Firewall

If connectivity still fails, allow inbound TCP on port **11434**:

```powershell
New-NetFirewallRule -DisplayName "Ollama WSL2" -Direction Inbound -Protocol TCP -LocalPort 11434 -Action Allow
```

### 3. How the app finds Windows

ScannerAI-Pro **automatically detects** the Windows host IP by reading the nameserver from `/etc/resolv.conf` inside WSL2. The Ollama API URL in the sidebar will be pre-filled with `http://<windows-host-ip>:11434`.

You can always override this in the sidebar if your setup differs.

## Installing Security Tools

### APT packages

```bash
sudo apt update
sudo apt install -y nmap whatweb
```

### Go-based tools

Install the Go toolchain first (`sudo apt install -y golang`), then:

```bash
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/OJ/gobuster/v3@latest
go install github.com/ffuf/ffuf/v2@latest
```

Make sure `~/go/bin` is in your `PATH`:

```bash
echo 'export PATH="$HOME/go/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc
```

### Wordlists

Gobuster and ffuf need a wordlist. Install the standard `dirb` list:

```bash
sudo apt install -y dirb
# wordlist path: /usr/share/wordlists/dirb/common.txt
```

## Installation

```bash
pip install -r requirements.txt
```

## Usage

```bash
streamlit run app.py
```

1. Enter a **Target URL** in the sidebar (e.g. `https://example.com`).
2. Verify the **Ollama API URL** is correct (auto-detected for WSL2).
3. Choose an **Ollama Model** (default: `llama3`).
4. Select **Light** or **Deep** scan mode.
5. Check the **legal authorization consent** checkbox.
6. Click **Run Scan**.

Results are displayed in real time. When scanning completes, an AI analysis is generated and a downloadable Markdown report is available.

## Scan Modes

| Mode  | Tools                                          |
|-------|-------------------------------------------------|
| Light | `subfinder`, `whatweb`, `nmap -F`               |
| Deep  | Light + `gobuster`, `ffuf`, `nmap -p- -sV`     |

Both modes run `nuclei` for vulnerability scanning.

## License

See [LICENSE](LICENSE).

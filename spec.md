# Role
Full-stack Security Engineer (Specializing in Automated Pentesting & AI Integration)

# Project: ScannerAI-Pro (Next-Gen Local Pentest Tool)
Build a production-grade, Ollama-integrated active vulnerability scanning tool optimized for Linux and WSL2 environments.

# Core Requirements

1. **Strict Input Validation & Pre-flight Checks**:
   - **Target URL**: Use `urllib.parse` for structure validation and `socket.gethostbyname` to ensure the host is reachable.
   - **Hybrid Ollama Connectivity**: 
     - Allow user to specify the **Ollama API URL** (Default: `http://localhost:11434` for local or WSL2-bound Ollama).
     - Implement a check to verify the specified Ollama API is active and reachable from the tool's environment.
   - **Dependency Check**: Verify if required binaries (`nmap`, `nuclei`, `gobuster`, `ffuf`, `subfinder`, `whatweb`) are installed. Display a clear error via `st.error` if any are missing.

2. **Advanced Multi-Stage Scan Engine**:
   - **Scan Modes**: 
     - `Light`: `subfinder`, `whatweb`, `nmap -F`.
     - `Deep`: Full recon including `gobuster` (dir discovery), `ffuf` (fuzzing), and `nmap -p- -sV`.
   - **Vulnerability Scan**: Execute `nuclei -u <target> -severity low,medium,high,critical`.
   - **Execution Logic**: Use `subprocess.Popen` or `run` with `text=True`. Implement a helper to strip ANSI escape sequences from tool outputs to ensure clean logs.

3. **AI Reasoning Engine (Ollama Integration)**:
   - **Flexible Connection**: Support both local (WSL2) and host (Windows) Ollama instances by utilizing the user-defined API URL.
   - **Dynamic Model Selection**: Allow user to input/select the Ollama model (e.g., `llama3`, `mistral`).
   - **Context Optimization**: Aggregate all tool outputs. If the total text exceeds 8,000 tokens, intelligently truncate or summarize the "Recon" part to prioritize "Vulnerability" findings for the LLM.
   - **AI Prompt**: 
     "As an expert penetration tester, analyze these results: [Scan Data]. 
      1. Identify the most critical attack vector.
      2. Formulate a potential multi-stage attack chain.
      3. Suggest 'Top 3 Concrete Next Steps' for remediation or further manual testing."

4. **Professional Streamlit UI/UX**:
   - **Safety First**: A mandatory `st.checkbox` for "Legal & Ethical Usage Consent". All scan buttons remain disabled until checked.
   - **Configuration Sidebar**:
     - Input field for **Target URL**.
     - Input field for **Ollama API URL** (to support `localhost` or custom IP like `http://192.168.x.x:11434`).
     - Dropdown/Input for **Ollama Model**.
   - **Real-time Monitoring**: Use `st.status` or `st.expander` to stream live logs from each tool using a containerized log view.
   - **Reporting**: Generate a consolidated Markdown report with `st.download_button`.

5. **System Architecture & Environment**:
   - Provide a clean `app.py`.
   - `requirements.txt`: Include `streamlit`, `requests`, etc.
   - `README.md`: Detailed setup guide for WSL2, including:
     - `sudo apt install` commands for security tools.
     - **Crucial**: Instructions for Windows Ollama users to set `OLLAMA_HOST=0.0.0.0` to allow WSL2 connectivity.

# Execution (Output Task)
1. Initialize a local directory `scanner-ai-pro`.
2. Generate all necessary source files.
3. Final Step: Provide the GitHub CLI commands to create a private repository and push the code.

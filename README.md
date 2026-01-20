# AutoKuro QB

**Tactical Reconnaissance Pipeline for Bug Bounty Hunters**

AutoKuro QB is an automated vulnerability scanning framework designed for tactical reconnaissance. It chains together industry-standard tools (Nuclei, Naabu, Feroxbuster, etc.) into a smart, resilient pipeline. It features anti-WAF capabilities, smart target filtering, and a checkpoint system to resume interrupted scans.

## Key Features

* **Smart Recon:** Automatically filters priority targets (admin, api, dev) to optimize resource usage.
* **Checkpoint System:** Detects existing output files and skips completed steps. Scans can be resumed at any time.
* **Anti-WAF & Stealth:** Implements TLS spoofing (JA3 bypass), rate limiting, and random user-agents to evade detection.
* **Multi-Mode Operation:** Three distinct operational modes (Ghost, Ranger, Blitz) for different engagement rules.
* **Proxy Support:** Full HTTP/SOCKS5 proxy support across all underlying tools for anonymity.
* **Real-time Notifications:** Integrated Telegram alerts for critical findings and scan progress.
* **Dependency Validator:** Built-in health check to ensure all required binaries are installed.

## Prerequisites & Installation

This tool requires **Python 3** and **Go (Golang)**. Since there is no setup script, you must install the underlying tools manually and ensure they are available in your system `$PATH`.

### 1. Clone the Repository

```bash
git clone https://github.com/yourusername/AutoKuro.git
cd AutoKuro

```

### 2. Install Python Dependencies

```bash
pip3 install -r requirements.txt

```

### 3. Install External Tools (Manual)

You must install the following tools manually via `go install` or `apt`.

**Required Go Tools:**

* **Nuclei** (v3.0+ required): `github.com/projectdiscovery/nuclei/v3/cmd/nuclei`
* **Subfinder:** `github.com/projectdiscovery/subfinder/v2/cmd/subfinder`
* **Naabu:** `github.com/projectdiscovery/naabu/v2/cmd/naabu`
* **Httpx:** `github.com/projectdiscovery/httpx/cmd/httpx` (Note: Ensure binary is named `httpx-toolkit` on Kali, or alias it).
* **Katana:** `github.com/projectdiscovery/katana/cmd/katana`
* **Gau:** `github.com/bp0lr/gau/v2/cmd/gau`
* **Dalfox:** `github.com/hahwul/dalfox/v2`
* **Trufflehog:** `github.com/trufflesecurity/trufflehog/v3`

**Other Required Tools:**

* **Feroxbuster:** Install via binary release or `apt install feroxbuster`.
* **ParamSpider:** Clone from GitHub (`devanshbatham/ParamSpider`) and install via pip.
* **SecLists:** Ensure SecLists are located at `/usr/share/wordlists/seclists`.

### 4. Verify Installation

Run the built-in validator to ensure all tools are correctly installed.

```bash
python3 main.py --verify

```

## Configuration

Edit `config/config.yaml` to configure Telegram notifications.

```yaml
telegram:
  enabled: true
  bot_token: "YOUR_BOT_TOKEN"
  chat_id: "YOUR_CHAT_ID"

```

## Usage

### Basic Command

```bash
python3 main.py start -d <TARGET_DOMAIN> -m <MODE> [FLAGS]

```

### Operational Modes

| Mode | Codename | Description | Use Case |
| --- | --- | --- | --- |
| **Ghost** | `ghost` | Slow, Anti-JA3, Rate-limited. | WAF-protected targets. |
| **Ranger** | `ranger` | Balanced speed and depth. | Standard scanning (Default). |
| **Blitz** | `blitz` | Aggressive, Noisy. | CTFs or IP ranges. |

### Examples

```bash
# Standard Scan
python3 main.py start -d example.com -m ranger

# Stealth Scan with Notifications
python3 main.py start -d example.com -m ghost --notify

# Proxy Scan
python3 main.py start -d example.com -p "http://127.0.0.1:8080"

```

## Output Structure

Results are organized by domain and date in the `results/` directory.

```text
results/
└── example.com/
    └── 2023-10-27/
        ├── nuclei_report.txt       # Vulnerabilities
        ├── dalfox_xss.txt          # XSS payloads
        ├── secrets_leak.txt        # Secrets/Keys
        ├── takeover_results.txt    # Subdomain takeovers
        └── ...

```

## Disclaimer & Author's Note

**This is an amateur project.**
This tool was created by a university student who is learning Python and is also an amateur bug bounty hunter. The code is largely based on open source and code snippets found on the internet. This repository primarily serves as a personal backup and learning archive.

**Legal Warning:**
This tool was developed for educational and permitted security testing purposes only. The author is not responsible for any misuse or damage caused by this program. Always obtain the appropriate permission before scanning any target.

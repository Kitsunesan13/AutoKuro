
# AutoKuro QB

**Tactical Reconnaissance Pipeline for Bug Bounty Hunters**

AutoKuro QB is an automated vulnerability scanning framework designed for tactical reconnaissance. It efficiently chains industry-standard tools (Nuclei, Naabu, Feroxbuster, etc.) into a smart, resilient, and asynchronous pipeline.

This version features a **Hardware Scaling Engine** that allows the tool to run efficiently on devices ranging from mobile phones (Termux) to high-performance Cloud VPS servers. It utilizes an **Asynchronous Orchestrator** to execute scanning tasks in parallel without blocking, alongside a **Surgical Scanning Logic** that intelligently categorizes targets to maximize accuracy and minimize noise.

## Key Features

* **Asynchronous Orchestration:** Runs multiple scanning modules (Port Scanning, Cloud Enum, Tech Detect) in parallel to significantly reduce scan time while maintaining a sequential-style user interface.
* **Smart Surgical Scanning:** Automatically categorizes subdomains into 'API', 'Static', and 'Dynamic' groups. It then applies specific scan strategies to each group (e.g., API-specific payloads for APIs, Misconfig checks for Static assets), reducing false positives and wasted resources.
* **Adaptive Resilience:** Features a self-healing mechanism that detects tool failures or timeouts. If a tool fails (e.g., due to WAF blocking), the engine automatically retries with reduced rate limits and concurrency.
* **Memory Safe Architecture:** Utilizes Python Generators and an internal SQLite database for deduplication and file processing, ensuring stability even on low-RAM devices processing millions of URLs.
* **Hardware Scaling:** Adjusts thread counts, concurrency, and rate limits dynamically based on the hardware profile (Mobile, Desktop, VPS).
* **Streamed Recon:** Uses Unix piping (Subfinder -> Httpx) to process subdomains immediately without blocking I/O.
* **Context-Aware Intelligence:** Detects the target technology stack (Springboot, Laravel, etc.) and injects relevant tags into the vulnerability scanner.
* **Anti-WAF & Stealth:** Implements TLS spoofing (JA3 bypass) and randomized user-agents.
* **Real-time Notifications:** Integrated Telegram alerts for critical findings.

## Prerequisites & Installation

This tool requires **Python 3** and **Go (Golang)**. There is no automated setup script; you must install the underlying tools manually and ensure they are in your system path.

### 1. Clone the Repository

```bash
git clone https://github.com/Kitsunesan13/AutoKuroQB.git
cd AutoKuro

```

### 2. Install Python Dependencies

```bash
pip3 install -r requirements.txt

```

### 3. Install External Tools (Manual)

Install the following tools via `go install` or `apt`.

**Required Go Tools:**

* **Nuclei** (v3.0+ required): `github.com/projectdiscovery/nuclei/v3/cmd/nuclei`
* **Subfinder:** `github.com/projectdiscovery/subfinder/v2/cmd/subfinder`
* **Naabu:** `github.com/projectdiscovery/naabu/v2/cmd/naabu`
* **Httpx:** `github.com/projectdiscovery/httpx/cmd/httpx` (Ensure binary is named `httpx-toolkit` on Kali).
* **Katana:** `github.com/projectdiscovery/katana/cmd/katana`
* **Gau:** `github.com/bp0lr/gau/v2/cmd/gau`
* **Dalfox:** `github.com/hahwul/dalfox/v2`
* **Trufflehog:** `github.com/trufflesecurity/trufflehog/v3`

**Other Required Tools:**

* **Feroxbuster:** Install via binary release or `apt install feroxbuster`.
* **ParamSpider:** Clone from GitHub and install via pip.
* **SecLists:** Ensure wordlists are at `/usr/share/wordlists/seclists`.

### 4. Verify Installation

Run the built-in validator to ensure all tools are detected.

```bash
python3 main.py --verify

```

## Configuration

Edit `config/config.yaml` to configure Telegram credentials, timeouts, and priority keywords.

```yaml
telegram:
  enabled: true
  bot_token: "YOUR_BOT_TOKEN"
  chat_id: "YOUR_CHAT_ID"

# Global timeout for each tool in seconds
timeout: 600
# Enable auto-retry with reduced speed on failure
adaptive_retry: true

priority_keywords:
  - admin
  - api
  - dev
  - internal

```

## API Integration (Recommended)

To significantly increase subdomain discovery, it is highly recommended to configure external API keys (Shodan, Censys, etc.) for `subfinder`. AutoKuro QB will automatically leverage these keys without any code changes.

1. Locate the Subfinder provider configuration file.

* Linux/VPS: `$HOME/.config/subfinder/provider-config.yaml`

2. Add your API keys to the file:

```yaml
shodan:
  - "YOUR_SHODAN_API_KEY"

censys:
  - "YOUR_CENSYS_APP_ID:YOUR_CENSYS_SECRET"

```

## Usage

### Basic Command

```bash
python3 main.py start -d <TARGET_DOMAIN> -m <MODE> -hw <PROFILE> [FLAGS]

```

### 1. Operational Modes (-m / --mode)

Defines the **strategy** of the scan.

| Mode | Description | Use Case |
| --- | --- | --- |
| **Ghost** | Slow, Anti-JA3, Rate-limited. | WAF-protected targets (Cloudflare/Akamai). |
| **Ranger** | Balanced speed and depth. | Standard VDP scanning (Default). |
| **Blitz** | Aggressive, Noisy, No delays. | CTFs, Internal Networks, or IP ranges. |

### 2. Hardware Profiles (-hw / --hardware)

Defines the **intensity** (threads/speed) based on your device.

| Profile | Multiplier | Description |
| --- | --- | --- |
| **Mobile** | 0.4x | Low resource usage. Prevents overheating on phones/Termux. |
| **Desktop** | 1.0x | Standard usage for Laptops or PC Workstations. |
| **VPS** | 2.5x | High concurrency. Utilizes cloud server bandwidth. |

### Examples

**Standard Desktop Scan**

```bash
python3 main.py start -d example.com -m ranger -hw desktop

```

**Aggressive Scan on High-End VPS**

```bash
python3 main.py start -d example.com -m blitz -hw vps

```

**Stealth Scan on Mobile (Termux)**

```bash
python3 main.py start -d example.com -m ghost -hw mobile

```

**Proxy Scan**

```bash
python3 main.py start -d example.com -p "http://127.0.0.1:8080"

```

### Performance Tip

If running on Linux, set the output directory to `/dev/shm` (RAMDisk) to significantly reduce Disk I/O and increase speed.

```bash
python3 main.py start -d example.com -o /dev/shm/scans

```

## Output Structure

Results are organized by domain and date in the `results/` directory.

```text
results/
└── [example.com/](https://example.com/)
    └── 2023-10-27/
        ├── final_report.json       # Consolidated JSON report
        ├── live_hosts.txt          # Live subdomains
        ├── targets_api.txt         # Segmented API targets
        ├── targets_dynamic.txt     # Segmented Dynamic targets
        ├── technology.txt          # Detected tech stack
        ├── nuclei_report.txt       # Vulnerabilities
        ├── dalfox_xss.txt          # XSS payloads
        ├── secrets_leak.txt        # Secrets/Keys
        ├── takeover_results.txt    # Subdomain takeovers
        └── ...

```

## Disclaimer & Author's Note

**This is an amateur project.**
This tool was created by a university student who is currently learning Python and is also an amateur bug hunter. The code is largely based on open source and code snippets found on the internet. This repository primarily serves as a **personal backup** and learning archive.

**Legal Warning:**
This tool is developed for educational purposes and authorized security testing only. The author is not responsible for any misuse or damage caused by this program. Always obtain proper authorization before scanning any target.


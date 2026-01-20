import typer
import yaml
import os
import sys
from datetime import datetime
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich import box
from rich.progress import (
    Progress,
    SpinnerColumn,
    TextColumn,
    BarColumn,
    TimeElapsedColumn,
    TaskProgressColumn
)
from modules import recon, crawler, scanner, dirscan, notify, utils

app = typer.Typer()
console = Console()

def load_config():
    try:
        with open("config/config.yaml", "r") as f:
            return yaml.safe_load(f)
    except FileNotFoundError:
        console.print("[bold red]❌ Config file not found![/bold red]")
        sys.exit(1)

CONFIG = load_config()

def get_dir_size(path):
    total_size = 0
    try:
        for dirpath, dirnames, filenames in os.walk(path):
            for f in filenames:
                fp = os.path.join(dirpath, f)
                if not os.path.islink(fp):
                    total_size += os.path.getsize(fp)
        return f"{total_size / (1024 * 1024):.2f} MB"
    except:
        return "0.00 MB"

@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    verify: bool = typer.Option(False, "--verify", help="Check system dependencies and exit")
):

    if verify:
        utils.check_dependencies()
        raise typer.Exit()
    
    if ctx.invoked_subcommand is None:
        console.print(ctx.get_help())
        raise typer.Exit()

def merge_and_clean_files(file_list, output_file):
    if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
        return output_file
    unique_lines = set()
    junk_keywords = ["sg_error.php", "404", "error.php", "cdn-cgi", "logout", "jquery", ".css", ".png", ".jpg", ".svg", ".gif", ".woff"]
    for fpath in file_list:
        if fpath and os.path.exists(fpath):
            with open(fpath, 'r', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if line and not any(k in line for k in junk_keywords):
                        unique_lines.add(line)
    with open(output_file, 'w') as f:
        f.write('\n'.join(unique_lines))
    return output_file

def check_findings_and_notify(step_name, file_path, target, should_notify):
    if file_path and os.path.exists(file_path) and os.path.getsize(file_path) > 0:
        with open(file_path, 'r') as f: count = sum(1 for _ in f)
        console.print(f"[bold red]   [!] ALERT: {count} findings in {step_name}![/bold red]")
        if should_notify:
            msg = f"🚨 *AutoKuro Alert* 🚨\n\n🎯 Target: `{target}`\n🛠 Stage: *{step_name}*\n⚠️ Findings: `{count}`\n📄 File: `{os.path.basename(file_path)}`"
            notify.send_telegram(msg, CONFIG['telegram'])

@app.command()
def start(
    domain: str = typer.Option(..., "-d", "--domain", help="Target Domain"),
    output: str = typer.Option("results", "-o", "--output", help="Output Directory"),
    mode: str = typer.Option("ranger", "-m", "--mode", help="Ghost, Ranger, Blitz"),
    profile: str = typer.Option("desktop", "-hw", "--hardware", help="mobile, desktop, vps"),
    cookie: str = typer.Option(None, "-c", "--cookie", help="Session Cookie"),
    proxy: str = typer.Option(None, "-p", "--proxy", help="Proxy URL"),
    notify_me: bool = typer.Option(False, "-n", "--notify", help="Enable Notifications")
):
    
    utils.check_dependencies()

    if mode not in CONFIG['modes']:
        console.print(f"[bold red]❌ Mode '{mode}' unknown![/bold red]")
        sys.exit(1)
    if profile not in CONFIG['hardware']:
        console.print(f"[bold red]❌ Profile '{profile}' unknown![/bold red]")
        sys.exit(1)
    
    base_config = CONFIG['modes'][mode]
    hw_multiplier = CONFIG['hardware'][profile]['multiplier']
    SELECTED_CONFIG = utils.apply_hardware_profile(base_config, hw_multiplier)

    real_httpx_bin = utils.get_httpx_binary()
    if real_httpx_bin and real_httpx_bin != "httpx-toolkit":
        if "recon_stream" in SELECTED_CONFIG:
            SELECTED_CONFIG['recon_stream'] = SELECTED_CONFIG['recon_stream'].replace("httpx-toolkit", real_httpx_bin)

    if proxy:
        console.print(f"[bold yellow]🕵️ Proxy Enabled: {proxy}[/bold yellow]")
        
        httpx_bin_name = real_httpx_bin if real_httpx_bin else "httpx-toolkit"
        if httpx_bin_name in SELECTED_CONFIG['recon_stream']:
            SELECTED_CONFIG['recon_stream'] = SELECTED_CONFIG['recon_stream'].replace(httpx_bin_name, f"{httpx_bin_name} -http-proxy {proxy}")
            
        proxy_nuclei = f" -proxy {proxy}"
        for k in SELECTED_CONFIG:
            if "nuclei" in k and isinstance(SELECTED_CONFIG[k], str):
                SELECTED_CONFIG[k] += proxy_nuclei
        
        SELECTED_CONFIG['katana'] += f" -proxy {proxy}"
        SELECTED_CONFIG['feroxbuster'] += f" --proxy {proxy}"
        SELECTED_CONFIG['dalfox'] += f" --proxy {proxy}"

    if cookie:
        console.print(f"[bold green]🍪 Auth Mode: ON[/bold green]")
        cookie_header = f" -H 'Cookie: {cookie}'"
        for k in SELECTED_CONFIG:
             if "nuclei" in k and isinstance(SELECTED_CONFIG[k], str):
                SELECTED_CONFIG[k] += cookie_header
        
        SELECTED_CONFIG['katana'] += cookie_header
        SELECTED_CONFIG['feroxbuster'] += cookie_header
        SELECTED_CONFIG['gau'] += f" --cookie '{cookie}'"

    console.print(Panel(
        f"[bold green]Target:[/bold green] {domain}\n"
        f"[bold blue]Mode:[/bold blue]   {mode.upper()}\n"
        f"[bold cyan]Profile:[/bold cyan] {profile.upper()} ({hw_multiplier}x)\n"
        f"[bold yellow]Proxy:[/bold yellow]  {'ON' if proxy else 'OFF'}\n"
        f"[bold magenta]Notify:[/bold magenta] {'ON' if notify_me else 'OFF'}",
        title="🏴 [bold white]AutoKuro QB[/bold white] 🦊",
        border_style="red",
        subtitle="[dim] 戦術偵察 [/dim]",
        padding=(1, 15),
        expand=False 
    ))
    
    if os.path.exists("/dev/shm") and "results" in output:
        console.print("[dim]💡 Tip: Use [bold]/dev/shm[/bold] for RAMDisk speed.[/dim]\n")

    if notify_me:
        notify.send_telegram(f"🚀 *Scan Started* on `{domain}` | Mode: `{mode}` | HW: `{profile}`", CONFIG['telegram'])

    date_str = datetime.now().strftime("%Y-%m-%d") 
    target_dir = os.path.join(output, domain, date_str)
    os.makedirs(target_dir, exist_ok=True)
    
    total_steps = 12
    
    with Progress(
        SpinnerColumn(style="bold red"),
        TextColumn("[bold blue]{task.description}", justify="left"),
        BarColumn(bar_width=None, complete_style="green", finished_style="green"),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        TextColumn("💾 {task.fields[data_size]}"),
        expand=True
    ) as progress:
        
        main_task = progress.add_task("[bold white]Running Pipeline...", total=total_steps, data_size="0.00 MB")

        def update_ui(desc):
            size = get_dir_size(target_dir)
            progress.update(main_task, description=desc, data_size=size)
            progress.advance(main_task)

        progress.update(main_task, description="[1/12] Streamed Recon (Pipe)...")
        expected_live = os.path.join(target_dir, "live_hosts.txt")
        if os.path.exists(expected_live) and os.path.getsize(expected_live) > 0:
            console.print(f"[dim]   ⏩ Checkpoint: Skipping Recon Stream[/dim]")
            live_file = expected_live
            update_ui("[1/12] Recon Done")
        else:
            live_file = recon.execute_streamed_recon(domain, target_dir, SELECTED_CONFIG['recon_stream'])
            update_ui("[1/12] Recon Done")
        
        if not live_file: 
            if notify_me: notify.send_telegram(f"❌ *Scan Failed*: No live hosts found.", CONFIG['telegram'])
            raise typer.Exit()

        progress.update(main_task, description="[2/12] Detecting Tech Stack...")
        expected_tech = os.path.join(target_dir, "technology.txt")
        if not os.path.exists(expected_tech):
            scanner.execute_nuclei_tech_detect(live_file, target_dir, SELECTED_CONFIG['nuclei_tech'])
        else: console.print(f"[dim]   ⏩ Checkpoint: Skipping Tech Detect[/dim]")
        update_ui("[2/12] Tech Done")

        progress.update(main_task, description="[3/12] Port Scanning...")
        expected_ports = os.path.join(target_dir, "open_ports.txt")
        if os.path.exists(expected_ports) and os.path.getsize(expected_ports) > 0:
            console.print(f"[dim]   ⏩ Checkpoint: Skipping Naabu[/dim]")
            update_ui("[3/12] Ports Done")
        else:
            naabu_flags = SELECTED_CONFIG.get('naabu', '-top-ports 1000 -silent')
            recon.execute_naabu(live_file, target_dir, naabu_flags)
            update_ui("[3/12] Ports Done")

        progress.update(main_task, description="[4/12] Checking Takeovers...")
        expected_takeover = os.path.join(target_dir, "takeover_results.txt")
        if not os.path.exists(expected_takeover):
            takeover_file = scanner.execute_nuclei_takeover(live_file, target_dir, SELECTED_CONFIG['nuclei_takeover'])
            check_findings_and_notify("Subdomain Takeover", takeover_file, domain, notify_me)
        else: console.print(f"[dim]   ⏩ Checkpoint: Skipping Takeover[/dim]")
        update_ui("[4/12] Takeover Done")

        progress.update(main_task, description="[5/12] Cloud Enumeration...")
        expected_cloud = os.path.join(target_dir, "cloud_enum_results.txt")
        if not os.path.exists(expected_cloud):
            cloud_file = scanner.execute_nuclei_cloud(live_file, target_dir, SELECTED_CONFIG['nuclei_cloud'])
            check_findings_and_notify("Cloud Assets", cloud_file, domain, notify_me)
        else: console.print(f"[dim]   ⏩ Checkpoint: Skipping Cloud Enum[/dim]")
        update_ui("[5/12] Cloud Done")

        progress.update(main_task, description="[6/12] Smart Dir Busting...")
        expected_ferox = os.path.join(target_dir, "hidden_dirs.txt")
        if os.path.exists(expected_ferox) and os.path.getsize(expected_ferox) > 0:
            console.print(f"[dim]   ⏩ Checkpoint: Skipping Feroxbuster[/dim]")
            ferox_file = expected_ferox
            update_ui("[6/12] DirBust Done")
        else:
            ferox_file = dirscan.execute_feroxbuster(
                live_file, 
                target_dir, 
                SELECTED_CONFIG['feroxbuster'], 
                CONFIG['wordlist_path'], 
                CONFIG['wordlist_fallback'],
                CONFIG.get('priority_keywords', [])
            )
            update_ui("[6/12] DirBust Done")

        progress.update(main_task, description="[7/12] Deep Crawling...")
        expected_gau = os.path.join(target_dir, "archive_urls.txt")
        expected_katana = os.path.join(target_dir, "active_crawl.txt")
        
        if os.path.exists(expected_gau): gau_file = expected_gau
        else: gau_file = crawler.execute_gau(domain, target_dir, SELECTED_CONFIG['gau'])

        if os.path.exists(expected_katana): katana_file = expected_katana
        else: katana_file = crawler.execute_katana(live_file, target_dir, SELECTED_CONFIG['katana'])
        
        all_urls_clean = os.path.join(target_dir, "all_urls_clean.txt")
        merge_and_clean_files([gau_file, katana_file, ferox_file], all_urls_clean)
        update_ui("[7/12] Crawl Done")

        progress.update(main_task, description="[8/12] Mining Parameters...")
        expected_params = os.path.join(target_dir, "parameters.txt")
        if os.path.exists(expected_params):
            console.print(f"[dim]   ⏩ Checkpoint: Skipping ParamSpider[/dim]")
            params_file = expected_params
            update_ui("[8/12] Mining Done")
        else:
            params_file = crawler.execute_paramspider(domain, target_dir, SELECTED_CONFIG['paramspider'])
            update_ui("[8/12] Mining Done")

        progress.update(main_task, description="[9/12] JS Token Analysis...")
        js_vuln_file = os.path.join(target_dir, "nuclei_report_secrets.txt")
        if not os.path.exists(js_vuln_file):
            js_targets = os.path.join(target_dir, "js_files.txt")
            os.system(f"grep '.js' {all_urls_clean} > {js_targets}")
            if os.path.exists(js_targets) and os.path.getsize(js_targets) > 0:
                js_vuln = scanner.execute_nuclei(js_targets, target_dir, SELECTED_CONFIG['nuclei_tokens'], suffix="_secrets")
                check_findings_and_notify("JS Secrets", js_vuln, domain, notify_me)
        else: console.print(f"[dim]   ⏩ Checkpoint: Skipping JS Analysis[/dim]")
        update_ui("[9/12] JS Done")

        progress.update(main_task, description="[10/12] Nuclei Scanning...")
        expected_nuclei = os.path.join(target_dir, "nuclei_report.txt")
        if os.path.exists(expected_nuclei):
            console.print(f"[dim]   ⏩ Checkpoint: Skipping Nuclei[/dim]")
            nuclei_vuln = expected_nuclei
            update_ui("[10/12] Nuclei Done")
        else:
            nuclei_vuln = scanner.execute_nuclei(live_file, target_dir, SELECTED_CONFIG['nuclei'])
            check_findings_and_notify("Nuclei Vulns", nuclei_vuln, domain, notify_me)
            update_ui("[10/12] Nuclei Done")

        progress.update(main_task, description="[11/12] XSS Check...")
        expected_dalfox = os.path.join(target_dir, "dalfox_xss.txt")
        if not os.path.exists(expected_dalfox):
            target_xss = params_file if (params_file and os.path.exists(params_file)) else all_urls_clean
            xss_file = scanner.execute_dalfox(target_xss, target_dir, SELECTED_CONFIG['dalfox'])
            check_findings_and_notify("XSS Findings", xss_file, domain, notify_me)
        else: console.print(f"[dim]   ⏩ Checkpoint: Skipping Dalfox[/dim]")
        update_ui("[11/12] XSS Done")

        progress.update(main_task, description="[12/12] Secrets Check...")
        expected_secrets = os.path.join(target_dir, "secrets_leak.txt")
        if not os.path.exists(expected_secrets):
            secrets_file = scanner.execute_trufflehog(target_dir, SELECTED_CONFIG['trufflehog'])
            check_findings_and_notify("Trufflehog Secrets", secrets_file, domain, notify_me)
        else: console.print(f"[dim]   ⏩ Checkpoint: Skipping Trufflehog[/dim]")
        update_ui("[12/12] Finished")

    console.print("\n[bold green]✅ MISSION COMPLETE![/bold green]")
    if notify_me: notify.send_telegram(f"✅ *Scan Finished* for `{domain}`.", CONFIG['telegram'])
    console.print(f"[yellow]📂 Report Directory: {target_dir}[/yellow]")

if __name__ == "__main__":
    app()
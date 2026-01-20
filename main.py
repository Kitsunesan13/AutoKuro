import typer
import yaml
import os
import sys
from datetime import datetime
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
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
    mode: str = typer.Option("ranger", "-m", "--mode", help="Mode: ghost, ranger, blitz"),
    cookie: str = typer.Option(None, "-c", "--cookie", help="Session Cookie"),
    proxy: str = typer.Option(None, "-p", "--proxy", help="Proxy URL"),
    notify_me: bool = typer.Option(False, "-n", "--notify", help="Enable Notifications")
):

    utils.check_dependencies()

    if mode not in CONFIG['modes']:
        console.print(f"[bold red]❌ Mode '{mode}' is unknown! Use: ghost, ranger, or blitz[/bold red]")
        sys.exit(1)
        
    SELECTED_CONFIG = CONFIG['modes'][mode]
    
    if proxy:
        console.print(f"[bold yellow]🕵️ Proxy Enabled: {proxy}[/bold yellow]")
        SELECTED_CONFIG['httpx'] += f" -http-proxy {proxy}"
        proxy_nuclei = f" -proxy {proxy}"
        SELECTED_CONFIG['nuclei'] += proxy_nuclei
        SELECTED_CONFIG['nuclei_tokens'] += proxy_nuclei
        SELECTED_CONFIG['nuclei_cloud'] += proxy_nuclei
        SELECTED_CONFIG['nuclei_takeover'] += proxy_nuclei
        SELECTED_CONFIG['katana'] += f" -proxy {proxy}"
        SELECTED_CONFIG['feroxbuster'] += f" --proxy {proxy}"
        SELECTED_CONFIG['dalfox'] += f" --proxy {proxy}"

    if cookie:
        console.print(f"[bold green]🍪 Auth Mode: ON[/bold green]")
        cookie_header = f" -H 'Cookie: {cookie}'"
        SELECTED_CONFIG['nuclei'] += cookie_header
        SELECTED_CONFIG['nuclei_tokens'] += cookie_header
        SELECTED_CONFIG['nuclei_cloud'] += cookie_header
        SELECTED_CONFIG['katana'] += cookie_header
        SELECTED_CONFIG['feroxbuster'] += cookie_header
        SELECTED_CONFIG['gau'] += f" --cookie '{cookie}'"

    console.print(Panel(
        f"[bold green]Target:[/bold green] {domain}\n"
        f"[bold blue]Mode:[/bold blue] {mode.upper()}\n"
        f"[bold yellow]Proxy:[/bold yellow] {'ON' if proxy else 'OFF'}\n"
        f"[bold magenta]Notify:[/bold magenta] {'ON' if notify_me else 'OFF'}",
        title="🏴 [bold white]AutoKuro QB[/bold white] 🦊",
        border_style="red",
        subtitle="[dim] 戦術偵察 [/dim]",
        padding=(1, 15),
        expand=False 
    ))

    if notify_me:
        notify.send_telegram(f"🚀 *Scan Started* on `{domain}` | Mode: `{mode}`", CONFIG['telegram'])

    date_str = datetime.now().strftime("%Y-%m-%d") 
    target_dir = os.path.join(output, domain, date_str)
    os.makedirs(target_dir, exist_ok=True)
    
    total_steps = 11
    
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

        progress.update(main_task, description="[1/11] Subdomain Enum...")
        expected_subs = os.path.join(target_dir, "subdomains.txt")
        if os.path.exists(expected_subs) and os.path.getsize(expected_subs) > 0:
            console.print(f"[dim]   ⏩ Checkpoint: Skipping Subfinder[/dim]")
            subs_file = expected_subs
            update_ui("[1/11] Subdomain Done")
        else:
            subs_file = recon.execute_subfinder(domain, target_dir, SELECTED_CONFIG['subfinder'])
            update_ui("[1/11] Subdomain Done")

        progress.update(main_task, description="[2/11] Port Scanning...")
        expected_ports = os.path.join(target_dir, "open_ports.txt")
        if os.path.exists(expected_ports) and os.path.getsize(expected_ports) > 0:
            console.print(f"[dim]   ⏩ Checkpoint: Skipping Naabu[/dim]")
            ports_file = expected_ports
            update_ui("[2/11] Ports Done")
        else:
            ports_file = recon.execute_naabu(subs_file if subs_file else domain, target_dir, SELECTED_CONFIG['naabu'])
            update_ui("[2/11] Ports Done")

        progress.update(main_task, description="[3/11] Filtering Live Hosts...")
        expected_live = os.path.join(target_dir, "live_hosts.txt")
        if os.path.exists(expected_live) and os.path.getsize(expected_live) > 0:
            console.print(f"[dim]   ⏩ Checkpoint: Skipping Httpx[/dim]")
            live_file = expected_live
            update_ui("[3/11] Filter Done")
        else:
            input_httpx = ports_file if ports_file else subs_file
            if not input_httpx:
                 with open(os.path.join(target_dir, "temp_target.txt"), "w") as f: f.write(domain)
                 input_httpx = os.path.join(target_dir, "temp_target.txt")
            live_file = recon.execute_httpx(input_httpx, target_dir, SELECTED_CONFIG['httpx'])
            update_ui("[3/11] Filter Done")
        
        if not live_file: 
            if notify_me: notify.send_telegram(f"❌ *Scan Failed*: No live hosts found.", CONFIG['telegram'])
            raise typer.Exit()

        progress.update(main_task, description="[4/11] Checking Takeovers...")
        expected_takeover = os.path.join(target_dir, "takeover_results.txt")
        if not os.path.exists(expected_takeover):
            takeover_file = scanner.execute_nuclei_takeover(subs_file if subs_file else domain, target_dir, SELECTED_CONFIG['nuclei_takeover'])
            check_findings_and_notify("Subdomain Takeover", takeover_file, domain, notify_me)
        else: console.print(f"[dim]   ⏩ Checkpoint: Skipping Takeover[/dim]")
        update_ui("[4/11] Takeover Done")

        progress.update(main_task, description="[5/11] Cloud Enumeration...")
        expected_cloud = os.path.join(target_dir, "cloud_enum_results.txt")
        if not os.path.exists(expected_cloud):
            cloud_file = scanner.execute_nuclei_cloud(subs_file if subs_file else domain, target_dir, SELECTED_CONFIG['nuclei_cloud'])
            check_findings_and_notify("Cloud Assets", cloud_file, domain, notify_me)
        else: console.print(f"[dim]   ⏩ Checkpoint: Skipping Cloud Enum[/dim]")
        update_ui("[5/11] Cloud Done")

        progress.update(main_task, description="[6/11] Smart Dir Busting...")
        expected_ferox = os.path.join(target_dir, "hidden_dirs.txt")
        if os.path.exists(expected_ferox) and os.path.getsize(expected_ferox) > 0:
            console.print(f"[dim]   ⏩ Checkpoint: Skipping Feroxbuster[/dim]")
            ferox_file = expected_ferox
            update_ui("[6/11] DirBust Done")
        else:
            ferox_file = dirscan.execute_feroxbuster(live_file, target_dir, SELECTED_CONFIG['feroxbuster'], CONFIG['wordlist_path'], CONFIG['wordlist_fallback'])
            update_ui("[6/11] DirBust Done")

        progress.update(main_task, description="[7/11] Deep Crawling...")
        expected_gau = os.path.join(target_dir, "archive_urls.txt")
        expected_katana = os.path.join(target_dir, "active_crawl.txt")
        
        if os.path.exists(expected_gau): gau_file = expected_gau
        else: gau_file = crawler.execute_gau(domain, target_dir, SELECTED_CONFIG['gau'])

        if os.path.exists(expected_katana): katana_file = expected_katana
        else: katana_file = crawler.execute_katana(live_file, target_dir, SELECTED_CONFIG['katana'])
        
        all_urls_clean = os.path.join(target_dir, "all_urls_clean.txt")
        merge_and_clean_files([gau_file, katana_file, ferox_file], all_urls_clean)
        update_ui("[7/11] Crawl Done")

        progress.update(main_task, description="[8/11] Mining Parameters...")
        expected_params = os.path.join(target_dir, "parameters.txt")
        if os.path.exists(expected_params):
            console.print(f"[dim]   ⏩ Checkpoint: Skipping ParamSpider[/dim]")
            params_file = expected_params
            update_ui("[8/11] Mining Done")
        else:
            params_file = crawler.execute_paramspider(domain, target_dir, SELECTED_CONFIG['paramspider'])
            update_ui("[8/11] Mining Done")

        progress.update(main_task, description="[9/11] JS Token Analysis...")
        js_vuln_file = os.path.join(target_dir, "nuclei_report_secrets.txt")
        if not os.path.exists(js_vuln_file):
            js_targets = os.path.join(target_dir, "js_files.txt")
            os.system(f"grep '.js' {all_urls_clean} > {js_targets}")
            if os.path.exists(js_targets) and os.path.getsize(js_targets) > 0:
                js_vuln = scanner.execute_nuclei(js_targets, target_dir, SELECTED_CONFIG['nuclei_tokens'], suffix="_secrets")
                check_findings_and_notify("JS Secrets", js_vuln, domain, notify_me)
        else: console.print(f"[dim]   ⏩ Checkpoint: Skipping JS Analysis[/dim]")
        update_ui("[9/11] JS Done")

        progress.update(main_task, description="[10/11] Nuclei Scanning...")
        expected_nuclei = os.path.join(target_dir, "nuclei_report.txt")
        if os.path.exists(expected_nuclei):
            console.print(f"[dim]   ⏩ Checkpoint: Skipping Nuclei[/dim]")
            nuclei_vuln = expected_nuclei
            update_ui("[10/11] Nuclei Done")
        else:
            nuclei_vuln = scanner.execute_nuclei(live_file, target_dir, SELECTED_CONFIG['nuclei'])
            check_findings_and_notify("Nuclei Vulns", nuclei_vuln, domain, notify_me)
            update_ui("[10/11] Nuclei Done")

        progress.update(main_task, description="[11/11] XSS & Secret Check...")
        
        expected_dalfox = os.path.join(target_dir, "dalfox_xss.txt")
        if not os.path.exists(expected_dalfox):
            target_xss = params_file if (params_file and os.path.exists(params_file)) else all_urls_clean
            xss_file = scanner.execute_dalfox(target_xss, target_dir, SELECTED_CONFIG['dalfox'])
            check_findings_and_notify("XSS Findings", xss_file, domain, notify_me)
        else: console.print(f"[dim]   ⏩ Checkpoint: Skipping Dalfox[/dim]")

        expected_secrets = os.path.join(target_dir, "secrets_leak.txt")
        if not os.path.exists(expected_secrets):
            secrets_file = scanner.execute_trufflehog(target_dir, SELECTED_CONFIG['trufflehog'])
            check_findings_and_notify("Trufflehog Secrets", secrets_file, domain, notify_me)
        else: console.print(f"[dim]   ⏩ Checkpoint: Skipping Trufflehog[/dim]")
             
        update_ui("[11/11] Finished")

    console.print("\n[bold green]✅ MISSION COMPLETE![/bold green]")
    if notify_me: notify.send_telegram(f"✅ *Scan Finished* for `{domain}`.", CONFIG['telegram'])
    console.print(f"[yellow]📂 Report Directory: {target_dir}[/yellow]")

if __name__ == "__main__":
    app()
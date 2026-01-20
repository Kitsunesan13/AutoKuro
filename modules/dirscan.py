import os
import json
from .utils import run_os_command
from rich.console import Console

console = Console()

def get_valid_wordlist(primary, fallback):
    if os.path.exists(primary): return primary
    elif os.path.exists(fallback): return fallback
    else: return None

def filter_priority_targets(input_file, output_dir):
    priority_file = os.path.join(output_dir, "priority_hosts_ferox.txt")
    keywords = ["admin", "api", "dev", "stag", "test", "corp", "intranet", "dashboard", "login"]
    
    priority_urls = set()
    total_hosts = 0
    
    with open(input_file, 'r') as f:
        for line in f:
            total_hosts += 1
            url = line.strip()
            if any(k in url.lower() for k in keywords):
                priority_urls.add(url)
    
    if total_hosts <= 20: return input_file
    
    if not priority_urls:
        os.system(f"head -n 10 {input_file} > {priority_file}")
        return priority_file

    with open(priority_file, 'w') as f:
        f.write('\n'.join(priority_urls))
        
    console.print(f"[dim]   [i] Smart Filter: {len(priority_urls)} priority hosts out of {total_hosts}.[/dim]")
    return priority_file

def execute_feroxbuster(input_file, output_dir, flags, wordlist_primary, wordlist_fallback):
    wordlist = get_valid_wordlist(wordlist_primary, wordlist_fallback)
    if not wordlist:
        console.print("[red][X] Error: No wordlist found.[/red]")
        return None

    target_file = filter_priority_targets(input_file, output_dir)
    json_output = os.path.join(output_dir, "ferox_raw.json")
    final_txt_output = os.path.join(output_dir, "hidden_dirs.txt")
    
    full_cmd = f"cat {target_file} | feroxbuster {flags} -w {wordlist} -o {json_output}"
    run_os_command(full_cmd, "Feroxbuster")

    urls = set()
    if os.path.exists(json_output):
        try:
            with open(json_output, 'r') as f:
                for line in f:
                    try:
                        data = json.loads(line)
                        if "url" in data: urls.add(data["url"])
                    except: pass
        except: pass
    
    if urls:
        with open(final_txt_output, 'w') as f:
            f.write('\n'.join(urls))
        console.print(f"[green]   [+] Found {len(urls)} hidden directories.[/green]")
        return final_txt_output
    return None
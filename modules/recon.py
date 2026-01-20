import os
from .utils import run_os_command

def execute_subfinder(domain, output_dir, flags):
    output_file = os.path.join(output_dir, "subdomains.txt")
    cmd = f"subfinder -d {domain} {flags} -o {output_file}"
    run_os_command(cmd, "Subfinder")
    if os.path.exists(output_file) and os.path.getsize(output_file) > 0: return output_file
    return None

def execute_naabu(domain, output_dir, flags):
    output_file = os.path.join(output_dir, "open_ports.txt")
    cmd = f"naabu -host {domain} {flags} -o {output_file}"
    run_os_command(cmd, "Naabu (Port Scan)")
    if os.path.exists(output_file) and os.path.getsize(output_file) > 0: return output_file
    return None

def execute_httpx(input_file, output_dir, flags):
    output_file = os.path.join(output_dir, "live_hosts.txt")
    cmd = f"cat {input_file} | httpx-toolkit {flags} -o {output_file}"
    run_os_command(cmd, "Httpx (Live Check)")
    if os.path.exists(output_file) and os.path.getsize(output_file) > 0: return output_file
    return None
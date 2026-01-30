import os
from urllib.parse import urlparse
from .utils import run_os_command, run_piped_command, run_async_command

def execute_streamed_recon(domain, output_dir, pipeline_cmd, timeout=None):
    live_file = os.path.join(output_dir, "live_hosts.txt")
    parts = pipeline_cmd.split("|", 1)
    if len(parts) < 2: return None 

    cmd1 = f"{parts[0].strip()} -d {domain}"
    cmd2 = f"{parts[1].strip()} -o {live_file}"
    
    success = run_piped_command(cmd1, cmd2, "Streamed Recon", timeout)
    if success and os.path.exists(live_file) and os.path.getsize(live_file) > 0:
        return live_file
    return None

async def execute_naabu_async(input_file, output_dir, flags, timeout=None):

    clean_input_file = os.path.join(output_dir, "naabu_targets.txt")
    
    try:
        unique_hosts = set()
        with open(input_file, 'r') as f:
            for line in f:
                url = line.strip()
                if not url: continue
                if "://" in url:
                    parsed = urlparse(url)
                    hostname = parsed.netloc
                    if hostname: unique_hosts.add(hostname)
                else:
                    unique_hosts.add(url)
        
        if unique_hosts:
            with open(clean_input_file, 'w') as f:
                f.write('\n'.join(unique_hosts))
        else:
            return None 
            
    except Exception:
        clean_input_file = input_file

    output_file = os.path.join(output_dir, "open_ports.txt")
    cmd = f"naabu -list {clean_input_file} {flags} -o {output_file}"
    
    await run_async_command(cmd, "Naabu", timeout, adaptive=True)
    if os.path.exists(output_file) and os.path.getsize(output_file) > 0: return output_file
    return None

def execute_naabu(input_file, output_dir, flags, timeout=None):
    output_file = os.path.join(output_dir, "open_ports.txt")
    cmd = f"naabu -list {input_file} {flags} -o {output_file}"
    run_os_command(cmd, "Naabu", timeout)
    if os.path.exists(output_file) and os.path.getsize(output_file) > 0: return output_file
    return None
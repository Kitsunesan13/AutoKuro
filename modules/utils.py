import subprocess
import shutil
import sys
import re
import shlex
import os
import asyncio
from rich.console import Console

console = Console()

WAF_SIGNATURES = [
    "Cloudflare Ray ID",
    "Attention Required! | Cloudflare",
    "Security check to access",
    "Ray ID:",
    "Error 1020",
    "Error 1015", 
    "The request was blocked",
    "You are unable to access",
    "WAF",
    "Firewall",
    "Imperva",
    "Incapsula",
    "AkamaiGHost",
    "banned",
    "Access Denied"
]

def check_waf_block(output_str):

    for sig in WAF_SIGNATURES:
        if sig in output_str:
            return True, sig
    return False, None

# --- OPTIMIZATION: ADAPTIVE RATE LIMIT ---
def reduce_rate_limit(command_str):
    new_cmd = command_str
    patterns = {
        r'(-rl|--rate-limit)\s+(\d+)': 0.5,
        r'(-rate)\s+(\d+)': 0.5,
        r'(-t|--threads)\s+(\d+)': 0.7,
        r'(-c|--concurrency)\s+(\d+)': 0.7,
        r'(--worker)\s+(\d+)': 0.5
    }
    modified = False
    for pat, factor in patterns.items():
        match = re.search(pat, new_cmd)
        if match:
            flag = match.group(1)
            val = int(match.group(2))
            new_val = max(2, int(val * factor))
            new_cmd = re.sub(pat, f"{flag} {new_val}", new_cmd)
            modified = True
    return new_cmd, modified

async def run_async_command(command, step_name, timeout=None, adaptive=True):
    current_cmd = command
    retries = 2 if adaptive else 0
    attempt = 0

    while attempt <= retries:
        try:
            if isinstance(current_cmd, str): safe_args = shlex.split(current_cmd)
            else: safe_args = current_cmd

            process = await asyncio.create_subprocess_exec(
                *safe_args,
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE
            )

            try:
                stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)
                
                out_str = stdout.decode().strip()
                err_str = stderr.decode().strip()
                combined_output = f"{out_str}\n{err_str}"

                is_blocked, sig = check_waf_block(combined_output)
                if is_blocked:
                    console.print(f"\n[bold white on red]🚨 EMERGENCY STOP: WAF BLOCKED DETECTED! ({sig})[/bold white on red]")
                    console.print(f"[bold red]⛔ The tool is stopping immediately to protect your IP Reputation.[/bold red]")
                    console.print(f"[dim]Module triggered: {step_name}[/dim]")
                    sys.exit(1)

                if process.returncode != 0:
                    err_msg = err_str if err_str else "Unknown Error"
                    if not err_msg: err_msg = out_str # Kadang error ada di stdout

                    if attempt < retries:
                        console.print(f"[bold yellow]⚠️ {step_name} failed. Adapting strategy... (Retry {attempt+1}/{retries})[/bold yellow]")
                        current_cmd, mod = reduce_rate_limit(current_cmd)
                        if not mod: break
                        attempt += 1
                        continue
                    else:
                        console.print(f"\n[bold red]❌ Error in {step_name} (Final):[/bold red]")
                        console.print(f"[dim]{err_msg}[/dim]")
                        return False
                
                return True

            except asyncio.TimeoutError:
                try: process.kill() 
                except: pass
                if attempt < retries:
                    console.print(f"[bold yellow]⏳ Timeout in {step_name}. Throttling down... (Retry {attempt+1}/{retries})[/bold yellow]")
                    current_cmd, _ = reduce_rate_limit(current_cmd)
                    attempt += 1
                    continue
                else:
                    console.print(f"\n[bold red]⏳ Timeout in {step_name} ({timeout}s) - Gave Up![/bold red]")
                    return False

        except Exception as e:
            console.print(f"\n[bold red]❌ Exec Error in {step_name}: {str(e)}[/bold red]")
            return False

# --- LEGACY SYNC EXECUTORS ---
def run_os_command(command, step_name, timeout=None):
    try:
        if isinstance(command, str): safe_args = shlex.split(command)
        else: safe_args = command
        result = subprocess.run(
            safe_args, shell=False, check=False,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, 
            text=True, timeout=timeout
        )
        
        is_blocked, sig = check_waf_block(result.stdout + result.stderr)
        if is_blocked:
             console.print(f"\n[bold white on red]🚨 EMERGENCY STOP: WAF BLOCKED ({sig})[/bold white on red]")
             sys.exit(1)

        if result.returncode != 0:
             console.print(f"\n[bold red]❌ Error in {step_name}:[/bold red]")
             console.print(f"[dim]{result.stderr.strip() or result.stdout.strip()}[/dim]")
             return False
        return True
    except subprocess.TimeoutExpired:
        console.print(f"\n[bold red]⏳ Timeout in {step_name}![/bold red]")
        return False
    except Exception as e:
        console.print(f"\n[bold red]❌ Unexpected Error in {step_name}: {str(e)}[/bold red]")
        return False

def run_piped_command(cmd1_str, cmd2_str, step_name, timeout=None):
    try:
        args1 = shlex.split(cmd1_str)
        args2 = shlex.split(cmd2_str)
        p1 = subprocess.Popen(args1, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        p2 = subprocess.Popen(args2, stdin=p1.stdout, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        p1.stdout.close()
        stderr_out = p2.communicate(timeout=timeout)[1]
        
        if stderr_out:
            is_blocked, sig = check_waf_block(stderr_out.decode())
            if is_blocked:
                console.print(f"\n[bold white on red]🚨 EMERGENCY STOP: WAF BLOCKED ({sig})[/bold white on red]")
                sys.exit(1)

        if p2.returncode != 0:
            console.print(f"\n[bold red]❌ Pipe Error in {step_name}:[/bold red]")
            if stderr_out: console.print(f"[dim]{stderr_out.decode('utf-8').strip()}[/dim]")
            return False
        return True
    except subprocess.TimeoutExpired:
        p1.kill()
        p2.kill()
        console.print(f"\n[bold red]⏳ Timeout in {step_name} (Pipeline)![/bold red]")
        return False
    except Exception as e:
        console.print(f"\n[bold red]❌ Pipeline Failure: {str(e)}[/bold red]")
        return False

def get_httpx_binary():
    if shutil.which("httpx-toolkit"): return "httpx-toolkit"
    elif shutil.which("httpx"): return "httpx"
    else: return None

def apply_hardware_profile(config_dict, multiplier):
    if multiplier == 1.0: return config_dict.copy()
    scaled_config = config_dict.copy()
    patterns = [r'(-t|--threads)\s+(\d+)', r'(-c|--concurrency)\s+(\d+)', 
                r'(-rl|--rate-limit)\s+(\d+)', r'(-rate)\s+(\d+)', r'(--worker)\s+(\d+)']
    def scaler(match):
        return f"{match.group(1)} {max(1, int(int(match.group(2)) * multiplier))}"
    for key, val in scaled_config.items():
        if isinstance(val, str):
            for pat in patterns: val = re.sub(pat, scaler, val)
            scaled_config[key] = val
    return scaled_config

def check_dependencies():
    tools = ["subfinder", "naabu", "nuclei", "feroxbuster", "gau", "katana", "paramspider", "dalfox", "trufflehog"]
    missing = [t for t in tools if not shutil.which(t)]
    if not get_httpx_binary(): missing.append("httpx")
    if missing:
        console.print(f"[bold red]❌ Missing: {', '.join(missing)}[/bold red]")
        sys.exit(1)
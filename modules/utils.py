import subprocess
import shutil
import sys
import re
from rich.console import Console

console = Console()

def run_os_command(command: str, step_name: str):

    try:
        result = subprocess.run(
            command, 
            shell=True, 
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True
        )
        return True
    except subprocess.CalledProcessError as e:
        console.print(f"\n[bold red]❌ Error in {step_name}:[/bold red]")
        console.print(f"[dim]{e.stderr.strip()}[/dim]")
        return False

def get_httpx_binary():

    if shutil.which("httpx-toolkit"):
        return "httpx-toolkit"
    elif shutil.which("httpx"):
        return "httpx"
    else:
        return None

def apply_hardware_profile(config_dict, multiplier):

    if multiplier == 1.0:
        return config_dict.copy()
    
    scaled_config = config_dict.copy()
    
    patterns = [
        r'(-t|--threads)\s+(\d+)',
        r'(-c|--concurrency)\s+(\d+)',
        r'(-rl|--rate-limit)\s+(\d+)',
        r'(-rate)\s+(\d+)',
        r'(--worker)\s+(\d+)'
    ]
    
    def scaler(match):
        flag = match.group(1)
        value = int(match.group(2))
        new_value = max(1, int(value * multiplier)) 
        return f"{flag} {new_value}"

    for key, command_str in scaled_config.items():
        if isinstance(command_str, str):
            temp_str = command_str
            for pat in patterns:
                temp_str = re.sub(pat, scaler, temp_str)
            scaled_config[key] = temp_str
            
    return scaled_config

def check_dependencies():

    required_tools = [
        "subfinder", "naabu", "nuclei", 
        "feroxbuster", "gau", "katana", "paramspider", 
        "dalfox", "trufflehog"
    ]
    
    missing_tools = []
    

    for tool in required_tools:
        if not shutil.which(tool):
            missing_tools.append(tool)
            
    if not get_httpx_binary():
        missing_tools.append("httpx (or httpx-toolkit)")
    
    if missing_tools:
        console.print(f"[bold red]❌ Error: Missing dependencies:[/bold red]")
        for t in missing_tools:
            console.print(f"   - [yellow]{t}[/yellow]")
        console.print("\n[dim]Please install them manually.[/dim]")
        sys.exit(1)
    
    console.print("[bold green]✅ System Check: All dependencies ready.[/bold green]")
import subprocess
import shutil
import sys
from rich.console import Console

console = Console()

def run_os_command(command: str, step_name: str):

    try:
        subprocess.run(
            command, 
            shell=True, 
            check=True, 
            stdout=subprocess.DEVNULL, 
            stderr=subprocess.DEVNULL
        )
        return True
    except subprocess.CalledProcessError:
        return False

def check_dependencies():

    required_tools = [
        "subfinder", "naabu", "httpx-toolkit", "nuclei", 
        "feroxbuster", "gau", "katana", "paramspider", 
        "dalfox", "trufflehog"
    ]
    
    missing_tools = []
    for tool in required_tools:
        if not shutil.which(tool):
            missing_tools.append(tool)
    
    if missing_tools:
        console.print(f"[bold red]❌ Error: Missing dependencies:[/bold red]")
        for t in missing_tools:
            console.print(f"   - [yellow]{t}[/yellow]")
        console.print("\n[dim]Please install them or check your PATH.[/dim]")
        sys.exit(1)
    
    console.print("[bold green]✅ System Check: All dependencies ready.[/bold green]")
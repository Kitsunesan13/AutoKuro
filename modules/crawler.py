import os
import shutil
from .utils import run_os_command
from rich.console import Console

console = Console()

def execute_gau(domain, output_dir, flags):
    output_file = os.path.join(output_dir, "archive_urls.txt")
    cmd = f"gau {domain} {flags} | sort -u > {output_file}"
    run_os_command(cmd, "Gau")
    if os.path.exists(output_file) and os.path.getsize(output_file) > 0: return output_file
    return None

def execute_katana(input_file, output_dir, flags):
    output_file = os.path.join(output_dir, "active_crawl.txt")
    cmd = f"katana -list {input_file} {flags} -o {output_file}"
    run_os_command(cmd, "Katana")
    if os.path.exists(output_file) and os.path.getsize(output_file) > 0: return output_file
    return None

def execute_paramspider(domain, output_dir, flags):
    cmd = f"paramspider -d {domain} {flags} --level high"
    run_os_command(cmd, "ParamSpider")
    
    expected_output_relative = os.path.join("results", f"{domain}.txt")
    final_destination = os.path.join(output_dir, "parameters.txt")
    
    if os.path.exists(expected_output_relative):
        if os.path.getsize(expected_output_relative) > 0:
            shutil.move(expected_output_relative, final_destination)
            try: os.rmdir("results") 
            except: pass
            return final_destination
    elif os.path.exists(f"{domain}.txt"):
        shutil.move(f"{domain}.txt", final_destination)
        return final_destination

    return None
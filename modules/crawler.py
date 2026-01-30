import os
import shutil
from .utils import run_async_command
from .db import ScanDatabase

async def execute_gau(domain, output_dir, flags, timeout=None):
    output_file = os.path.join(output_dir, "archive_urls.txt")
    # FIX: Menggunakan --o (double dash)
    cmd = f"gau {domain} {flags} --o {output_file}"
    await run_async_command(cmd, "Gau", timeout, adaptive=True)
    if os.path.exists(output_file) and os.path.getsize(output_file) > 0: return output_file
    return None

async def execute_katana(input_file, output_dir, flags, timeout=None):
    output_file = os.path.join(output_dir, "active_crawl.txt")
    cmd = f"katana -list {input_file} {flags} -o {output_file}"
    await run_async_command(cmd, "Katana", timeout, adaptive=True)
    if os.path.exists(output_file) and os.path.getsize(output_file) > 0: return output_file
    return None

async def execute_paramspider(domain, output_dir, flags, timeout=None):
    cmd = f"paramspider -d {domain} {flags}"
    await run_async_command(cmd, "ParamSpider", timeout, adaptive=True)
    
    expected_output_relative = os.path.join("results", f"{domain}.txt")
    final_destination = os.path.join(output_dir, "parameters.txt")
    
    if os.path.exists(expected_output_relative) and os.path.getsize(expected_output_relative) > 0:
        shutil.move(expected_output_relative, final_destination)
        try: os.rmdir("results") 
        except: pass
        return final_destination
    elif os.path.exists(f"{domain}.txt"):
        shutil.move(f"{domain}.txt", final_destination)
        return final_destination
    return None

def file_line_generator(filepath):
    if filepath and os.path.exists(filepath):
        with open(filepath, 'r', errors='ignore') as f:
            for line in f: yield line.strip()

def merge_crawl_results(output_dir):
    files = ["archive_urls.txt", "active_crawl.txt", "hidden_dirs.txt", "parameters.txt"]
    junk = [".png", ".jpg", ".gif", ".css", ".svg", ".woff", ".eot", ".ttf", ".ico"]
    
    db = ScanDatabase()
    for fname in files:
        fpath = os.path.join(output_dir, fname)
        if os.path.exists(fpath):
            gen = file_line_generator(fpath)
            clean_gen = (url for url in gen if url and not any(url.endswith(ext) for ext in junk))
            db.bulk_insert_urls(clean_gen, source=fname)
            
    clean_path = os.path.join(output_dir, "all_urls_clean.txt")
    with open(clean_path, 'w') as f:
        for url in db.get_unique_urls():
            f.write(f"{url}\n")
    db.close()
    return clean_path
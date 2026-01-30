import os
from .utils import run_async_command

async def execute_nuclei_tech_detect(input_file, output_dir, flags, timeout=None):
    output_file = os.path.join(output_dir, "technology.txt")
    cmd = f"nuclei -l {input_file} {flags} -o {output_file}"
    await run_async_command(cmd, "Nuclei (Tech)", timeout, adaptive=True)
    return output_file

async def execute_nuclei_takeover(input_file, output_dir, flags, timeout=None):
    output_file = os.path.join(output_dir, "takeover_results.txt")
    cmd = f"nuclei -l {input_file} {flags} -o {output_file}"
    await run_async_command(cmd, "Nuclei (Takeover)", timeout, adaptive=True)
    return output_file

async def execute_nuclei_cloud(input_file, output_dir, flags, timeout=None):
    output_file = os.path.join(output_dir, "cloud_enum_results.txt")
    cmd = f"nuclei -l {input_file} {flags} -o {output_file}"
    await run_async_command(cmd, "Nuclei (Cloud Enum)", timeout, adaptive=True)
    return output_file

async def execute_nuclei(input_file, output_dir, flags, suffix="", timeout=None):
    output_file = os.path.join(output_dir, f"nuclei_report{suffix}.txt")
    cmd = f"nuclei -l {input_file} {flags} -o {output_file}"
    await run_async_command(cmd, f"Nuclei Scan {suffix}", timeout, adaptive=True)
    return output_file

async def execute_dalfox(input_file, output_dir, flags, timeout=None):
    output_file = os.path.join(output_dir, "dalfox_xss.txt")
    filtered_input = os.path.join(output_dir, "dalfox_targets.txt")
    
    os.system(f"grep '?' {input_file} > {filtered_input}")
    
    if not os.path.exists(filtered_input) or os.path.getsize(filtered_input) == 0:
        return None

    cmd = f"dalfox file {filtered_input} {flags} -o {output_file}"
    await run_async_command(cmd, "Dalfox", timeout, adaptive=True)
    
    if os.path.exists(output_file) and os.path.getsize(output_file) > 0: return output_file
    return None

async def execute_trufflehog(output_dir, flags, timeout=None):
    report_file = os.path.join(output_dir, "secrets_leak.txt")
    safe_cmd = ["bash", "-c", f"trufflehog {flags} {output_dir} > {report_file}"]
    
    import asyncio, subprocess
    try:
        process = await asyncio.create_subprocess_exec(
            *safe_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE
        )
        await asyncio.wait_for(process.communicate(), timeout=timeout)
    except:
        pass
    return report_file
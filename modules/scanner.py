import os
from .utils import run_os_command

def execute_nuclei_takeover(input_file, output_dir, flags):
    output_file = os.path.join(output_dir, "takeover_results.txt")
    cmd = f"nuclei -l {input_file} {flags} -o {output_file}"
    run_os_command(cmd, "Nuclei (Takeover)")
    return output_file

def execute_nuclei_cloud(input_file, output_dir, flags):
    output_file = os.path.join(output_dir, "cloud_enum_results.txt")
    cmd = f"nuclei -l {input_file} {flags} -o {output_file}"
    run_os_command(cmd, "Nuclei (Cloud Enum)")
    return output_file

def execute_nuclei(input_file, output_dir, flags, suffix=""):
    output_file = os.path.join(output_dir, f"nuclei_report{suffix}.txt")
    cmd = f"nuclei -l {input_file} {flags} -o {output_file}"
    run_os_command(cmd, f"Nuclei Scan {suffix}")
    return output_file

def execute_dalfox(input_file, output_dir, flags):
    output_file = os.path.join(output_dir, "dalfox_xss.txt")
    filtered_input = os.path.join(output_dir, "dalfox_targets.txt")
    os.system(f"grep '?' {input_file} > {filtered_input}")
    
    if not os.path.exists(filtered_input) or os.path.getsize(filtered_input) == 0:
        return None

    cmd = f"dalfox file {filtered_input} {flags} -o {output_file}"
    run_os_command(cmd, "Dalfox")
    if os.path.exists(output_file) and os.path.getsize(output_file) > 0: return output_file
    return None

def execute_trufflehog(output_dir, flags):
    report_file = os.path.join(output_dir, "secrets_leak.txt")
    cmd = f"trufflehog {flags} {output_dir} > {report_file}"
    run_os_command(cmd, "TruffleHog")
    return report_file
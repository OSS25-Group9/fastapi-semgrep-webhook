import subprocess
import json
import os
import glob

def run_semgrep(target_dir: str):
    # ZIP 압축 풀리면 내부에 “owner-repo-xxx/” 이런 폴더가 생김
    subdirs = [d for d in glob.glob(f"{target_dir}/*") if os.path.isdir(d)]
    if not subdirs:
        raise Exception("No extracted directory found.")

    code_dir = subdirs[0]

    print("🔍 Semgrep 스캔 실행 중...", code_dir)

    result_file = os.path.join(target_dir, "result.json")
    
    cmd = [
        "semgrep",
        "--config", "p/default",
        "--json",
        "--output", result_file,
        code_dir
    ]

    subprocess.run(cmd, check=True)

    with open(result_file) as f:
        result = json.load(f)

    print("🎉 Semgrep 스캔 완료!")
    return result

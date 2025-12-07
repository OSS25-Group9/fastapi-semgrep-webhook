import subprocess
import json
import os
from datetime import datetime

def run_semgrep(target_dir, config_file="monitoring/semgrep_rules.yaml", output_dir="./semgrep_results"):
    """
    Semgrep을 실행하고 결과를 JSON 파일로 저장
    
    Args:
        target_dir: 스캔할 디렉토리
        config_file: Semgrep 규칙 파일 경로 (기본: monitoring/semgrep_rules.yaml)
        output_dir: 결과 저장 디렉토리
    
    Returns:
        dict: 스캔 결과 요약
    """
    # 결과 디렉토리 생성
    os.makedirs(output_dir, exist_ok=True)
    
    # 타임스탬프로 파일명 생성
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = os.path.join(output_dir, f"scan_{timestamp}.json")
    
    # Semgrep 규칙 파일이 없으면 기본 규칙 사용
    if not os.path.exists(config_file):
        print(f"⚠️  Custom rules not found at {config_file}, using default rules")
        config_arg = "--config=auto"
    else:
        config_arg = f"--config={config_file}"
    
    try:
        # Semgrep 실행
        print(f"🔍 Running Semgrep on {target_dir}...")
        
        result = subprocess.run(
            [
                "semgrep",
                config_arg,
                "--json",
                "--output", output_file,
                target_dir
            ],
            capture_output=True,
            text=True,
            check=False  # Semgrep은 취약점 발견 시 exit code 1을 반환할 수 있음
        )
        
        print(f"✅ Semgrep scan completed")
        print(f"📄 Results saved to: {output_file}")
        
        # 결과 파일 읽기
        with open(output_file, 'r', encoding='utf-8') as f:
            scan_data = json.load(f)
        
        # 결과 요약 생성
        results = scan_data.get('results', [])
        
        # 심각도별 카운트
        severity_count = {
            'ERROR': 0,
            'WARNING': 0,
            'INFO': 0
        }
        
        for finding in results:
            severity = finding.get('extra', {}).get('severity', 'INFO')
            severity_count[severity] = severity_count.get(severity, 0) + 1
        
        summary = {
            "status": "completed",
            "output_file": output_file,
            "total_findings": len(results),
            "severity": severity_count,
            "errors": severity_count['ERROR'],
            "warnings": severity_count['WARNING'],
            "infos": severity_count['INFO']
        }
        
        print(f"📊 Found {len(results)} issues:")
        print(f"   - ERROR: {severity_count['ERROR']}")
        print(f"   - WARNING: {severity_count['WARNING']}")
        print(f"   - INFO: {severity_count['INFO']}")
        
        return summary
        
    except FileNotFoundError:
        print("❌ Semgrep not found. Please install it:")
        print("   pip install semgrep")
        print("   or visit: https://semgrep.dev/docs/getting-started/")
        return {
            "status": "error",
            "message": "Semgrep not installed"
        }
    
    except Exception as e:
        print(f"❌ Error running Semgrep: {e}")
        return {
            "status": "error",
            "message": str(e)
        }


# 기존 코드와의 호환성을 위한 래퍼 함수
def run_semgrep_legacy(target_dir):
    """기존 코드 호환을 위한 함수"""
    return run_semgrep(target_dir)

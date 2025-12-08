from monitoring.monitoring_module import (
    MonitoringDatabase,
    SemgrepResultParser,
    MonitoringReport
)

# 데이터베이스 초기화
db = MonitoringDatabase()

# 저장된 JSON 파일 처리
import os
for filename in os.listdir("semgrep_results"):
    if filename.endswith(".json"):
        filepath = os.path.join("semgrep_results", filename)
        
        # 파싱
        scan_result, findings = SemgrepResultParser.parse_semgrep_output(filepath)
        
        # 저장
        db.save_scan_result(scan_result, findings)
        print(f"✅ Processed: {filename}")

# 리포트 생성
reporter = MonitoringReport(db)
report = reporter.generate_summary_report("your-repo-name")
print(f"보안 점수: {report['security_score']}")

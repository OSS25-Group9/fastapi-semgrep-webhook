"""
Semgrep Webhook 모니터링 모듈
- Semgrep 스캔 결과 통계 수집
- 취약점 트렌드 분석
- 리포지토리별 보안 점수 계산
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional
from collections import defaultdict, Counter
from dataclasses import dataclass, asdict
import sqlite3


@dataclass
class ScanResult:
    """스캔 결과 데이터 모델"""
    scan_id: str
    repository: str
    commit_sha: str
    timestamp: str
    total_findings: int
    error_count: int
    warning_count: int
    info_count: int
    scan_duration: float
    rules_applied: int


@dataclass
class FindingDetail:
    """개별 취약점 상세 정보"""
    rule_id: str
    severity: str
    category: str
    file_path: str
    line_number: int
    message: str


class MonitoringDatabase:
    """모니터링 데이터 저장 및 조회"""
    
    def __init__(self, db_path: str = "monitoring.db"):
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        """데이터베이스 초기화"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # 스캔 결과 테이블
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS scan_results (
                    scan_id TEXT PRIMARY KEY,
                    repository TEXT NOT NULL,
                    commit_sha TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    total_findings INTEGER,
                    error_count INTEGER,
                    warning_count INTEGER,
                    info_count INTEGER,
                    scan_duration REAL,
                    rules_applied INTEGER
                )
            """)
            
            # 취약점 상세 테이블
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT NOT NULL,
                    rule_id TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    category TEXT,
                    file_path TEXT,
                    line_number INTEGER,
                    message TEXT,
                    FOREIGN KEY (scan_id) REFERENCES scan_results (scan_id)
                )
            """)
            
            # 인덱스 생성
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_repository 
                ON scan_results(repository)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_timestamp 
                ON scan_results(timestamp)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_severity 
                ON findings(severity)
            """)
            
            conn.commit()
    
    def save_scan_result(self, result: ScanResult, findings: List[FindingDetail]):
        """스캔 결과 저장"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # 스캔 결과 저장
            cursor.execute("""
                INSERT INTO scan_results VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                result.scan_id,
                result.repository,
                result.commit_sha,
                result.timestamp,
                result.total_findings,
                result.error_count,
                result.warning_count,
                result.info_count,
                result.scan_duration,
                result.rules_applied
            ))
            
            # 취약점 상세 저장
            for finding in findings:
                cursor.execute("""
                    INSERT INTO findings (scan_id, rule_id, severity, category, 
                                        file_path, line_number, message)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (
                    result.scan_id,
                    finding.rule_id,
                    finding.severity,
                    finding.category,
                    finding.file_path,
                    finding.line_number,
                    finding.message
                ))
            
            conn.commit()
    
    def get_repository_stats(self, repository: str) -> Dict:
        """리포지토리별 통계"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # 총 스캔 횟수
            cursor.execute("""
                SELECT COUNT(*) FROM scan_results WHERE repository = ?
            """, (repository,))
            total_scans = cursor.fetchone()[0]
            
            # 심각도별 취약점 수
            cursor.execute("""
                SELECT f.severity, COUNT(*)
                FROM findings f
                JOIN scan_results s ON f.scan_id = s.scan_id
                WHERE s.repository = ?
                GROUP BY f.severity
            """, (repository,))
            severity_counts = dict(cursor.fetchall())
            
            # 가장 많이 발견된 취약점 Top 5
            cursor.execute("""
                SELECT f.rule_id, COUNT(*) as cnt
                FROM findings f
                JOIN scan_results s ON f.scan_id = s.scan_id
                WHERE s.repository = ?
                GROUP BY f.rule_id
                ORDER BY cnt DESC
                LIMIT 5
            """, (repository,))
            top_issues = cursor.fetchall()
            
            # 최근 스캔 정보
            cursor.execute("""
                SELECT timestamp, total_findings, scan_duration
                FROM scan_results
                WHERE repository = ?
                ORDER BY timestamp DESC
                LIMIT 1
            """, (repository,))
            last_scan = cursor.fetchone()
            
            return {
                "repository": repository,
                "total_scans": total_scans,
                "severity_distribution": severity_counts,
                "top_issues": [{"rule_id": r, "count": c} for r, c in top_issues],
                "last_scan": {
                    "timestamp": last_scan[0],
                    "findings": last_scan[1],
                    "duration": last_scan[2]
                } if last_scan else None
            }
    
    def get_trend_data(self, repository: Optional[str] = None, days: int = 30) -> List[Dict]:
        """취약점 트렌드 데이터"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            query = """
                SELECT 
                    DATE(timestamp) as date,
                    SUM(error_count) as errors,
                    SUM(warning_count) as warnings,
                    SUM(info_count) as infos
                FROM scan_results
                WHERE datetime(timestamp) >= datetime('now', '-' || ? || ' days')
            """
            params = [days]
            
            if repository:
                query += " AND repository = ?"
                params.append(repository)
            
            query += " GROUP BY DATE(timestamp) ORDER BY date"
            
            cursor.execute(query, params)
            
            return [
                {
                    "date": row[0],
                    "errors": row[1],
                    "warnings": row[2],
                    "infos": row[3]
                }
                for row in cursor.fetchall()
            ]


class SemgrepResultParser:
    """Semgrep JSON 결과 파싱"""
    
    @staticmethod
    def parse_semgrep_output(json_path: str) -> tuple[ScanResult, List[FindingDetail]]:
        """Semgrep JSON 출력 파싱"""
        with open(json_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        # 결과 추출
        results = data.get('results', [])
        
        # 심각도별 카운트
        severity_count = Counter(r.get('extra', {}).get('severity', 'INFO') 
                                for r in results)
        
        # 스캔 정보 생성
        scan_result = ScanResult(
            scan_id=f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            repository=data.get('paths', {}).get('_comment', 'unknown'),
            commit_sha=data.get('version', 'unknown'),
            timestamp=datetime.now().isoformat(),
            total_findings=len(results),
            error_count=severity_count.get('ERROR', 0),
            warning_count=severity_count.get('WARNING', 0),
            info_count=severity_count.get('INFO', 0),
            scan_duration=0.0,  # Semgrep 출력에서 추출 필요
            rules_applied=len(set(r.get('check_id', '') for r in results))
        )
        
        # 취약점 상세 정보 생성
        findings = []
        for result in results:
            finding = FindingDetail(
                rule_id=result.get('check_id', 'unknown'),
                severity=result.get('extra', {}).get('severity', 'INFO'),
                category=result.get('extra', {}).get('metadata', {}).get('category', 'unknown'),
                file_path=result.get('path', ''),
                line_number=result.get('start', {}).get('line', 0),
                message=result.get('extra', {}).get('message', '')
            )
            findings.append(finding)
        
        return scan_result, findings


class SecurityScoreCalculator:
    """보안 점수 계산"""
    
    WEIGHTS = {
        'ERROR': 10,
        'WARNING': 5,
        'INFO': 1
    }
    
    @staticmethod
    def calculate_score(scan_result: ScanResult) -> float:
        """보안 점수 계산 (0-100, 높을수록 좋음)"""
        penalty = (
            scan_result.error_count * SecurityScoreCalculator.WEIGHTS['ERROR'] +
            scan_result.warning_count * SecurityScoreCalculator.WEIGHTS['WARNING'] +
            scan_result.info_count * SecurityScoreCalculator.WEIGHTS['INFO']
        )
        
        # 기본 점수 100에서 페널티 차감
        score = max(0, 100 - penalty)
        return round(score, 2)
    
    @staticmethod
    def get_grade(score: float) -> str:
        """점수에 따른 등급 부여"""
        if score >= 90:
            return 'A'
        elif score >= 80:
            return 'B'
        elif score >= 70:
            return 'C'
        elif score >= 60:
            return 'D'
        else:
            return 'F'


class MonitoringReport:
    """모니터링 리포트 생성"""
    
    def __init__(self, db: MonitoringDatabase):
        self.db = db
    
    def generate_summary_report(self, repository: str) -> Dict:
        """종합 리포트 생성"""
        stats = self.db.get_repository_stats(repository)
        
        if stats['last_scan']:
            last_scan_result = ScanResult(
                scan_id="",
                repository=repository,
                commit_sha="",
                timestamp=stats['last_scan']['timestamp'],
                total_findings=stats['last_scan']['findings'],
                error_count=stats['severity_distribution'].get('ERROR', 0),
                warning_count=stats['severity_distribution'].get('WARNING', 0),
                info_count=stats['severity_distribution'].get('INFO', 0),
                scan_duration=stats['last_scan']['duration'],
                rules_applied=0
            )
            
            score = SecurityScoreCalculator.calculate_score(last_scan_result)
            grade = SecurityScoreCalculator.get_grade(score)
        else:
            score = 0
            grade = 'N/A'
        
        return {
            "repository": repository,
            "security_score": score,
            "security_grade": grade,
            "statistics": stats,
            "trend": self.db.get_trend_data(repository, days=7)
        }
    
    def export_to_json(self, report: Dict, output_path: str):
        """리포트를 JSON 파일로 출력"""
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)


# 사용 예시
if __name__ == "__main__":
    # 데이터베이스 초기화
    db = MonitoringDatabase()
    
    # Semgrep 결과 파싱 및 저장 예시
    # json_path = "semgrep_results.json"
    # scan_result, findings = SemgrepResultParser.parse_semgrep_output(json_path)
    # db.save_scan_result(scan_result, findings)
    
    # 리포트 생성
    reporter = MonitoringReport(db)
    report = reporter.generate_summary_report("test-repo")
    
    print(json.dumps(report, indent=2))

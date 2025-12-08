"""
모니터링 대시보드 API 엔드포인트
FastAPI 라우터로 통합 가능
"""

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import JSONResponse
from typing import Optional, List
from datetime import datetime, timedelta
from pydantic import BaseModel

# monitoring_module에서 임포트
# from monitoring_module import MonitoringDatabase, MonitoringReport, SecurityScoreCalculator

router = APIRouter(prefix="/api/monitoring", tags=["monitoring"])


# Pydantic 모델 정의
class RepositoryStats(BaseModel):
    repository: str
    total_scans: int
    severity_distribution: dict
    top_issues: List[dict]
    last_scan: Optional[dict]


class SecurityScore(BaseModel):
    repository: str
    score: float
    grade: str
    timestamp: str


class TrendData(BaseModel):
    date: str
    errors: int
    warnings: int
    infos: int


class DashboardSummary(BaseModel):
    total_repositories: int
    total_scans: int
    total_findings: int
    average_score: float
    recent_scans: List[dict]


# 데이터베이스 인스턴스 (실제로는 dependency injection 사용 권장)
# db = MonitoringDatabase()
# reporter = MonitoringReport(db)


@router.get("/health")
async def health_check():
    """헬스 체크 엔드포인트"""
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "service": "semgrep-monitoring"
    }


@router.get("/repositories", response_model=List[str])
async def list_repositories():
    """
    모든 모니터링 대상 리포지토리 목록 조회
    """
    # 실제 구현에서는 데이터베이스에서 조회
    # return db.get_all_repositories()
    
    # 예시 응답
    return [
        "example-repo-1",
        "example-repo-2",
        "fastapi-semgrep-webhook"
    ]


@router.get("/repositories/{repository}/stats", response_model=RepositoryStats)
async def get_repository_stats(repository: str):
    """
    특정 리포지토리의 통계 정보 조회
    
    Args:
        repository: 리포지토리 이름
    
    Returns:
        리포지토리 통계 정보
    """
    # 실제 구현
    # stats = db.get_repository_stats(repository)
    # if not stats:
    #     raise HTTPException(status_code=404, detail="Repository not found")
    # return stats
    
    # 예시 응답
    return RepositoryStats(
        repository=repository,
        total_scans=42,
        severity_distribution={
            "ERROR": 5,
            "WARNING": 15,
            "INFO": 8
        },
        top_issues=[
            {"rule_id": "hardcoded-credentials", "count": 3},
            {"rule_id": "sql-injection-risk", "count": 2}
        ],
        last_scan={
            "timestamp": datetime.now().isoformat(),
            "findings": 28,
            "duration": 12.5
        }
    )


@router.get("/repositories/{repository}/score", response_model=SecurityScore)
async def get_security_score(repository: str):
    """
    리포지토리 보안 점수 조회
    
    Args:
        repository: 리포지토리 이름
    
    Returns:
        보안 점수 및 등급
    """
    # 실제 구현
    # report = reporter.generate_summary_report(repository)
    # return SecurityScore(
    #     repository=repository,
    #     score=report['security_score'],
    #     grade=report['security_grade'],
    #     timestamp=datetime.now().isoformat()
    # )
    
    # 예시 응답
    return SecurityScore(
        repository=repository,
        score=85.5,
        grade="B",
        timestamp=datetime.now().isoformat()
    )


@router.get("/repositories/{repository}/trend", response_model=List[TrendData])
async def get_trend_data(
    repository: str,
    days: int = Query(default=30, ge=1, le=365, description="조회할 일수")
):
    """
    리포지토리의 취약점 트렌드 데이터 조회
    
    Args:
        repository: 리포지토리 이름
        days: 조회할 기간 (일수)
    
    Returns:
        일별 취약점 통계
    """
    # 실제 구현
    # trend_data = db.get_trend_data(repository, days)
    # return trend_data
    
    # 예시 응답
    trend = []
    for i in range(min(days, 7)):
        date = datetime.now() - timedelta(days=i)
        trend.append(TrendData(
            date=date.strftime("%Y-%m-%d"),
            errors=5 - i,
            warnings=15 - (i * 2),
            infos=8 + i
        ))
    return trend


@router.get("/dashboard/summary", response_model=DashboardSummary)
async def get_dashboard_summary():
    """
    대시보드 요약 정보 조회
    전체 시스템의 요약 통계를 제공
    
    Returns:
        대시보드 요약 정보
    """
    # 실제 구현에서는 데이터베이스에서 집계
    # summary = db.get_dashboard_summary()
    
    # 예시 응답
    return DashboardSummary(
        total_repositories=5,
        total_scans=250,
        total_findings=1234,
        average_score=78.5,
        recent_scans=[
            {
                "repository": "example-repo-1",
                "timestamp": (datetime.now() - timedelta(hours=2)).isoformat(),
                "findings": 12,
                "score": 88.0
            },
            {
                "repository": "example-repo-2",
                "timestamp": (datetime.now() - timedelta(hours=5)).isoformat(),
                "findings": 8,
                "score": 92.5
            }
        ]
    )


@router.get("/findings/recent")
async def get_recent_findings(
    limit: int = Query(default=20, ge=1, le=100, description="조회할 개수"),
    severity: Optional[str] = Query(default=None, description="심각도 필터 (ERROR, WARNING, INFO)")
):
    """
    최근 발견된 취약점 목록 조회
    
    Args:
        limit: 조회할 개수
        severity: 심각도 필터
    
    Returns:
        최근 취약점 목록
    """
    # 실제 구현
    # findings = db.get_recent_findings(limit, severity)
    
    # 예시 응답
    return {
        "findings": [
            {
                "id": 1,
                "repository": "example-repo",
                "rule_id": "hardcoded-credentials",
                "severity": "ERROR",
                "file_path": "src/config.py",
                "line_number": 42,
                "message": "Hardcoded credentials detected",
                "timestamp": (datetime.now() - timedelta(hours=1)).isoformat()
            },
            {
                "id": 2,
                "repository": "example-repo",
                "rule_id": "sql-injection-risk",
                "severity": "ERROR",
                "file_path": "src/database.py",
                "line_number": 156,
                "message": "Potential SQL injection",
                "timestamp": (datetime.now() - timedelta(hours=3)).isoformat()
            }
        ],
        "total": 2,
        "limit": limit,
        "severity_filter": severity
    }


@router.get("/statistics/severity-distribution")
async def get_severity_distribution(
    repository: Optional[str] = Query(default=None, description="특정 리포지토리 필터"),
    start_date: Optional[str] = Query(default=None, description="시작 날짜 (YYYY-MM-DD)"),
    end_date: Optional[str] = Query(default=None, description="종료 날짜 (YYYY-MM-DD)")
):
    """
    심각도별 취약점 분포 통계
    
    Args:
        repository: 특정 리포지토리 필터 (선택)
        start_date: 시작 날짜
        end_date: 종료 날짜
    
    Returns:
        심각도별 통계
    """
    # 날짜 파싱 및 검증
    if start_date:
        try:
            datetime.fromisoformat(start_date)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid start_date format")
    
    if end_date:
        try:
            datetime.fromisoformat(end_date)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid end_date format")
    
    # 예시 응답
    return {
        "distribution": {
            "ERROR": 45,
            "WARNING": 120,
            "INFO": 78
        },
        "total": 243,
        "repository": repository,
        "period": {
            "start": start_date or (datetime.now() - timedelta(days=30)).strftime("%Y-%m-%d"),
            "end": end_date or datetime.now().strftime("%Y-%m-%d")
        }
    }


@router.get("/statistics/top-vulnerabilities")
async def get_top_vulnerabilities(
    limit: int = Query(default=10, ge=1, le=50, description="조회할 개수")
):
    """
    가장 많이 발견되는 취약점 유형 Top N
    
    Args:
        limit: 조회할 개수
    
    Returns:
        Top 취약점 목록
    """
    # 예시 응답
    return {
        "top_vulnerabilities": [
            {
                "rank": 1,
                "rule_id": "hardcoded-credentials",
                "count": 23,
                "severity": "ERROR",
                "category": "security"
            },
            {
                "rank": 2,
                "rule_id": "sql-injection-risk",
                "count": 18,
                "severity": "ERROR",
                "category": "security"
            },
            {
                "rank": 3,
                "rule_id": "bare-except",
                "count": 15,
                "severity": "WARNING",
                "category": "best-practice"
            }
        ],
        "total_analyzed": 243,
        "limit": limit
    }


@router.post("/repositories/{repository}/rescan")
async def trigger_rescan(repository: str):
    """
    특정 리포지토리의 재스캔 트리거
    
    Args:
        repository: 리포지토리 이름
    
    Returns:
        스캔 작업 정보
    """
    # 실제로는 비동기 작업 큐에 추가
    # job_id = scan_queue.add_job(repository)
    
    return {
        "status": "queued",
        "repository": repository,
        "job_id": f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
        "queued_at": datetime.now().isoformat()
    }


@router.get("/export/report/{repository}")
async def export_report(
    repository: str,
    format: str = Query(default="json", regex="^(json|csv|pdf)$")
):
    """
    리포지토리 리포트 내보내기
    
    Args:
        repository: 리포지토리 이름
        format: 출력 형식 (json, csv, pdf)
    
    Returns:
        리포트 파일 또는 다운로드 링크
    """
    if format == "json":
        # 실제 구현
        # report = reporter.generate_summary_report(repository)
        # return JSONResponse(content=report)
        
        return {
            "repository": repository,
            "format": format,
            "download_url": f"/api/monitoring/downloads/report_{repository}.json"
        }
    
    # CSV, PDF 등은 파일 생성 후 다운로드 링크 반환
    return {
        "status": "generating",
        "repository": repository,
        "format": format,
        "estimated_time": "30 seconds"
    }


# main.py에 통합하는 방법:
"""
from monitoring_api import router as monitoring_router

app = FastAPI()
app.include_router(monitoring_router)
"""

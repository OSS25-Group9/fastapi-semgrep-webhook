from fastapi import FastAPI, Request, HTTPException
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse
from github_client import download_repo_zip
from semgrep_runner import run_semgrep
from dotenv import load_dotenv
from monitoring.monitoring_api import router as monitoring_router  # 추가 1
import json
import os
from collections import defaultdict
from datetime import datetime

# 현재 파일의 디렉토리 기준으로 .env 파일 찾기
env_path = os.path.join(os.path.dirname(__file__), '.env')
load_dotenv(env_path)

app = FastAPI()
templates = Jinja2Templates(directory="templates")

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
print(f"토큰 로드 상태: {'로드됨' if GITHUB_TOKEN else 'None입니다!'}")
print(f"토큰 길이: {len(GITHUB_TOKEN) if GITHUB_TOKEN else 0}")
print(f".env 파일 경로: {env_path}")
print(f".env 파일 존재: {os.path.exists(env_path)}")

# 모니터링 API 라우터 추가 (이것만 추가!)
app.include_router(monitoring_router)  # 추가 2

DOWNLOAD_DIR = "./downloaded_repo"
RESULT_JSON_PATH = os.path.join(DOWNLOAD_DIR, "result.json")


def normalize_semgrep_results(data: dict):
    #Semgrep result.json 정규화
    raw_results = data.get("results", [])
    normalized = []

    for r in raw_results:
        extra = r.get("extra", {})
        meta = extra.get("metadata", {})
        start = r.get("start", {}) or {}
        end = r.get("end", {}) or {}

        item = {
            "check_id": r.get("check_id"),
            "path": r.get("path"),
            "start_line": start.get("line"),
            "end_line": end.get("line"),
            "message": extra.get("message"),
            "severity": extra.get("severity") or r.get("severity", "INFO"),  
            "category": meta.get("category"),
            "owasp": meta.get("owasp"),
            "cwe": meta.get("cwe"),
        }
        normalized.append(item)

    # 심각도 순서 정의
    severity_order = {"ERROR": 0, "WARNING": 1, "INFO": 2}

    normalized.sort(
        key=lambda f: (
            severity_order.get(f["severity"], 99),
            f["path"] or "",
            f["start_line"] or 0,
        )
    )

    # 파일별 그룹핑
    by_file = defaultdict(list)
    for n in normalized:
        by_file[n["path"]].append(n)

    # 요약 정보
    total = len(normalized)
    count_error = sum(1 for n in normalized if n["severity"] == "ERROR")
    count_warning = sum(1 for n in normalized if n["severity"] == "WARNING")
    count_info = sum(1 for n in normalized if n["severity"] == "INFO")

    return {
        "results": normalized,
        "by_file": dict(by_file),
        "total": total,
        "count_error": count_error,
        "count_warning": count_warning,
        "count_info": count_info,
    }


@app.post("/webhook")
async def webhook_handler(request: Request):
    try:
        payload = await request.json()
        print("🚨 Webhook 수신!", payload.get("repository", {}))

        # 필수 필드 검증
        repo = payload.get("repository", {}).get("full_name")
        commit_sha = payload.get("after")

        if not repo:
            raise HTTPException(status_code=400, detail="repository.full_name이 필요합니다")
        if not commit_sha:
            raise HTTPException(status_code=400, detail="after (commit SHA)가 필요합니다")

        # 1) GitHub에서 코드 ZIP 다운로드
        try:
            download_repo_zip(repo, commit_sha, GITHUB_TOKEN, DOWNLOAD_DIR)
        except Exception as e:
            error_msg = str(e)
            print(f"GitHub 다운로드 실패: {error_msg}")

            if "404" in error_msg or "Not Found" in error_msg:
                raise HTTPException(
                    status_code=404,
                    detail=f"레포지토리를 찾을 수 없습니다: {repo} (또는 커밋 SHA가 유효하지 않음: {commit_sha[:8]}...)",
                )
            elif "401" in error_msg or "Bad credentials" in error_msg:
                raise HTTPException(
                    status_code=401,
                    detail="GitHub 인증 실패. GITHUB_TOKEN을 확인하세요.",
                )
            else:
                raise HTTPException(status_code=500, detail=f"GitHub 다운로드 실패: {error_msg}")

        # 2) Semgrep 실행
        try:
            result = run_semgrep(DOWNLOAD_DIR)
        except Exception as e:
            error_msg = str(e)
            print(f"Semgrep 실행 실패: {error_msg}")
            raise HTTPException(status_code=500, detail=f"Semgrep 실행 실패: {error_msg}")

        # 3) 정규화된 요약 생성
        normalized = normalize_semgrep_results(result)

        # 4) JSON 응답 + 리포트 URL
        return {
            "status": "ok",
            "repo": repo,
            "commit": commit_sha,
            "summary": {
                "total": normalized["total"],
                "error": normalized["count_error"],
                "warning": normalized["count_warning"],
                "info": normalized["count_info"],
            },
            "report_url": "/report",
        }
    except HTTPException:
        raise
    except Exception as e:
        error_msg = str(e)
        print(f"예상치 못한 에러: {error_msg}")
        raise HTTPException(status_code=500, detail=f"서버 에러: {error_msg}")


@app.get("/report", response_class=HTMLResponse)
async def report(request: Request):
    
    if not os.path.exists(RESULT_JSON_PATH):
        return templates.TemplateResponse(
            "report.html",
            {
                "request": request,
                "has_result": False,
                "generated_at": None,
                "summary": None,
                "by_file": {},
            },
        )

    with open(RESULT_JSON_PATH) as f:
        data = json.load(f)

    normalized = normalize_semgrep_results(data)

    # 생성 시각 (Semgrep time 정보가 없으면 현재 시간 사용)
    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    summary = {
        "total": normalized["total"],
        "error": normalized["count_error"],
        "warning": normalized["count_warning"],
        "info": normalized["count_info"],
    }

    return templates.TemplateResponse(
        "report.html",
        {
            "request": request,
            "has_result": True,
            "generated_at": generated_at,
            "summary": summary,
            "by_file": normalized["by_file"],
        },
    )


@app.get("/")
def root():
    return {"message": "Semgrep Webhook Service Running!", "report_url": "/report"}
    # 3) 결과 반환 (원하면 Slack/Discord 전송도 가능)
    return {
        "status": "success",
        "repository": repo,
        "commit": commit_sha,
        "result": result
    }

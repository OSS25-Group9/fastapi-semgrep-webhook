from fastapi import FastAPI, Request
from github_client import download_repo_zip
from semgrep_runner import run_semgrep
from monitoring.monitoring_api import router as monitoring_router  # 추가 1
import json
import os

app = FastAPI()

# 모니터링 API 라우터 추가 (이것만 추가!)
app.include_router(monitoring_router)  # 추가 2

GITHUB_TOKEN = "ghp_"  # GitHub Personal Access Token
DOWNLOAD_DIR = "./downloaded_repo"

@app.post("/webhook")
async def webhook_handler(request: Request):
    payload = await request.json()
    print("🚨 Webhook 수신!", payload.get("repository", {}))

    repo = payload["repository"]["full_name"]          # "owner/repo"
    commit_sha = payload["after"]                      # push된 commit SHA

    # 1) GitHub에서 코드 ZIP 다운로드
    download_repo_zip(repo, commit_sha, GITHUB_TOKEN, DOWNLOAD_DIR)

    # 2) Semgrep 실행
    result = run_semgrep(DOWNLOAD_DIR)

    # 3) 결과 반환 (원하면 Slack/Discord 전송도 가능)
    return {
        "status": "success",
        "repository": repo,
        "commit": commit_sha,
        "result": result
    }

from fastapi import FastAPI, Request
from github_client import download_repo_zip
from semgrep_runner import run_semgrep
import json
import os

app = FastAPI()

GITHUB_TOKEN = " "  # GitHub Personal Access Token 
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
        "status": "ok",
        "repo": repo,
        "commit": commit_sha,
        "semgrep_result": result
    }

@app.get("/")
def root():
    return {"message": "Semgrep Webhook Service Running!"}

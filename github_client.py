import requests
import zipfile
import io
import os
import shutil

def download_repo_zip(repo_full_name: str, commit_sha: str, token: str, dest_dir: str):
    """
    repo_full_name: "owner/repo"
    commit_sha: "abc123..."
    token: GitHub Personal Access Token
    dest_dir: 다운로드 후 압축 해제할 디렉토리
    """
    url = f"https://api.github.com/repos/{repo_full_name}/zipball/{commit_sha}"
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github+json"
    }

    print("📥 GitHub 레포 ZIP 다운로드 중:", url)
    r = requests.get(url, headers=headers)

    if r.status_code != 200:
        raise Exception(f"Download failed: {r.status_code} {r.text}")

    # 기존 디렉토리 삭제
    if os.path.exists(dest_dir):
        shutil.rmtree(dest_dir)
    os.makedirs(dest_dir, exist_ok=True)

    # ZIP 압축 해제
    with zipfile.ZipFile(io.BytesIO(r.content)) as z:
        z.extractall(dest_dir)

    print("📦 ZIP 다운로드 & 압축 해제 완료:", dest_dir)
    return dest_dir

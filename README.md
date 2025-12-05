# FastAPI Semgrep Webhook

> **Term Project for Open Source Software Course**  
> School of Computing, Gachon University
> Fall 2025

이 프로젝트는 GitHub 웹훅을 통해 특정 레포지토리의 코드를 다운로드하고 Semgrep을 실행하여 결과를 반환하는 FastAPI 애플리케이션입니다.

## 설치 및 설정

### 1. 가상환경 생성

프로젝트 디렉토리로 이동한 후, 가상환경을 생성합니다.

```bash
python -m venv venv
```

### 2. 가상환경 활성화

- **Windows**:
```bash
venv\Scripts\activate
```

- **macOS/Linux**:
```bash
source venv/bin/activate
```

### 3. requirements.txt 설치

다음 명령어를 사용하여 필요한 패키지를 설치합니다.

```bash
pip install -r requirements.txt
```

## 사용 방법

1. GitHub Personal Access Token을 생성하고 `main.py` 파일의 `GITHUB_TOKEN` 변수에 추가합니다.
2. FastAPI 애플리케이션을 실행합니다.

```bash
uvicorn main:app --reload
```

3. GitHub 웹훅을 설정하여 `/webhook` 엔드포인트로 POST 요청을 보냅니다. 이 요청은 레포지토리의 정보를 포함해야 합니다.

## 결과

웹훅이 호출되면, 지정된 레포지토리의 코드를 다운로드하고 Semgrep을 실행하여 결과를 반환합니다. 결과는 JSON 형식으로 제공됩니다.

## 주의사항

- Semgrep이 설치되어 있어야 합니다. 설치 방법은 [Semgrep 공식 문서](https://semgrep.dev/docs/getting-started/installation/)를 참조하세요.
- GitHub API 사용에 대한 제한이 있으므로, 사용량에 주의해야 합니다.

## Credit
- Group #9 (Open Source Software, Fall 2025)
    - **이재훈** - https://github.com/jaehoon0905
    - **박우진** - https://github.com/jin-156
    - **이민우** - https://github.com/lmw1663
    - **배연주** - https://github.com/paeyz

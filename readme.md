# Secure Coding

## Tiny Secondhand Shopping Platform

### 기능
- **회원가입 및 로그인**: 사용자 이름과 비밀번호를 이용한 로그인 및 회원가입 기능.
- **상품 등록 및 관리**: 사용자가 상품을 등록, 수정, 삭제할 수 있는 기능.
- **실시간 채팅**: 사용자 간 실시간 채팅 기능 제공.
- **송금 기능**: 사용자 간 송금을 지원하며, 잔액 확인 및 송금 내역 기록.
- **CSRF 보호**: CSRF 공격을 방지하기 위해 CSRF 토큰을 사용한 보안 기능.
- **관리자 대시보드**: 관리자는 사용자와 상품을 관리할 수 있는 대시보드 제공.

---

## Requirements

- **Miniconda (or Anaconda)**: 미리 설치되어 있지 않다면 아래 링크를 통해 Miniconda를 설치할 수 있습니다.  
  [Miniconda 설치](https://docs.anaconda.com/free/miniconda/index.html)

- **프로젝트 설정**:  
  아래 명령어를 통해 프로젝트를 클론하고 의존성 패키지를 설치합니다.
  ```bash
  git clone https://github.com/ugonfor/secure-coding  (원본)
  git clone https://github.com/legendwon/securecoding.git
  conda env create -f enviroments.yaml

Usage

python app.py

# ngrok 설치 (옵션)
sudo snap install ngrok

# ngrok으로 URL 포워딩
ngrok http 5000



어제
고급 채팅 경험 안내
지난 7일
플랜 보기
제한 없는 액세스, 팀 기능, 그 외에 많은 것들
나의 말:
깃 푸시 어케 함
ChatGPT의 말:
Git에서 push 명령어는 로컬 저장소의 변경 사항을 원격 저장소에 반영할 때 사용됩니다. 아래는 Git에서 push 명령어를 사용하는 방법입니다.

1️⃣ 로컬 저장소에 변경 사항을 커밋
먼저, 변경된 파일을 로컬 저장소에 커밋해야 합니다.

git add .
git commit -m "커밋 메시지"
2️⃣ 원격 저장소에 푸시
git push 명령어로 로컬 저장소의 커밋을 원격 저장소로 푸시할 수 있습니다.

git push origin <브랜치명>
예를 들어, main 브랜치에 푸시하려면:

git push origin main
3️⃣ 푸시 완료
푸시가 완료되면, 원격 저장소의 해당 브랜치에 로컬 커밋 내용이 반영됩니다.

추가 팁:

만약 처음 원격 저장소와 연결하지 않았다면, 원격 저장소를 설정해야 합니다.

git remote add origin <원격 저장소 URL>
이 방법으로 Git 푸시가 가능합니다!

나의 말:
# Secure Coding

## Tiny Secondhand Shopping Platform.

기능
회원가입 및 로그인: 사용자 이름과 비밀번호를 이용한 로그인 및 회원가입.

상품 등록 및 관리: 사용자가 상품을 등록, 수정, 삭제할 수 있는 기능.

실시간 채팅: 사용자 간 실시간 채팅 기능을 제공.

송금 기능: 사용자 간 송금을 지원하며, 잔액 확인 및 송금 내역 기록.

CSRF 보호: CSRF 공격을 방지하기 위해 CSRF 토큰을 사용한 보안 기능.

관리자 대시보드: 관리자는 사용자와 상품을 관리할 수 있는 대시보드 제공.

## requirements

if you don't have a miniconda(or anaconda), you can install it on this url. - https://docs.anaconda.com/free/miniconda/index.html

git clone https://github.com/ugonfor/secure-coding (원본)
conda env create -f enviroments.yaml




# usage

usage
run the server process.

python app.py
if you want to test on external machine, you can utilize the ngrok to forwarding the url.

# optional
sudo snap install ngrok
ngrok http 5000


##주요 기술 스택
Flask: Python으로 작성된 웹 프레임워크

Flask-SocketIO: 실시간 웹 소켓을 통한 메시징 시스템 구현

Flask-SQLAlchemy: 데이터베이스 ORM

Flask-WTF: 폼 처리 및 CSRF 보호

Flask-Talisman: 보안 헤더 설정 및 HTTPS 강제

bcrypt: 비밀번호 해시화

보안
이 프로젝트에서는 다음과 같은 보안 기능을 포함하고 있습니다:

CSRF 보호: 모든 폼에 CSRF 토큰을 추가하여 요청 위조 공격 방지

XSS 방어: HTML 태그 및 스크립트 코드 이스케이프 처리

비밀번호 암호화: bcrypt를 사용하여 비밀번호를 해시화하여 저장

세션 관리: 세션 쿠키의 HttpOnly, Secure, SameSite 설정


깔끔하게 해줄래?

readme.md인데

바로 복붙할 수 있게
ChatGPT의 말:
아래는 깔끔하게 정리된 README.md 파일입니다. 바로 복붙하여 사용하실 수 있습니다.

# Secure Coding

## Tiny Secondhand Shopping Platform

### 기능
- **회원가입 및 로그인**: 사용자 이름과 비밀번호를 이용한 로그인 및 회원가입 기능.
- **상품 등록 및 관리**: 사용자가 상품을 등록, 수정, 삭제할 수 있는 기능.
- **실시간 채팅**: 사용자 간 실시간 채팅 기능 제공.
- **송금 기능**: 사용자 간 송금을 지원하며, 잔액 확인 및 송금 내역 기록.
- **CSRF 보호**: CSRF 공격을 방지하기 위해 CSRF 토큰을 사용한 보안 기능.
- **관리자 대시보드**: 관리자는 사용자와 상품을 관리할 수 있는 대시보드 제공.

---

## Requirements

- **Miniconda (or Anaconda)**: 미리 설치되어 있지 않다면 아래 링크를 통해 Miniconda를 설치할 수 있습니다.  
  [Miniconda 설치](https://docs.anaconda.com/free/miniconda/index.html)

- **프로젝트 설정**:  
  아래 명령어를 통해 프로젝트를 클론하고 의존성 패키지를 설치합니다.
  ```bash
  git clone https://github.com/ugonfor/secure-coding
  conda env create -f enviroments.yaml
Usage
서버 실행
아래 명령어로 서버를 실행합니다:

python app.py
외부 머신에서 테스트
외부에서 테스트하려면 ngrok을 사용하여 URL을 포워딩할 수 있습니다.

# ngrok 설치 (옵션)
sudo snap install ngrok

# ngrok으로 URL 포워딩
ngrok http 5000


주요 기술 스택
Flask: Python으로 작성된 웹 프레임워크

Flask-SocketIO: 실시간 웹 소켓을 통한 메시징 시스템 구현

Flask-SQLAlchemy: 데이터베이스 ORM

Flask-WTF: 폼 처리 및 CSRF 보호

Flask-Talisman: 보안 헤더 설정 및 HTTPS 강제

bcrypt: 비밀번호 해시화

보안 기능
이 프로젝트에서는 다음과 같은 보안 기능을 포함하고 있습니다:

CSRF 보호: 모든 폼에 CSRF 토큰을 추가하여 요청 위조 공격을 방지

XSS 방어: HTML 태그 및 스크립트 코드 이스케이프 처리

비밀번호 암호화: bcrypt를 사용하여 비밀번호를 해시화하여 저장

세션 관리: 세션 쿠키의 HttpOnly, Secure, SameSite 설정

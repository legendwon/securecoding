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

```
git clone https://github.com/ugonfor/secure-coding (원본)
conda env create -f enviroments.yaml
```



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

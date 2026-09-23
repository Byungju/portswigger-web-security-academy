# Lab: Broken brute-force protection, IP block

## 개요

- **난이도**: Practitioner
- **주제**: Authentication — 취약한 Brute-force 보호 / IP 차단 로직 결함 / 성공 로그인으로 카운터 리셋 악용
- **링크**: https://portswigger.net/web-security/authentication/password-based/lab-broken-bruteforce-protection-ip-block

## 목표

IP 기반 brute-force 차단 로직의 결함을 이용해 `carlos` 의 password 를 brute-force 하고, 그 계정으로 로그인해 접근한다.

- 내 계정: `wiener:peter`
- 피해자: `carlos`
- 입력 목록: candidate passwords

## 기초 개념 — Brute-force 보호 기법

```
[자주 쓰이는 보호]
  1) Rate limiting      : 단위 시간당 시도 횟수 제한
  2) Account locking    : 실패 누적 시 계정 잠금
  3) IP blocking        : 같은 IP 의 실패 누적 시 차단

[핵심 설계 포인트]
  - "무엇을 기준으로" 카운트하는가 (IP / 계정 / 조합)
  - 카운터를 "언제" 리셋하는가
  - 우회 가능한 클라이언트 입력에 의존하지 않는가
```

## 취약 지점 — 성공 로그인 시 카운터 리셋

```
[보호 동작]
  잘못된 로그인 3회 연속 → 해당 IP 일시 차단

[결함]
  로그인에 "성공" 하면 실패 카운터가 0으로 리셋됨

[악용]
  실패 1회 → 성공 1회(리셋) → 실패 1회 → 성공 1회(리셋) ...
  → 카운터가 절대 3에 도달하지 않음
  → IP 차단 없이 무제한 brute-force 가능
```

```
[시도 순서]
  wiener:peter(성공, reset)
  carlos:후보1(실패, count=1)
  wiener:peter(성공, reset)
  carlos:후보2(실패, count=1)
  ...
  carlos:정답(성공)  ← 302
```

## 공격 단계

### 1단계 — 보호 동작 확인

로그인 페이지에서 잘못된 자격증명을 3회 연속 제출하면 IP 가 일시 차단됨을 확인한다.
반면, 그 전에 자기 계정(`wiener:peter`)으로 로그인하면 실패 카운터가 리셋된다.

### 2단계 — Burp Intruder Pitchfork 구성

`POST /login` 요청에서 **username 과 password 두 위치**에 payload 를 둔다.

```
username=§user§&password=§pass§
```

- **Resource pool** 의 `Maximum concurrent requests = 1` 로 설정해
  요청 순서를 보장한다(인터리브가 어긋나면 차단됨).

### 3단계 — 교차 목록 구성

```
username 목록:                 password 목록:
  wiener                          peter
  carlos                          후보1
  wiener                          peter
  carlos                          후보2
  wiener                          peter
  carlos                          후보3
  ...                             ...
```

- 내 username 을 먼저, `carlos` 를 100회 이상 반복.
- password 목록은 각 후보 앞에 자기 password(`peter`)를 같은 위치에 맞춰 넣는다.

### 4단계 — 결과 분석

- 응답이 `200`(실패)인 항목을 숨기고, 남은 결과를 username 으로 정렬한다.
- `carlos` 요청 중 단 하나의 **`302`** 응답이 정답 password 다.

### 5단계 — 로그인

찾은 password 로 `carlos` 로그인 → 계정 페이지 접근 → 랩 해결.

## 자동화 툴

인터리브와 카운터 리셋을 자동화한 툴을 사용한다.

```bash
python3 tools/14-authentication-ip-block-bypass.py \
  --target "https://LAB-ID.web-security-academy.net" \
  --valid-username wiener --valid-password peter \
  --victim carlos --verify
```

```
동작:
  1) 매 후보 시도 전에 정상 계정으로 로그인 → 실패 카운터 리셋
  2) victim:candidate 시도 → 302면 성공
  3) 차단(403/429, "too many") 감지 시 --block-wait 대기 후 재개
  4) --verify 로 계정 페이지 접근 확인
```

주요 옵션:

```
--victim carlos                 공격 대상 username
--valid-username / --valid-password   카운터 리셋용 정상 자격증명
--passwords                     후보 password 목록
--block-wait 61                 차단 감지 시 대기(초)
--delay                         요청 간 지연
```

### 검증 메모

목 서버(실패 3회 차단, 성공 시 리셋)로 두 툴을 비교 검증했다.

```
기존 brute-force 툴 : 3회 실패 후 403 으로 차단되어 실패
ip-block 우회 툴    : 인터리브로 carlos / <pw> 탐지 성공
```

## 방어

```
[근본 원인]
  실패 카운터가 "성공 로그인" 으로 리셋되어
  실패/성공 교차로 무제한 시도 가능

[올바른 방어]
  1. 성공 로그인으로 실패 카운터를 리셋하지 않음
     - 카운터는 일정 시간 창(time window) 기반으로 관리
     - 리셋은 시간 경과로만 (또는 관리자 조치로만)
  2. 계정 단위 + IP 단위를 함께 추적
     - IP 만 보호하면 IP 회전으로 우회, 계정만 보호하면 분산 시도에 취약
  3. 지수 백오프(exponential backoff) / CAPTCHA / MFA
  4. 클라이언트 제공 IP 헤더(X-Forwarded-For) 신뢰 금지
     - 신뢰 경계에서 정규화, 실제 연결 정보 기준
  5. 로그인 실패 모니터링/알림, 비정상 패턴 탐지
  6. 강한 비밀번호 정책 + 유출 비밀번호 차단

[주의]
  "성공 시 리셋" 은 사용자 편의를 위한 흔한 구현이지만,
  공격자에게는 카운터를 영구히 낮게 유지하는 수단이 된다.
```

## 핵심 정리

- IP 차단은 실패 3회 연속 시 동작했지만, 성공 로그인이 실패 카운터를 리셋하는 결함이 있었다.
- `wiener:peter` 성공과 `carlos` 후보 시도를 교차시켜 카운터를 1로 유지하며 brute-force 했다.
- `carlos` 요청 중 302 응답이 정답 password 였다.
- 방어는 성공 로그인으로 카운터를 리셋하지 않고, 계정·IP 단위의 시간 창 기반 제한을 함께 적용하는 것이다.

## 배운 점

- brute-force 보호의 핵심은 "무엇을 세고, 언제 리셋하는가" 이며, 리셋 조건이 허점이 될 수 있다.
- Burp Intruder 의 Pitchfork + Resource pool(동시성 1)로 요청 순서를 제어하는 기법을 익혔다.
- 005(응답 시간)와 006(IP 차단) 모두 "보호/정보 노출이 검증되지 않은 가정에 의존" 한 사례다.
- 이 랩을 위해 `tools/14-authentication-ip-block-bypass.py` 를 작성해 인터리브 우회를 자동화했다.

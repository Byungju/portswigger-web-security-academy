# Lab: 2FA bypass using a brute-force attack

## 개요

- **난이도**: Practitioner
- **주제**: Authentication — MFA(2FA) 코드 brute-force / 세션 로그아웃 우회(자동 재로그인)
- **링크**: https://portswigger.net/web-security/authentication/multi-factor/lab-2fa-bypass-using-a-brute-force-attack

## 목표

`carlos:montoya` 자격증명은 알고 있지만 2FA 코드는 모른다. 4자리 코드를 brute-force 해 `carlos` 의 계정 페이지에 접근한다.

- 피해자 자격증명: `carlos:montoya`
- 코드: 4자리 숫자 (0000~9999)

## 취약 지점

### 1. 2FA 코드에 시도 제한이 없음

```
4자리 숫자 → 10,000가지
시도 횟수 제한/잠금이 없어 전수 대입이 이론상 가능
```

### 2. 잘못된 코드 2회 → 세션 로그아웃

```
- 코드 1~2회 틀리면 세션이 무효화됨
- 즉, 한 세션에서는 2번까지만 시도 가능
→ Burp 매크로로 매 시도 전에 다시 로그인해야 함
```

### 3. 코드가 로그인마다 재생성되지 않음(또는 특정 창 동안 유지)

```
로그인(매크로)을 반복해도 검증되는 코드가 유지되므로
여러 세션에 걸쳐 같은 코드를 brute-force 할 수 있다.
```

## 공격 단계 (Burp)

### 1단계 — 흐름 관찰

`carlos:montoya` 로 로그인해 2FA 페이지로 이동한다.
잘못된 코드를 2회 입력하면 로그아웃됨을 확인한다.

### 2단계 — 세션 처리 매크로 등록

`Settings → Sessions → Session Handling Rules → Add` 에서
**Run a macro** 규칙을 만들고 다음 3개 요청을 매크로로 기록한다.

```
GET /login
POST /login
GET /login2
```

매크로 테스트 시 마지막 응답이 4자리 코드 입력 페이지인지 확인한다.
이제 Burp 가 각 요청 전에 자동으로 carlos 로 재로그인한다.

### 3단계 — Intruder 로 코드 brute-force

`POST /login2` 를 Intruder 로 보내고 `mfa-code` 에 payload 위치를 둔다.

```
Numbers, 0 ~ 9999, step 1, 자릿수 4
Resource pool: Maximum concurrent requests = 1
```

### 4단계 — 302 응답

공격 결과 중 **302** 응답이 성공이다.
`Show response in browser` 로 열어 세션을 얻고 `My account` 접근 → 랩 해결.

> 코드가 주기적으로 재생성되므로, 성공하지 못하면 같은 공격을 여러 번 반복해야 할 수 있다.

## 자동화 툴

```bash
python3 tools/14-authentication-2fa-bruteforce.py \
  --target "https://LAB-ID.web-security-academy.net" \
  --victim-username carlos --victim-password montoya --threads 20 --verify
```

```
동작:
  1) 작업(스레드)마다 새 세션으로 재로그인 (GET /login → POST /login → GET /login2)
  2) 세션당 최대 --attempts-per-session(기본 2)회 mfa-code 시도
  3) 로그아웃 감지 시 즉시 재로그인 후 계속
  4) 302 /my-account 발견 시 종료, --verify 로 계정 페이지 확인
  5) 코드 재생성 대비 --rounds(기본 3) 반복
```

성능 최적화(중요):

```
- --threads(기본 10) 병렬: 로그인이 코드를 재생성하지 않으므로 병렬 안전
- 스레드별 requests.Session 유지 + 쿠키만 초기화 → TCP/TLS 핸드셰이크 제거
- CSRF 자동 감지: csrf 가 없으면 GET /login·GET /login2 생략 → 요청 수 절감
- 5초마다 [진행] 카운트/속도/ETA 출력
```

### 툴 성능 디버깅에서 배운 점

```
[증상] 라운드 1이 끝나지 않고 매우 느림
[원인]
  - --threads 기본값 1 → 사실상 순차 실행
  - 세션마다 Session 새로 생성 → 매번 TCP/TLS 핸드셰이크
  - csrf 불필요한데도 GET 두 번을 항상 수행
[해결]
  - 병렬화 + 연결 재사용 + 불필요한 GET 생략 + 진행률/ETA 표시
```

## Brute-force 유형 정리 (Authentication 시리즈)

| # | 랩 | 핵심 |
|---|-----|------|
| 001 | different responses | 실패 메시지 차이 |
| 004 | subtly different responses | 미묘한 문자 차이 |
| 005 | response timing | 응답 시간 + IP 우회 |
| 006 | IP block | 성공 로그인으로 카운터 리셋 |
| 007 | account lock | 잠금 메시지로 열거 |
| 009 | stay-logged-in cookie | 쿠키 오프라인/온라인 brute-force |
| 012 | password change | 변경 API + 메시지 차이 |
| 013 | multiple credentials | 한 요청에 다중 자격증명(배열) |
| 014 | 2FA brute-force | 세션 로그아웃 우회 + 자동 재로그인 |

```
공통: 시도 제한/세션/응답의 허점을 이용해 대입을 완성한다.
차이: "무엇을(로그인/2FA/쿠키/변경 API) 어디로(엔드포인트) 어떻게(우회) 대입하는가"
```

## 방어

```
[근본 원인]
  2FA 코드에 시도 제한/잠금이 없음 (+ 4자리라는 낮은 엔트로피)

[올바른 방어]
  1. 2FA 코드 시도 제한
     - 일정 횟수(예: 3회) 실패 시 코드 무효화 + 재발급 요구
     - 계정/IP 단위 rate limiting, 지수 백오프
  2. 코드 보안 강화
     - 코드 길이/엔트로피 상향, 짧은 만료, 일회용
     - 로그인마다 코드 재생성(재사용 방지)
  3. 세션/상태 관리
     - 2FA 미완료 세션에서 다른 기능 접근 차단
     - 실패 누적 시 명확히 잠그고 알림
  4. MFA 피로/브루트 탐지 및 모니터링
  5. MFA 우회 방지(2FA 필수화)

[주의]
  4자리는 10,000가지뿐이며, 시도 제한이 없으면 수 분 내 대입 가능하다.
```

## 핵심 정리

- 2FA 코드에 시도 제한이 없어 0000~9999 를 brute-force 할 수 있었다.
- 잘못된 코드 2회마다 세션이 로그아웃되어, 매크로(자동 재로그인)로 세션을 갱신하며 코드를 계속 시도했다.
- 성공 시 302 응답의 세션으로 `carlos` 계정에 접근했다.
- 방어는 2FA 코드 시도 제한(실패 시 코드 무효화/재발급)과 엔트로피·만료 강화다.

## 배운 점

- 본질은 로그인 비밀번호 brute-force 와 같고, 대상이 "2FA 코드" 로 바뀐 변형이다(세션 로그아웃 우회가 추가됨).
- 세션 무효화 같은 보호도 자동 재로그인(매크로) 앞에서는 지연일 뿐이다.
- 툴 성능(병렬화·연결 재사용·불필요 요청 제거)이 실전 brute-force 성공 여부를 좌우한다.
- 이 랩을 위해 `tools/14-authentication-2fa-bruteforce.py` 를 작성·최적화했다.

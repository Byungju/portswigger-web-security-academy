# Lab: Web cache poisoning with an unkeyed cookie

## 개요

- **난이도**: Practitioner
- **주제**: Web Cache Poisoning — Unkeyed Cookie / 쿠키 값 반영 / JavaScript 컨텍스트 XSS
- **링크**: https://portswigger.net/web-security/web-cache-poisoning/exploiting-design-flaws/lab-web-cache-poisoning-with-an-unkeyed-cookie

## 목표

쿠키가 캐시 키에 포함되지 않는 결함을 이용해 캐시를 오염시키고, 방문자 브라우저에서 `alert(1)` 을 실행시킨다.

## 취약 지점

### 1. 쿠키가 Cache Key 에 없음 (unkeyed cookie)

```
[정상 요청]
  홈 페이지 첫 응답이 쿠키를 설정:
    Set-Cookie: fehost=prod-cache-01

[재요청]
  Cookie: fehost=prod-cache-01
  → 응답의 JavaScript 객체 안에 값이 반영됨
```

쿠키 값이 응답 생성에 사용되지만 Cache Key 에는 쿠키가 없어,
같은 경로의 캐시를 임의 값으로 덮어쓸 수 있다.

### 2. 값이 JS(이중 인용부호) 컨텍스트에 인코딩 없이 반영

```
응답(예):
  <script>
    data = {"fehost":"prod-cache-01"};   // 쿠키 값이 그대로 삽입
  </script>
```

값을 `"` 로 탈출하면 JavaScript 를 주입할 수 있다.

```
Cookie: fehost=someString"-alert(1)-"someString

결과:
  data = {"fehost":"someString"-alert(1)-"someString"};
  → "someString" - alert(1) - "someString" 로 실행되어 alert(1) 발생
```

## 공격 단계

### 1단계 — 반영 지점 확인

홈 페이지를 로드해 `Set-Cookie: fehost=prod-cache-01` 을 확인하고,
재로드 시 `fehost` 값이 응답의 JS 객체 안에 반영되는 것을 본다.

### 2단계 — cache-buster 추가

다른 사용자에게 영향을 주지 않도록 고유 쿼리를 붙인다.

```
GET /?cb=1234
```

쿠키 값을 임의 문자열로 바꿔 응답에 그대로 반영되는지 확인한다.

### 3단계 — XSS 페이로드 삽입

쿠키에 JS 컨텍스트를 탈출하는 페이로드를 넣는다.

```
Cookie: fehost=someString"-alert(1)-"someString
```

### 4단계 — 캐시 오염 확인

응답에 페이로드가 반영되고 `X-Cache: hit` 가 나올 때까지 재전송한다.

### 5단계 — 피해자 유도 및 유지

브라우저에서 URL 을 열어 `alert()` 를 확인한다.
cache-buster 를 제거하고, 피해자가 방문해 랩이 풀릴 때까지 재전송으로 캐시를 계속 오염 상태로 유지한다.

## XSS 컨텍스트 탈출 분석

```
[삽입 위치]
  {"fehost":"<우리 값>"}

[페이로드]
  someString"-alert(1)-"someString
            └─ " 로 문자열 종료 → 다음 토큰이 코드로 실행

[결과]
  {"fehost":"someString"-alert(1)-"someString"}
             └ 문자열 ┘ └── 코드 ──┘ └ 문자열 ┘
```

이 랩은 **기존 XSS(JavaScript 컨텍스트 탈출) 지식을 캐시 취약점과 결합**한 사례다.
(02-xss 의 JS 문자열 컨텍스트 우회와 동일한 원리)

## 방어

```
[근본 원인]
  1) 쿠키 값이 응답에 안전하지 않게(인코딩 없이) 반영
  2) 쿠키가 Cache Key 에 포함되지 않아 임의 값으로 캐시 오염 가능
  3) 개인화된 응답이 캐시됨

[올바른 방어]
  1. 컨텍스트에 맞는 출력 인코딩
     - JS 컨텍스트는 JSON 직렬화(json.dumps) 등으로 안전하게 삽입
     - HTML/속성/JS 별 인코딩 규칙 준수
  2. 캐시 키에 쿠키 포함 여부 정비
     - 쿠키가 응답에 영향을 주면 Vary: Cookie 등으로 캐시 분리
     - 개인화 응답은 캐시하지 않음 (Cache-Control: no-store/private)
  3. 클라이언트 쿠키를 보안 판단/응답 생성에 신뢰하지 않음
  4. CSP 로 인라인 스크립트 실행 완화
  5. 프록시/캐시 설정 정기 점검

[주의]
  "쿠키는 캐시 키에 없다" 는 사실 자체가 공격 표면이다.
  응답에 반영되는 모든 입력(헤더·쿠키·쿼리)을 캐시 키와 함께 검토해야 한다.
```

## 핵심 정리

- `fehost` 쿠키가 캐시 키에 포함되지 않고 응답의 JS 객체에 인코딩 없이 반영되어 캐시 오염이 성립했다.
- `fehost=someString"-alert(1)-"someString` 로 문자열을 탈출해 `alert(1)` 을 실행했다.
- 001(헤더)에 이어, 이번에는 **쿠키**가 unkeyed 입력이었다.
- 방어는 출력 컨텍스트 인코딩과 캐시 키/Vary 설계(개인화 응답 비캐시)다.

## 배운 점

- 캐시 오염의 "unkeyed input" 은 헤더뿐 아니라 **쿠키**일 수도 있다.
- 반영형 XSS 지식(컨텍스트 탈출)이 캐시와 결합하면 피해자 전원에게 영향을 주는 저장형에 준하는 공격이 된다.
- 캐시 키에 무엇이 포함되는지(헤더/쿠키/쿼리) 파악하는 것이 분석의 핵심이다.
- 이후 랩은 여러 헤더 조합, 쿠키 처리, 캐시 구현 결함으로 확장된다.

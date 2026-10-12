# Lab: Web cache poisoning via an unkeyed query parameter

## 개요

- **난이도**: Practitioner
- **주제**: Web Cache Poisoning — 개별 파라미터가 캐시 키에서 제외(Unkeyed Parameter) / UTM 분석 파라미터 / 반영 XSS
- **링크**: https://portswigger.net/web-security/web-cache-poisoning/exploiting-implementation-flaws/lab-web-cache-poisoning-unkeyed-param

## 목표

캐시 키에서 제외된 특정 파라미터(`utm_content`)에 XSS 페이로드를 넣어 홈 페이지 캐시를 오염시키고, 방문자 브라우저에서 `alert(1)` 을 실행시킨다.

## 005 와 006 의 차이

```
[005 — unkeyed query string]
  쿼리스트링 전체가 캐시 키에서 제외
  → 임의의 쿼리로 응답 오염

[006 — unkeyed query parameter (이번)]
  쿼리스트링은 캐시 키에 포함됨(파라미터를 바꾸면 cache miss)
  그러나 특정 파라미터(utm_content)만 키에서 제외
  → 그 파라미터를 바꿔도 같은 캐시 항목 → 오염
```

## 취약 지점

### 1. `utm_content` 가 캐시 키에서 제외됨

```
GET /?cb=1234&utm_content=abc   → cache hit
GET /?cb=1234&utm_content=xyz   → cache hit (같은 항목)

→ 쿼리스트링은 keyed 이지만 utm_content 는 unkeyed
```

### 2. 그 값이 응답에 반영됨

```
utm_content 값이 응답(현재 URL/쿼리 반영 등)에 그대로 출력
→ 반영 문자열을 탈출해 XSS 주입 가능
```

## UTM 파라미터 조사

UTM(Urchin Tracking Module) 파라미터는 마케팅 캠페인 추적용으로,
분석 도구가 처리하므로 **캐시 키에서 제외되는 경우가 많다.**

### 표준 UTM 파라미터 (Google Analytics)

```
utm_source             유입 소스 (예: google, newsletter)
utm_medium             매체 (예: cpc, email, social)
utm_campaign           캠페인 이름
utm_term               검색 키워드 (유료 검색)
utm_content            광고/링크 콘텐츠 구분 (A/B, 이미지 등)   ← 이 랩
utm_id                 캠페인 ID
utm_source_platform    소스 플랫폼 (GA4)
utm_creative_format    크리에이티브 형식 (GA4)
utm_marketing_tactic   마케팅 전술 (GA4)
```

### 기타 광고/분석 클릭 식별자 (유사하게 제외되기 쉬움)

```
gclid      Google Click ID
gbraid/wbraid  Google iOS/웹-앱 클릭 ID
fbclid     Facebook Click ID
msclkid    Microsoft Click ID
dclid      DoubleClick ID
ttclid     TikTok Click ID
li_fat_id  LinkedIn Click ID
_ga, _gl   Google Analytics 쿠키 연동 파라미터
mc_eid, mc_cid  Mailchimp
```

### 왜 조사해야 하는가

```
[캐시 구현 관례]
  CDN/캐시 설정에서 "분석용 파라미터는 캐시 키에서 제외" 하는 경우가 흔함
  → 목록에 없는 UTM/추적 파라미터가 unkeyed 로 남을 수 있음

[점검 방법]
  1) Param Miner → "Guess GET parameters" 로 지원 파라미터 탐색
  2) 후보 파라미터를 값만 바꿔 요청 → 계속 cache hit 이면 unkeyed
  3) 그 응답에 값이 반영되는지 확인
  4) 반영되면 XSS/리다이렉트 등으로 악용
```

## 공격 단계

### 1단계 — 캐시 동작 파악

홈 페이지에서 쿼리를 바꾸면 `X-Cache: miss` 가 되고, 쿼리가 응답에 반영됨을 확인한다.
(= 쿼리스트링은 keyed, 응답에 반영됨)

### 2단계 — cache-buster 추가

```
GET /?cb=1234
```

### 3단계 — 숨은 파라미터 탐색

Param Miner 의 **Guess GET parameters** 로 `utm_content` 가 지원됨을 확인한다.

### 4단계 — unkeyed 확인

`utm_content` 값을 바꿔도 계속 `X-Cache: hit` 인지 확인한다.
cache miss 응답에서 이 값이 응답에 반영됨도 확인한다.

### 5단계 — XSS 페이로드 주입

```
GET /?cb=1234&utm_content='/><script>alert(1)</script>
```

반영 문자열을 탈출해 스크립트를 주입한다.
응답에 페이로드가 반영되고 `X-Cache: hit` 가 날 때까지 재전송한다.

### 6단계 — 피해자 시뮬레이션

`utm_content` 를 제거한 URL 을 브라우저로 열어 캐시된 응답이 `alert()` 를 실행하는지 확인한다.

### 7단계 — 일반 사용자 오염

cache-buster 를 제거하고 다시 `utm_content` 페이로드를 넣어 재전송해
일반 사용자 캐시 키를 오염시킨다. 피해자가 방문할 때까지 재오염을 반복한다.

## 방어

```
[근본 원인]
  1) 응답에 영향을 주는 파라미터(utm_content)를 캐시 키에서 제외
  2) 그 값이 응답에 안전하지 않게 반영(XSS)
  3) 응답 캐싱

[올바른 방어]
  1. 캐시 키 정책 명확화
     - 응답에 영향을 주는 모든 파라미터를 캐시 키에 포함
     - "분석용" 이라도 응답에 반영된다면 키에 포함하거나 반영을 제거
  2. 반영 값 출력 인코딩
     - URL/canonical 등 반영 지점 컨텍스트에 맞게 인코딩
  3. 캐시 제어/정규화 규칙 정기 점검
     - CDN 의 캐시 키 제외 목록(UTM 등)을 검토
  4. CSP 로 인라인 스크립트 완화
  5. Param Miner 등으로 unkeyed 파라미터 주기적 테스트

[주의]
  분석 파라미터 제외는 편의를 위한 최적화이며,
  그 파라미터가 응답에 반영되는 순간 캐시 오염 취약점이 된다.
```

## 핵심 정리

- 쿼리스트링은 캐시 키에 포함되지만 `utm_content` 파라미터만 제외되어, 값만 바꿔도 같은 캐시를 오염시킬 수 있었다.
- `utm_content='/><script>alert(1)</script>` 로 반영 문자열을 탈출해 `alert(1)` 을 실행했다.
- UTM·광고 클릭 식별자(utm_*, gclid, fbclid 등)는 캐시 키에서 제외되기 쉬우므로 점검 대상이다.
- 방어는 응답에 영향을 주는 파라미터를 캐시 키에 포함하고 반영 값 인코딩을 적용하는 것이다.

## 배운 점

- 005(쿼리 전체 unkeyed)와 달리, 006 은 **개별 파라미터만 unkeyed** 인 경우다.
- 캐시 키 제외 목록(UTM/분석 파라미터)은 실제 공격 표면이며, Param Miner 로 지원 파라미터를 찾아낸다.
- "쿼리스트링은 keyed" 라고 해서 안전한 것이 아니라, 어떤 파라미터가 키에서 빠지는지 확인해야 한다.
- 마케팅/분석 파라미터는 성능 최적화 명목으로 흔히 제외되므로, 캐시 오염 진단 시 우선 점검 후보군으로 정리해 둔다.

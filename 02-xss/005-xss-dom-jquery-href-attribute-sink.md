# Lab: DOM XSS in jQuery anchor href attribute sink using location.search source

## 개요

- **난이도**: Apprentice
- **주제**: Cross-Site Scripting (XSS) — DOM-based / jQuery / href attribute sink
- **링크**: https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-jquery-href-attribute-sink

## 목표

피드백 페이지의 "Back" 링크 href에 DOM XSS를 삽입하여 `alert(document.cookie)`를 실행시킨다.

## 취약점 분석

피드백 페이지(`/feedback`)의 JavaScript:

```javascript
$(function() {
    $('#backLink').attr("href",
        (new URLSearchParams(window.location.search)).get('returnPath')
    );
});
```

`location.search`에서 `returnPath` 파라미터를 읽어 jQuery로 `#backLink` 요소의 `href` 속성에 그대로 삽입한다.

**Source**: `location.search` → `returnPath` 파라미터  
**Sink**: jQuery `.attr("href", ...)` — href 속성에 직접 삽입

## 공격 방법

```
/feedback?returnPath=javascript:alert(document.cookie)
```

페이지 로드 후 DOM 상태:

```html
<!-- 원래 -->
<a id="backLink" href="/">Back</a>

<!-- 공격 후 -->
<a id="backLink" href="javascript:alert(document.cookie)">Back</a>
```

페이지 내 **"Back" 링크를 클릭**하면 `javascript:` 프로토콜이 실행되어 `alert(document.cookie)`가 동작한다.

## 주의 — 브라우저 뒤로가기 vs 페이지 내 Back 링크

이 공격에서 혼동하기 쉬운 부분이 있다.

| 동작 | 결과 |
|------|------|
| 브라우저 뒤로가기 버튼 | href 링크를 거치지 않으므로 **alert 미실행** |
| 페이지 내 "Back" 텍스트 링크 클릭 | href="javascript:..." 실행 → **alert 실행** |

취약점은 `href` 속성에 삽입된 `javascript:` 프로토콜이므로, 반드시 해당 링크를 **직접 클릭**해야 발동된다.

## `javascript:` 프로토콜이란

`href`, `src`, `action` 등 URL을 받는 속성에 `javascript:` 스킴을 사용하면 링크 클릭 시 JS 코드를 실행할 수 있다.

```html
<!-- 링크 클릭 시 alert 실행 -->
<a href="javascript:alert(1)">클릭</a>

<!-- void(0)으로 페이지 이동 없이 함수 호출 -->
<a href="javascript:void(0)" onclick="doSomething()">클릭</a>
```

원래는 인라인 이벤트 핸들러 대용으로 사용되던 구문이지만, 사용자 입력이 href에 그대로 삽입될 때 XSS 벡터가 된다.

## 이전 랩들과의 비교

| 항목 | 003 (document.write) | 004 (innerHTML) | 005 (href attribute) |
|------|----------------------|-----------------|----------------------|
| Sink | `document.write()` | `element.innerHTML` | `jQuery .attr("href")` |
| 페이로드 형태 | `<svg onload=...>` | `<img onerror=...>` | `javascript:alert(...)` |
| 실행 조건 | 페이지 로드 즉시 | 페이지 로드 즉시 | **링크 클릭 시** |
| 태그 삽입 여부 | O | O | X (URL 값만 삽입) |

href sink는 태그를 삽입하는 게 아니라 **URL 값**을 조작하는 방식이기 때문에 `javascript:` 프로토콜을 활용해야 한다.

## 핵심 정리

- jQuery `.attr()`, `.prop()` 등으로 href를 동적으로 설정할 때 사용자 입력이 그대로 들어가면 XSS가 성립한다.
- `javascript:` 프로토콜은 링크 클릭 시 JS를 실행하므로 href sink에서의 핵심 공격 벡터다.
- `<script>`, 이벤트 핸들러 없이도 URL 속성만으로 XSS가 가능하다.
- **방어**:
  - href 값이 `http://`, `https://`, `/` 로 시작하는지 화이트리스트 검증
  - `javascript:`, `data:`, `vbscript:` 스킴 차단
  - CSP `script-src 'self'`로 인라인 JS 차단

## 배운 점 및 추가 학습

### 1. href 외에도 `javascript:` 가 동작하는 속성들

```html
<!-- href -->
<a href="javascript:alert(1)">링크</a>

<!-- src (일부 브라우저) -->
<iframe src="javascript:alert(1)"></iframe>

<!-- action -->
<form action="javascript:alert(1)"><button>submit</button></form>

<!-- xlink:href (SVG) -->
<svg><a xlink:href="javascript:alert(1)"><text y="20">클릭</text></a></svg>
```

### 2. URL 속성 sink 목록

href 외에도 URL을 받는 속성이 XSS sink가 될 수 있다.

| 속성 | 태그 | 위험 조건 |
|------|------|-----------|
| `href` | `<a>`, `<link>`, `<base>` | 사용자 입력이 그대로 삽입될 때 |
| `src` | `<script>`, `<iframe>`, `<img>` | 외부 JS 로드 가능 시 |
| `action` | `<form>` | javascript: 스킴 삽입 시 |
| `data` | `<object>` | data URI 삽입 시 |
| `location.href` | JS | `location.href = userInput` |

### 3. jQuery가 특히 위험한 이유

jQuery는 편의성을 위해 설계되어 내부적으로 `innerHTML`, `attr()`, `html()` 등을 많이 사용한다.

```javascript
// 위험한 jQuery 패턴들
$('#el').html(userInput);           // innerHTML과 동일
$('#el').attr('href', userInput);   // href에 직접 삽입
$('#el').prop('src', userInput);    // src에 직접 삽입
$(userInput);                       // 셀렉터로 HTML 생성 가능
```

특히 `$(userInput)` 형태는 입력값이 HTML 태그처럼 생기면 DOM 요소로 생성하기 때문에 그 자체로 XSS sink가 된다.

### 4. XSS 실행 조건별 위험도

| 실행 조건 | 예시 | 위험도 | 이유 |
|-----------|------|--------|------|
| 페이지 로드 즉시 | `<svg onload>`, `<img onerror>` | 최고 | 피해자가 아무것도 안 해도 실행 |
| 링크/버튼 클릭 | `href="javascript:..."` | 높음 | 자연스러운 UX 행동 유도 가능 |
| 마우스 오버 | `onmouseover` | 높음 | 링크 위에 마우스만 올려도 실행 |
| 폼 입력 | `oninput`, `onchange` | 중간 | 입력 행동 유도 필요 |
| 특정 키 입력 | `onkeydown` | 낮음 | 특정 조건 충족 필요 |

링크 클릭은 "뒤로가기"처럼 자연스러운 UX 동작으로 위장할 수 있기 때문에 실질적인 위험도가 높다.

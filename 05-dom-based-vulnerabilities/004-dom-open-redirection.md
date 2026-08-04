# Lab: DOM-based open redirection

## 개요

- **난이도**: Apprentice
- **주제**: DOM-based Open Redirection — URL 파라미터 인젝션 / location.href 싱크
- **링크**: https://portswigger.net/web-security/dom-based/open-redirection/lab-dom-open-redirection

## 목표

페이지의 JS 가 URL 파라미터(`url=`)를 읽어 `location.href` 에 설정하는 구조를 이용한다. 파라미터에 공격자 URL 을 삽입하면 피해자를 임의 사이트로 리다이렉트할 수 있다.

## 이전 랩들과의 차이

```
[001~003 랩 — postMessage 기반]
  공격자 페이지에서 iframe + postMessage 로
  타겟 페이지에 크로스 오리진으로 페이로드 전달

[004 랩 (이번) — URL 파라미터 직접 조작]
  별도 exploit 페이지 불필요
  타겟 URL 에 파라미터를 직접 삽입
  → 브라우저에서 해당 URL 접근만으로 공격 성립
  → 더 단순한 공격 경로
```

## 취약한 코드 구조

```javascript
// 타겟 사이트의 취약한 코드
// "Back to Blog" 버튼 등에서 returnUrl 처리

var returnUrl = /url=(https?:\/\/.+)/.exec(location.search);
if (returnUrl) {
    location.href = returnUrl[1];  // ← 싱크: URL 파라미터를 그대로 이동
}
```

```
동작:
  /post?postId=1&url=https://target.com
  → url 파라미터 추출: https://target.com
  → location.href = 'https://target.com' → 이동

취약점:
  url 파라미터에 임의 URL 삽입 가능
  → 공격자 도메인으로 리다이렉트 가능
```

## 공격 방법

### 페이로드

```
https://VULNERABLE.com/post?postId=4&url=https://exploit-server.net
```

```
피해자가 위 URL 방문 시:
  JS 실행:
    returnUrl = /url=(https?:\/\/.+)/.exec(location.search)
    → ['url=https://exploit-server.net', 'https://exploit-server.net']
  location.href = 'https://exploit-server.net'
  → 피해자가 exploit-server.net 으로 이동
```

### 실행 흐름

```
1. 공격자: 피해자에게 조작된 URL 전달
   https://VULNERABLE.com/post?postId=4&url=https://evil.com

2. 피해자: 링크 클릭 → 타겟 사이트 방문
   (정상 사이트 URL 처럼 보임 → 신뢰)

3. 페이지 JS 실행:
   url 파라미터 값 추출 → https://evil.com
   location.href = 'https://evil.com'

4. 피해자: evil.com 으로 자동 이동
   → 피싱 페이지, 악성 파일 다운로드 등으로 유도
```

## 오픈 리다이렉트의 위험성

```
단독으로는 큰 피해가 없어 보이지만:

[피싱 공격]
  https://trusted-bank.com/redirect?url=https://fake-bank.com
  → URL 앞부분이 신뢰할 수 있는 도메인 → 피해자 속이기 쉬움
  → 가짜 로그인 페이지로 유도 → 자격증명 탈취

[OAuth 토큰 탈취]
  일부 OAuth 구현에서 redirect_uri 를 검증할 때
  오픈 리다이렉트를 통해 우회 가능
  → 인증 코드/토큰이 공격자 서버로 전달

[SSRF 연계]
  서버 사이드에서 URL 을 fetch 하는 경우
  내부 네트워크 접근 유도

[악성코드 배포]
  신뢰할 수 있는 도메인의 URL 로 악성 파일 다운로드 유도
```

## 이전 랩들 종합 비교 (001~004)

| 항목 | 001~003 | 004 (이번) |
|------|---------|-----------|
| 공격 방식 | postMessage (크로스 오리진) | URL 파라미터 직접 조작 |
| exploit 페이지 | 필요 (iframe + postMessage) | 불필요 |
| 소스 | `event.data` | `location.search` |
| 싱크 | innerHTML / location.href / iframe.src | `location.href` |
| 영향 | XSS 실행 | 임의 URL 로 리다이렉트 |
| 난이도 | 상대적으로 복잡 | 단순 (URL 파라미터만 조작) |

## 핵심 정리

- URL 파라미터를 읽어 `location.href` 에 설정할 때 값 검증이 없으면 오픈 리다이렉트 취약점이 발생한다.
- 피해자 입장에서는 신뢰할 수 있는 도메인의 URL 로 보이기 때문에 피싱 공격에 효과적으로 활용된다.
- **방어**:
  - URL 파라미터 기반 리다이렉트 자체를 제거하거나 화이트리스트로 제한
  - 상대 경로만 허용 (`/path/to/page` 형식, 외부 도메인 차단)
  - URL 파싱 후 호스트 검증:
    ```javascript
    const url = new URL(returnUrl, location.origin);
    if (url.origin === location.origin) {
        location.href = returnUrl;  // 같은 사이트만 허용
    }
    ```

## 배운 점 및 추가 학습

### 1. DOM 기반 오픈 리다이렉트 소스 유형

```javascript
// 자주 사용되는 소스들:
location.search   // ?returnUrl=https://...
location.hash     // #https://...
document.referrer // 이전 페이지 URL
postMessage       // 크로스 오리진 메시지

// 취약한 코드 패턴:
// 패턴 1: 정규식 추출
var url = /url=(https?:\/\/.+)/.exec(location.search);
location.href = url[1];

// 패턴 2: URLSearchParams
const returnUrl = new URLSearchParams(location.search).get('returnUrl');
location.href = returnUrl;

// 패턴 3: 해시
location.href = location.hash.slice(1);

// 패턴 4: 직접 비교
if (location.search.includes('redirect=')) {
    location.href = location.search.split('redirect=')[1];
}
```

### 2. 오픈 리다이렉트 방어 패턴

```javascript
// 방어 1: 상대 경로만 허용
function safeRedirect(url) {
    // 외부 URL 차단: //evil.com, https://evil.com 등
    if (/^(https?:)?\/\//i.test(url)) {
        url = '/';  // 기본 경로로 대체
    }
    location.href = url;
}

// 방어 2: 같은 오리진만 허용
function safeRedirect(url) {
    try {
        const parsed = new URL(url, location.origin);
        if (parsed.origin !== location.origin) {
            url = '/';
        }
    } catch {
        url = '/';
    }
    location.href = url;
}

// 방어 3: 화이트리스트
const allowed = [
    'https://trusted.com',
    'https://partner.com'
];
if (allowed.includes(returnUrl)) {
    location.href = returnUrl;
}
```

### 3. DOM 기반 vs 서버 기반 오픈 리다이렉트

```
[서버 기반 오픈 리다이렉트]
  서버가 302 응답으로 리다이렉트:
  GET /redirect?url=https://evil.com
  → HTTP 302 Location: https://evil.com

  탐지: Burp Suite 등으로 응답 헤더 확인 가능

[DOM 기반 오픈 리다이렉트 (이번 랩)]
  클라이언트 JS 가 location.href 변경:
  → 서버 요청 없이 브라우저에서만 처리
  → 서버 로그에 리다이렉트 기록 없음
  → 탐지/방어 어려움
  → JS 코드 분석 필요
```

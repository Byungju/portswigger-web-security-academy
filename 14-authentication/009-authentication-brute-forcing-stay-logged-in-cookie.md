# Lab: Brute-forcing a stay-logged-in cookie

## 개요

- **난이도**: Practitioner
- **주제**: Authentication — 유지 로그인(Stay logged in) 쿠키 / MD5 해시 노출 / 쿠키 brute-force
- **링크**: https://portswigger.net/web-security/authentication/other-mechanisms/lab-brute-forcing-a-stay-logged-in-cookie

## 목표

`stay-logged-in` 쿠키의 구조를 파악해 `carlos` 의 쿠키를 brute-force 로 만들어내고, 그의 `My account` 페이지에 접근한다.

- 내 계정: `wiener:peter`
- 피해자: `carlos`
- 입력 목록: candidate passwords

## 기초 개념 — 유지 로그인 쿠키

```
[목적]
  브라우저를 닫아도 로그인 상태를 유지 (Remember me)

[일반적 구현]
  서버가 별도 토큰을 발급하고 서버 측에 저장

[이 랩의 취약한 구현]
  쿠키 값이 base64(username + ":" + md5(password)) 형태로
  "비밀번호를 그대로 담은" 결정적 값
```

## 취약 지점

### 1. 쿠키가 비밀번호와 동등한 자격증명

```
stay-logged-in = base64( username + ":" + md5(password) )

wiener 로 로그인 → 쿠키 확인 → 디코딩
  wiener:51dc30ddc473d43a6011e9ebba6ca770
          └──────────────┬────────────────┘
                    md5("peter") 와 일치
```

- 서버는 이 쿠키를 비밀번호 검증 없이 신뢰한다.
- 즉, 쿠키를 위조할 수 있으면 그 계정으로 로그인할 수 있다.

### 2. MD5(솔트 없음) + 예측 가능

```
- 알고리즘이 널리 알려진 MD5 (레인보우 테이블/사전 공격 가능)
- 솔트 없음 → 동일 password 는 항상 동일 해시
- 후보 password 목록으로 오프라인 대입 가능
```

### 3. 시도 제한 부재

```
- 쿠키 검증 요청에 대한 rate limiting/잠금 없음
- 온라인으로도 100개 수준의 후보를 빠르게 시도 가능
```

## 공격 단계

### 1단계 — 쿠키 구조 파악

`wiener:peter` 로 **Stay logged in** 옵션을 켜고 로그인한다.
`stay-logged-in` 쿠키를 확인하고 Base64 디코딩한다.

```
Cookie: stay-logged-in=d2llbmVyOjUxZGMzMGRkYzQ3M2Q0M2E2MDExZTllYmJhNmNhNzcw

Base64 디코딩 → wiener:51dc30ddc473d43a6011e9ebba6ca770
MD5 확인     → md5("peter") = 51dc30ddc473d43a6011e9ebba6ca770
```

→ 형식 확인: `base64(username + ":" + md5(password))`

### 2단계 — 본인 쿠키로 공격 검증 (Burp Intruder)

`GET /my-account?id=wiener` 요청의 `stay-logged-in` 값에 payload 위치를 둔다.
**Payload processing** 을 순서대로 설정한다.

```
1) Hash: MD5
2) Add prefix: wiener:
3) Encode: Base64-encode
```

Grep - Match 로 `Update email` 을 지정해 인증 상태를 식별한다.
본인 password 를 넣어 규칙이 정상 동작함을 확인한다.

### 3단계 — carlos 쿠키 brute-force

```
- password 목록을 candidate passwords 로 교체
- URL 의 id 를 carlos 로 변경
- Add prefix 를 carlos: 로 변경
```

각 요청은 후보 password 로 만든 쿠키가 유효한지 확인한다.
`Update email` 이 포함된 응답이 하나뿐이며, 그 쿠키가 carlos 의 유효 쿠키다.

### 4단계 — 계정 접근

유효 쿠키로 `/my-account?id=carlos` 에 접근 → carlos 계정 → 랩 해결.
(or 찾은 password 로 로그인)

## 자동화 툴

```bash
python3 tools/14-authentication-stay-logged-in-cookie.py \
  --target "https://LAB-ID.web-security-academy.net" \
  --victim carlos --verify
```

```
동작:
  1) wiener:peter 쿠키로 형식/성공 시그니처 sanity check
  2) 후보 password 마다 base64(victim:md5(pw)) 쿠키로
     GET /my-account?id=victim 요청 (스레드 병렬)
  3) 응답에 "Update email" 또는 "Your username is: carlos" 가 있으면 성공
  4) --verify 시 찾은 password 로 POST /login 검증
```

주요 옵션:

```
--victim carlos             대상 username
--cookie-name stay-logged-in
--success-text "Update email"
--threads 10                동시 요청
--no-sanity                 자기 계정 형식 검증 생략
--verify                    찾은 자격증명으로 로그인 확인
```

검증 메모(목 서버): 형식 sanity 통과 → `carlos / <pw>` 및 유효 쿠키 발견 → 로그인 확인.

## 방어

```
[근본 원인]
  유지 로그인 쿠키가 비밀번호(해시)를 그대로 담은 결정적 값
  + 시도 제한 부재

[올바른 방어]
  1. 쿠키/토큰에 비밀번호(또는 그 해시)를 넣지 않는다
     - 서버가 무작위 토큰을 생성하고 서버 측 저장소에 매핑
     - 토큰에는 만료/회전/폐기(로그아웃, 비밀번호 변경 시 무효화) 적용
  2. 토큰을 예측 불가능하게 (충분한 엔트로피의 난수)
  3. 토큰 무결성 보호 (서명/HMAC) 및 HttpOnly·Secure·SameSite
  4. 시도 제한 / rate limiting / 이상 탐지
  5. 비밀번호는 솔트 + 강한 해시(bcrypt/scrypt/Argon2)로 저장
     (MD5 단독 사용 금지)

[주의]
  "해시가 들어 있으니 안전" 이 아니다. 솔트 없는 MD5 는 사실상 평문에 가깝다.
  쿠키 하나가 계정 전체를 여는 열쇠가 되어서는 안 된다.
```

## 핵심 정리

- `stay-logged-in` 쿠키가 `base64(username:md5(password))` 형식이라 쿠키만으로 계정 접근이 가능했다.
- password 후보 목록으로 쿠키를 만들어 brute-force 해 `carlos` 의 유효 쿠키/password 를 찾았다.
- 성공 판별은 인증 시에만 보이는 `Update email` 존재 여부로 했다.
- 방어는 비밀번호를 담지 않은 무작위 서버 측 토큰과 시도 제한, 강한 비밀번호 해시다.

## 배운 점

- 자격증명을 쿠키에 "인코딩" 하는 것은 암호화가 아니며, 예측 가능하면 곧 비밀번호 노출이다.
- 알려진 해시(MD5)·솔트 없음·시도 제한 없음이 결합하면 오프라인/온라인 brute-force 모두 가능하다.
- 003(비밀번호 재설정), 008(2FA)처럼 인증 보조 메커니즘도 본 인증과 동등한 공격 표면이다.
- 이 랩을 위해 `tools/14-authentication-stay-logged-in-cookie.py` 를 작성하고, 쿠키 형식 sanity check와 병렬 brute-force를 구현했다.

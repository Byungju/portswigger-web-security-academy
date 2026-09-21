# Lab: Referer-based access control

## 개요

- **난이도**: Practitioner
- **주제**: Access Control — Referer 헤더 기반 접근 제어 / 헤더 위조 / 수직적 권한 상승
- **링크**: https://portswigger.net/web-security/access-control/lab-referer-based-access-control

## 목표

일부 관리자 기능이 `Referer` 헤더로 접근을 통제한다. 일반 사용자 세션으로 `Referer` 를 관리자 페이지 URL 로 위조해 `/admin-roles` 를 호출하고, 스스로를 관리자로 승격시킨다.

- 관리자 계정: `administrator:admin` (구조 파악용)
- 일반 계정: `wiener:peter`

## 취약 지점 — Referer 기반 접근 제어

```
[서버의 판단 (추정)]
  GET/POST /admin-roles 요청에서
  Referer 헤더에 "/admin" 이 포함되어 있으면 허용

  Referer: https://LAB-ID.web-security-academy.net/admin
  → "관리자 페이지에서 온 요청" 으로 간주
```

- `/admin` 메인 페이지 자체는 적절히 보호될 수 있지만,
- 하위 기능(`/admin-roles`)은 Referer 만 검사해 통과시킨다.
- `Referer` 는 **클라이언트가 임의로 설정할 수 있는 헤더**다.

## Referer 헤더의 성질

```
[용도]
  브라우저가 "어느 페이지에서 이 요청을 보냈는가" 를 알려줌
  → 링크 클릭, 폼 제출 시 자동 설정

[중요한 성질]
  - 클라이언트(브라우저/프록시/스크립트)가 완전히 제어 가능
  - 생략 가능 (Referrer-Policy, 프라이버시 설정)
  - 위조 가능 (Burp/curl 로 임의 값 지정)

[결론]
  Referer 는 무결성이 없으므로 접근 제어의 근거가 될 수 없다.
```

## 공격 단계

### 1단계 — 관리자로 흐름 파악

`administrator:admin` 로 로그인하고 관리자 패널에서 `carlos` 를 승격시킨다.
요청을 Burp Repeater 로 보낸다.

```
GET /admin-roles?username=carlos&action=upgrade HTTP/1.1
Cookie: session=<administrator 세션>
Referer: https://LAB-ID.web-security-academy.net/admin
```

### 2단계 — 일반 사용자 세션으로 Referer 없이 시도

`wiener:peter` 로 로그인해 일반 사용자 세션 쿠키를 얻고,
Repeater 요청의 쿠키를 교체한 뒤 Referer 를 제거하고 보낸다.

```
GET /admin-roles?username=carlos&action=upgrade HTTP/1.1
Cookie: session=<wiener 세션>
```

응답: `Unauthorized` (Referer 부재) → Referer 기반 통제임을 확인.

### 3단계 — Referer 위조 + 대상 변경

세션은 일반 사용자 그대로 두고, Referer 를 관리자 페이지 URL 로 설정한다.
대상은 자기 자신(`wiener`)으로 바꾼다.

```
GET /admin-roles?username=wiener&action=upgrade HTTP/1.1
Cookie: session=<wiener 세션>
Referer: https://LAB-ID.web-security-academy.net/admin
```

Referer 검사를 통과해 `wiener` 가 관리자로 승격된다 → 랩 해결.

## Referer 검사 우회 정리

```
[필터가 보는 것]
  Referer 헤더 값에 특정 문자열(/admin) 포함 여부

[필터가 놓치는 것]
  Referer 는 클라이언트가 임의로 만들 수 있음
  → 관리자 페이지만 위조하면 됨
  → 세션(실제 사용자 권한)과 전혀 연결되지 않음

[핵심]
  "어디서 왔는가" 는 "누구인가/권한이 있는가" 를 대신할 수 없다.
```

## 방어

```
[근본 원인]
  Referer 헤더 값으로 접근 권한을 판단
  → 클라이언트가 제어 가능한 값에 인가를 위임

[올바른 방어]
  1. 접근 제어는 서버 측 세션/권한으로만 수행
     - "요청자의 역할이 관리자인가?" 를 검사 (deny by default)
     - Referer/Origin 등 헤더는 참고 정보로만 사용
  2. 민감 기능은 모든 단계·메서드에서 동일하게 인가
  3. CSRF 방어가 필요하면 Referer 확인이 아니라
     CSRF 토큰(추측 불가, 세션 연동)을 사용
  4. 보안 목적의 Referer 검사 로직 제거

[안티패턴]
  Referer 가 /admin 을 포함하면 관리자로 간주
  Referer 존재 여부만으로 권한 판단
  UI 에서 관리자 링크를 숨기는 것으로 대체
```

## 핵심 정리

- `/admin-roles` 는 `Referer` 에 `/admin` 이 있으면 허용하는 취약한 통제를 사용했다.
- 일반 사용자 세션으로 `Referer` 를 관리자 URL 로 위조하고 `username=wiener` 로 호출해 자기 자신을 승격시켰다.
- `Referer` 는 클라이언트가 완전히 제어할 수 있어 접근 제어의 근거가 될 수 없다.
- 방어는 세션 기반 서버 측 인가이며, 헤더 검사에 의존하지 않아야 한다.

## 배운 점

- "요청이 어디서 왔는가(Referer)" 는 "요청자에게 권한이 있는가" 와 무관하며 위조 가능하다.
- 010(경로), 011(메서드), 012(단계), 013(헤더) 모두 "권한이 아닌 다른 것을 검사해서 생긴 우회" 라는 공통점이 있다.

---

## Access Control 시리즈 정리

| # | 랩 | 유형 | 취약 원인 | 우회 |
|---|-----|------|-----------|------|
| 001 | Unprotected admin functionality | 수직 | 기능 보호 없음 | `robots.txt` → `/administrator-panel` |
| 002 | ...with unpredictable URL | 수직 | 기능 보호 없음 | JS 소스에서 admin URL |
| 003 | User role controlled by request parameter | 수직 | 파라미터 기반 제어 | 쿠키 `Admin=true` |
| 004 | User role can be modified in user profile | 수직 | Mass Assignment | JSON 에 `roleid:2` |
| 005 | User ID controlled by request parameter | 수평 | IDOR | `id=carlos` |
| 006 | ...with unpredictable user IDs | 수평 | IDOR (GUID) | 블로그에서 GUID 수집 |
| 007 | ...with data leakage in redirect | 수평 | 인가 전 데이터 생성 | 302 body 에서 API 키 |
| 008 | ...with password disclosure | 수평→수직 | IDOR + 비밀번호 프리필 | admin 비밀번호 획득 후 로그인 |
| 009 | Insecure direct object references | 수평 | 정적 파일 IDOR | `1.txt` 순번 변조 |
| 010 | URL-based access control can be circumvented | 수직 | 플랫폼 설정 오류 | `X-Original-URL: /admin` |
| 011 | Method-based access control can be circumvented | 수직 | 메서드 기반 제어 | POST → GET |
| 012 | Multi-step process with no access control on one step | 수직 | 단계별 인가 누락 | confirm 단계 직접 호출 |
| 013 | Referer-based access control | 수직 | Referer 기반 제어 | `Referer` 위조 |

**공통 교훈**

```
- 접근 제어는 "권한(세션/역할)" 으로 판단해야 하며,
  경로/메서드/단계/헤더/파라미터 등 우회 가능한 값에 의존하면 안 된다.
- 검사 지점과 실행 지점이 다르면(계층 불일치, 순서 문제) 우회된다.
- 민감 데이터를 응답에 담지 않아야 하며, 인가 검사를 데이터 처리보다 먼저 수행해야 한다.
- 방어 원칙: deny by default, 단일 전역 인가, 리소스별 권한 명시, 서버 측 검증.
```

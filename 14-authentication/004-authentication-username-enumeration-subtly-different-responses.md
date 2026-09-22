# Lab: Username enumeration via subtly different responses

## 개요

- **난이도**: Apprentice
- **주제**: Authentication — Username Enumeration / 미묘한 응답 차이 / Password Brute-force
- **링크**: https://portswigger.net/web-security/authentication/password-based/lab-username-enumeration-via-subtly-different-responses

## 목표

에러 메시지의 아주 미묘한 차이(마침표 대신 후행 공백)를 이용해 유효한 username 을 열거하고, 해당 사용자의 password 를 brute-force 해 계정에 접근한다.

- 입력 목록: PortSwigger candidate usernames / passwords

## 이전 랩(001)과의 차이

```
[001 — different responses]
  메시지가 명확히 다름
  "Invalid username" vs "Incorrect password"
  → Grep Match 로 쉽게 구분

[004 — subtly different (이번)]
  메시지가 거의 동일하고 "미묘하게" 다름
  "Invalid username or password."  (마침표)
  "Invalid username or password "  (마침표 대신 후행 공백, typo)
  → 육안/길이로는 놓치기 쉬움
```

## 취약 지점

### 에러 메시지의 미묘한 차이

```
[존재하지 않는 username]
  Invalid username or password.     ← 마침표(.)로 끝남

[존재하는 username + 틀린 password]
  Invalid username or password      ← 마침표 대신 후행 공백
```

- 두 응답은 길이도 거의 같고(1바이트 차이) 문구도 동일해 보인다.
- 하지만 실제로는 마지막 문자(마침표 vs 공백)가 다르며, 이것이 username 존재 여부를 노출한다.
- 응답 body 를 그대로 비교하지 않으면 놓치는 전형적인 "미묘한 차이" 취약점이다.

## 공격 단계

### 1단계 — 로그인 요청 분석

아무 자격증명으로 로그인을 시도하고 `POST /login` 요청을 캡처한다.
(CSRF 토큰 포함)

```http
POST /login HTTP/1.1
Content-Type: application/x-www-form-urlencoded

username=invalid&password=invalid&csrf=<token>
```

### 2단계 — Username Enumeration (Burp Intruder)

username 파라미터에 후보 목록을 넣고, password 는 고정한다.

```
username=§candidate§ & password=invalid
```

**Settings → Grep - Extract** 로 에러 메시지 `Invalid username or password.` 를 추출하면
결과 테이블에 메시지 컬럼이 생긴다. 이 컬럼을 정렬하면 **단 하나만 미묘하게 다르다.**

```
다른 항목 : "Invalid username or password."
유효 항목 : "Invalid username or password "   ← 후행 공백 (typo)
```

→ 유효 username 확인

### 3단계 — Password Brute-force

찾은 username 을 고정하고 password 후보를 순회한다.

```
username=<identified>&password=§candidate§
```

상태 코드가 `200` 이 아닌 **`302`**(계정 페이지로 리다이렉트)인 항목이 성공이다.

### 4단계 — 로그인

찾은 자격증명으로 로그인해 계정 페이지에 접근 → 랩 해결.

## 자동화 툴

미묘한 차이는 exact-match 기반 툴로는 놓치므로 전용 툴을 사용한다.

```bash
python3 tools/14-authentication-subtle-enum.py \
  --target "https://LAB-ID.web-security-academy.net" --verify
```

동작 원리:

```
1) 에러 메시지 앵커("Invalid username or password") 뒤 꼬리를 추출해 repr 로 비교
   → 후행 공백/마침표 같은 비가시 문자 차이를 노출
2) 최빈 응답(modal)과 difflib 로 diff → 첫 차이 위치/컨텍스트 출력
3) 유효 username 탐지 후 password 목록 순회
   → 성공 판정은 상태 코드(302)를 1차 기준으로 사용
```

### 툴 디버깅에서 배운 점

```
[문제 1] 성공 판정을 "실패 문구 부재" 로 처리
  → username 이 틀렸거나 문구가 다르면 첫 시도부터 성공으로 오탐
  → 해결: 302(리다이렉트)를 성공의 1차 기준으로 사용,
          실패문구도 302도 아닌 응답은 "불확실"로 별도 보고

[문제 2] 이 랩은 유효 username + 틀린 password 응답에도
        "Invalid username or password" 가 포함됨
  → 이를 "username 무효" 로 오판해 중단하는 로직 제거
  → pass-fail 시그니처도 이 랩에 맞게 조정

[문제 3] CSRF 토큰이 응답마다 회전될 수 있음
  → 매 응답에서 토큰을 재파싱해 갱신
```

## 방어

```
[근본 원인]
  인증 실패 응답이 경로/상태에 따라 미묘하게 달라
  username 존재 여부가 드러남 (typo 포함)

[올바른 방어]
  1. 인증 실패 응답을 완전히 동일하게 반환
     - 메시지 문자열(문장부호·공백 포함), 상태 코드, 헤더, 길이까지 일치
     - 공통 에러 템플릿 사용
  2. 타이밍 차이도 완화
     - username 존재 여부와 무관하게 동일한 연산/지연
  3. Brute-force 방어
     - 실패 횟수 기반 rate limiting, 지수 백오프, 계정 잠금(알림 동반)
     - CAPTCHA, IP/계정 단위 제한
  4. 강한 비밀번호 정책 + 유출 비밀번호 차단 + MFA
  5. 로그인 실패 모니터링/탐지

[주의]
  "Invalid username or password" 처럼 문구를 통일해도
  코드 경로에 따라 마침표/공백 하나가 달라지면 열거가 가능하다.
```

## 핵심 정리

- 인증 실패 메시지가 `...password.`(마침표)와 `...password `(후행 공백)로 미묘하게 달라 username 을 열거할 수 있었다.
- 길이·상태코드·문구가 거의 같아 육안으로는 어렵지만, 응답을 정밀 비교하면 차이가 드러난다.
- 유효 username 을 찾은 뒤 password 를 brute-force 했고, 성공은 302 리다이렉트로 판별했다.
- 방어는 실패 응답을 문장부호·공백·타이밍까지 완전히 동일하게 만드는 것이다.

## 배운 점

- 정보 노출은 뚜렷한 메시지 차이가 아니라 문장부호 하나에서도 발생한다.
- 자동화 툴에서 "실패 시그니처 부재 = 성공" 은 위험한 가정이며, 상태 코드를 1차 근거로 삼아야 한다.
- 인증 관련 툴은 CSRF 토큰 회전, 동적 응답 등 실험 환경의 세부 동작까지 고려해야 오탐/미탐을 줄일 수 있다.
- 이 랩을 통해 `tools/14-authentication-subtle-enum.py` 를 작성·보완하며 미묘한 차이 탐지와 견고한 성공 판정을 익혔다.

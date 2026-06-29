# Lab: SQL injection vulnerability allowing login bypass

## 개요

- **난이도**: Apprentice
- **주제**: SQL Injection — Login Bypass
- **링크**: https://portswigger.net/web-security/sql-injection/lab-login-bypass

## 목표

SQL injection을 이용해 `administrator` 계정으로 로그인 인증을 우회하고, 해당 계정의 이메일을 업데이트한다.

## 분석

로그인 폼에서 username과 password를 입력하면 서버 측에서 아래와 같은 쿼리가 실행된다고 추정할 수 있다.

> **참고**: 서버 측 쿼리는 직접 볼 수 없다. 아래는 응답 동작을 통해 추측한 구조이며, PortSwigger 랩 설명에서도 이 구조를 힌트로 제공한다.

```sql
SELECT * FROM users WHERE username = 'input_username' AND password = 'input_password'
```

- `username`과 `password` 파라미터가 쿼리에 직접 삽입된다.
- 두 조건이 모두 참일 때만 로그인에 성공한다.
- `administrator`처럼 높은 권한을 가진 계정이 존재한다면, password 조건만 무력화해도 해당 계정으로 로그인할 수 있다.

## 풀이

### 1단계 — 로그인 우회

`username` 입력란에 다음 페이로드를 삽입한다.

```
administrator'--
```

`password` 입력란에는 임의의 값을 입력한다.

최종 실행되는 쿼리:

```sql
SELECT * FROM users WHERE username = 'administrator'--' AND password = 'anything'
```

| 요소 | 역할 |
|------|------|
| `administrator` | 로그인 대상 계정 지정 |
| `'` | username 문자열 리터럴을 닫음 |
| `--` | `AND password = '...'` 조건 전체를 주석 처리하여 무력화 |

password 조건이 사라지므로 비밀번호 없이 `administrator` 계정으로 로그인에 성공한다.

### 2단계 — 이메일 업데이트

로그인 후 계정 정보 페이지에서 이메일을 변경한다. 이 단계는 administrator 권한으로 로그인이 실제로 성공했음을 확인하는 과정이다.

## 핵심 정리

- password 조건을 `--` 주석으로 제거하면 username만으로 로그인할 수 있다.
- 001 랩의 WHERE 절 우회와 동일한 원리로, **주석 처리를 통해 쿼리의 일부를 무력화**한다.
- **방어**: Prepared Statement(Parameterized Query)를 사용하여 입력값이 쿼리 구조에 영향을 줄 수 없도록 해야 한다.

## 배운 점 및 추가 학습

### 1. 001 랩과의 공통점 — 주석을 이용한 우회

| 랩 | 페이로드 | 무력화 대상 |
|----|----------|------------|
| 001 (WHERE 필터) | `' OR 1=1--` | `AND released = 1` |
| 002 (로그인 우회) | `administrator'--` | `AND password = '...'` |

두 랩 모두 `--` 주석으로 쿼리 뒷부분을 잘라내는 구조다. 차이점은 001은 OR로 조건을 추가했고, 002는 OR 없이 계정명만으로 username 조건을 직접 충족했다는 점이다.

### 2. 권한 있는 계정 이름 사용에 대한 주의

공격자 입장에서 계정명을 추측할 때 가장 먼저 시도하는 것이 시스템에서 관례적으로 사용되는 고권한 계정 이름이다.

| 계정명 | 주로 사용되는 환경 |
|--------|-------------------|
| `administrator` | Windows, 일반 웹 애플리케이션 |
| `admin` | 웹 애플리케이션 일반 |
| `root` | Linux/Unix, MySQL |
| `postgres` | PostgreSQL |
| `sa` | Microsoft SQL Server |
| `system` / `sys` | Oracle DB |
| `superuser` | PostgreSQL |

- 이러한 이름은 공격자가 **사전 없이 추측할 수 있는 고정 타깃**이다.
- SQL injection 취약점이 없더라도 계정명이 예측 가능하면 Brute Force, Credential Stuffing 공격의 대상이 된다.
- **방어**: 고권한 계정에 예측하기 어려운 이름을 사용하거나, 해당 계정의 외부 로그인을 차단해야 한다.

### 3. 추가로 고민해볼 것

- `username` 외에 `password` 필드에도 주석 페이로드를 삽입하면 어떻게 될까? (필드에 따라 동작이 달라질 수 있음)
- 로그인 폼의 어느 필드가 SQL에 직접 삽입되는지 확인하려면, 각 필드에 `'`를 하나씩 넣어 에러 응답이나 동작 차이를 관찰하는 것이 첫 단계다.
- 계정명을 모르는 상황이라면 `' OR 1=1--` 조합으로 첫 번째 행의 계정으로 로그인되는 경우도 있다.

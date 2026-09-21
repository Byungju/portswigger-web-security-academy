# Lab: Unprotected admin functionality with unpredictable URL

## 개요

- **난이도**: Apprentice
- **주제**: Access Control — 보호되지 않은 관리자 기능 / 예측 불가 URL / 소스 정보 노출
- **링크**: https://portswigger.net/web-security/access-control/lab-unprotected-admin-functionality-with-unpredictable-url

## 목표

예측 불가능한 위치에 숨겨진 관리자 패널을 애플리케이션 소스에서 찾아내고, 접속해 `carlos` 계정을 삭제한다.

## 이전 랩(001)과의 차이

```
[001 — unprotected admin functionality]
  경로는 /administrator-panel (고정)
  노출 위치: robots.txt 의 Disallow 라인
  → robots.txt 로 경로 획득

[002 — unpredictable URL (이번)]
  경로는 /admin-<무작위값> (예측 불가)
  노출 위치: 홈 페이지 HTML 내 JavaScript
  → 페이지 소스에서 URL 획득
```

취약점의 본질(관리자 기능에 대한 접근 제어 부재)은 **001과 동일**하다.
차이는 **숨겨진 경로를 알아내는 방법**뿐이다.

## 취약 지점

### 1. 관리자 기능에 대한 접근 제어 부재 (본질)

```
/admin-<무작위값>
  → URL 이 추측하기 어려울 뿐, 서버는 사용자 역할을 검사하지 않음
  → 경로를 아는 순간 누구나 접근 가능
```

### 2. JavaScript 를 통한 관리자 URL 노출

홈 페이지 소스에 역할에 따라 관리자 링크를 생성하는 스크립트가 포함되어 있다.

```html
<script>
    var isAdmin = false;
    if (isAdmin) {
        ...
        var adminPanelTag = document.createElement('a');
        adminPanelTag.setAttribute('href', '/admin-1a2b3c');
        adminPanelTag.innerText = 'Admin panel';
        ...
    }
</script>
```

- 일반 사용자에게는 `isAdmin = false` 라 링크가 만들어지지 않는다.
- 그러나 **스크립트 자체는 모든 사용자에게 전송**되므로, 소스를 보면 URL 이 그대로 노출된다.

## 공격 단계

### 1단계 — 홈 페이지 소스 검토

브라우저 개발자 도구 또는 Burp Suite 로 홈 페이지 응답을 확인한다.

```
GET / HTTP/1.1
Host: LAB-ID.web-security-academy.net
```

응답 소스에서 관리자 패널 경로를 발견:

```html
adminPanelTag.setAttribute('href', '/admin-1a2b3c');
```

### 2단계 — 관리자 패널 접근

```
GET /admin-1a2b3c HTTP/1.1
Host: LAB-ID.web-security-academy.net
```

인증/권한 검사 없이 관리자 패널 HTML 이 반환된다.

### 3단계 — carlos 삭제

```
GET /admin-1a2b3c/delete?username=carlos HTTP/1.1
Host: LAB-ID.web-security-academy.net
```

carlos 삭제 완료 → 랩 해결.

## 예측 불가 URL 이 방어가 되지 못하는 이유

```
[Security by Obscurity]
  "URL 을 추측하기 어렵게 만들면 안전할 것" 이라는 가정

[가정이 깨지는 지점]
  1. 클라이언트에 전송되는 스크립트에 URL 이 포함됨
     → 소스 보기로 그대로 노출
  2. 다른 응답/주석/에러 메시지에서 유출될 수 있음
  3. 브루트포스/디렉토리 스캔으로도 발견 가능
  4. 관리자 UI 에서 링크가 생성되는 구조라면 어딘가에 반드시 존재

[결론]
  접근 제어는 "경로를 아는가" 가 아니라
  "서버가 권한을 검사하는가" 로 결정되어야 한다
```

## 방어

```
[근본 원인]
  관리자 기능에 서버 측 권한 검사가 없음

[올바른 방어]
  1. 모든 민감 기능에 서버 측 접근 제어 적용 (deny by default)
     - 요청마다 세션 사용자 역할 검사 (일반 사용자 요청은 403/redirect)
  2. 관리자 URL/링크를 클라이언트에 불필요하게 노출하지 않음
     - 역할에 따른 링크 생성은 서버에서 처리
     - 비관리자 응답에 admin 경로/스크립트 포함 금지
  3. 추측 불가 URL 을 보안 수단으로 사용하지 않음
  4. 단일 전역 인가 메커니즘으로 라우트별 권한 선언

[안티패턴]
  관리자 페이지를 "숨기는" 것만으로 보호했다고 간주
  JavaScript 안에 관리자 경로를 하드코딩해 모든 사용자에게 전송
```

## 핵심 정리

- 관리자 패널 경로가 무작위(`/admin-<random>`)여도 접근 제어가 없으면 누구나 접근할 수 있다.
- 경로는 홈 페이지의 JavaScript 소스에 그대로 노출되어 있었고, 소스 검토로 알아낼 수 있었다.
- 001과 취약점 본질은 같고, 경로 발견 경로(robots.txt → HTML/JS 소스)만 다르다.
- 방어는 URL 은닉이 아니라 서버 측 권한 검사이며, 비관리자 응답에 admin 경로를 노출하지 않아야 한다.

## 배운 점

- 예측 불가능한 URL 은 보안이 아니다(Security by Obscurity). 경로를 알아내는 것과 접근 권한을 얻는 것은 별개다.
- 클라이언트에 전송되는 모든 코드/데이터는 공격자가 볼 수 있다고 가정해야 한다.
- 정보 수집 시 소스 보기, JS 파일, robots.txt, sitemap 등을 함께 확인하는 습관이 관리자 경로 발견에 효과적이다.

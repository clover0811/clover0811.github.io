---
title: "structure-based carving"
date: 2026-05-11
categories: [Write-up]
tags: [Digital Forensics, ZIP, Dreamhack]
---

## 문제 정보

- 플랫폼: Dreamhack
- 문제명: structure-based carving
- 분야: Digital Forensics

<img width="600" height="300" alt="image" src="https://github.com/user-attachments/assets/2d6cad53-4dde-46c9-aace-fa196caf9981" />


이번 문제는 주어진 파일 안에서 구조를 기준으로 필요한 데이터를 찾아내는 문제였다.  
힌트로 ZIP 구조 어딘가에 압축 패스워드가 있다고 제시되어 있었기 때문에, 파일 내부에 존재하는 ZIP 파일을 찾아 분석하는 방향으로 접근했다.

---

## 문제 풀이

ZIP 파일의 Local File Header는 `50 4B 03 04` 시그니처로 시작한다.  
따라서 먼저 HxD에서 해당 값을 검색해 파일 내부에 존재하는 ZIP 헤더들을 확인했다.

다만 파일 내부에는 ZIP 헤더 시그니처가 여러 개 존재했기 때문에, 이 중에서 어떤 ZIP 파일이 문제와 관련 있는지 구분할 필요가 있었다.

ZIP의 Local File Header에는 `general purpose bit flag`라는 값이 존재하며, ZIP 헤더 시그니처 기준 7~8번째 바이트에 저장된다.

`general purpose bit flag`는 ZIP 내부의 각 파일 항목에 어떤 설정이 적용되어 있는지를 비트 단위로 표시하는 값이다.  
여러 개의 비트가 각각 다른 의미를 가지며, 그중 `bit 0`은 암호화 여부를 나타낸다.

'bit 0 = 1'이면 해당 파일 항목이 암호화되어 있다는 뜻이다.

예를 들어 `general purpose bit flag`가 `01 00`, `03 00`, `05 00`처럼 첫 번째 바이트가 홀수라면, 2진수로 보았을 때 가장 오른쪽 비트가 `1`이 되므로 `bit 0 = 1`이라고 판단할 수 있다.

처음에는 ZIP 헤더 시그니처를 하나씩 확인하면서, `general purpose bit flag`의 `bit 0`이 `1`인 암호화된 ZIP 항목을 찾는 방식으로 접근했다.  
그 결과 `0xeeade8` 위치에서 'general purpose bit flag'가 '09 00'인 암호화된 ZIP 파일이 시작되는 것을 확인할 수 있었다.

<img width="1500" height="450" alt="image" src="https://github.com/user-attachments/assets/8f8e9c56-16c8-494f-8311-0ad3657ff9a0" />

이후 해당 ZIP 파일의 구조를 따라 뒤쪽의 `Central Directory File Header`를 확인했다.  
이 영역에는 파일 이름 뒤에 추가 정보를 저장할 수 있는 `extra field`가 존재하는데, 암호화된 ZIP 파일 구조의 끝 부분(다음 ZIP 헤더 시그니처 전)에서 `a1b2c3d4e5f6` 문자열을 확인할 수 있었다.

<img width="1500" height="200" alt="image" src="https://github.com/user-attachments/assets/0997161c-f946-406f-8992-119166464fac" />

발견한 문자열을 비밀번호로 사용해서 ZIP 파일의 압축을 해제했고, 그 결과로 플래그 획득~

<img width="500" height="400" alt="image" src="https://github.com/user-attachments/assets/b362954f-ae20-4bb2-a834-66fc0df39097" />

---

## 풀이 후 알게 된 점

처음에는 HxD에서 `50 4B 03 04`를 직접 검색한 뒤, 각 ZIP 헤더의 `general purpose bit flag`를 하나씩 확인하는 방식으로 접근했다.  
이론적으로는 이 방법만으로도 암호화된 ZIP 항목을 찾을 수 있지만, 파일 내부에 ZIP 헤더가 많이 존재할 경우 모든 값을 직접 확인해야 하므로 시간이 오래 걸린다는 한계가 있었다.

이후 더 효율적인 방법을 찾아보면서 아래의 파이썬 코드와 같이 ZIP 헤더 시그니처를 찾고 그중 `general purpose bit flag`의 `bit 0`이 `1`인 항목만 자동으로 골라내는 방식이 가능하다는 것을 알게 되었다.

```python
def isFlagZip(data, offset):
    condition1 = (data[offset:offset+4] == b'\x50\x4b\x03\x04')
    condition2 = (data[offset+6] & 1 == 1)
    if condition1 and condition2:
        return True
    else:
        return False

with open('carving_target.bin', 'rb') as f:
    data = f.read()
    
idx = 0
while True:
    idx = data.find(b'\x50\x4b\x03\x04', idx)
    if idx == -1:
        break
    if isFlagZip(data, idx):
        print("find: ", hex(idx))  # find:  0xeeade8 출력
    idx += 1
```

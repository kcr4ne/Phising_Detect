# Phising_Detect

Windows용 피싱 문자 탐지 GUI 프로그램입니다. 사용자는 `phishing-detector.exe`를 실행한 뒤 문자 내용과 발신번호를 입력하면 프로그램이 피싱 위험도를 자동으로 판단합니다.
<img width="2348" height="1604" alt="image" src="https://github.com/user-attachments/assets/ff1e33ab-2859-498f-8e14-cbd94a06b4b4" />

## 실행 방법

1. `phishing-detector.exe` 파일을 실행합니다.
   <img width="1094" height="172" alt="image" src="https://github.com/user-attachments/assets/8433c42c-e20d-4ec5-8491-94704abdd008" />

2. 검사할 문자 내용을 입력합니다.
   <img width="740" height="350" alt="image" src="https://github.com/user-attachments/assets/3b8c065c-9355-4ed9-a26b-bd726e9d5e5c" />

3. 필요하면 발신번호도 입력합니다.
   <img width="472" height="128" alt="image" src="https://github.com/user-attachments/assets/449e0bcb-aa6d-4ae9-9974-3f4e04e595fe" />

4. `정밀검사` 버튼을 누릅니다.
   <img width="618" height="302" alt="image" src="https://github.com/user-attachments/assets/ff433666-6b45-4575-8665-f55ee9685d5d" />

5. 결과 화면에서 위험 등급, 점수, 탐지 URL, 키워드, 판단 근거를 확인합니다.
   <img width="1458" height="1188" alt="image" src="https://github.com/user-attachments/assets/fc43db97-f558-4f34-916d-ddd6e084477a" />

## 실행 파일 위치 주의

`phishing-detector.exe`는 바탕화면, 다운로드 폴더, USB처럼 파일 생성이 가능한 위치에서 실행하는 것이 좋습니다.

프로그램 실행 시 `phishing_rules.db` 파일이 exe와 같은 폴더에 자동 생성됩니다. 이 DB에는 위험 키워드, 공식 도메인, 예시 문자, 검사 로그가 저장됩니다.
<img width="360" height="152" alt="image" src="https://github.com/user-attachments/assets/04db6b9b-fa27-429d-9365-5409e8ad5158" />

## 공유 시 주의사항

다른 사람에게 프로그램을 공유할 때는 보통 `phishing-detector.exe`만 공유하면 됩니다.

단, 실행 후 생성된 `phishing_rules.db`에는 사용자가 검사한 문자 기록이 포함될 수 있으므로 함께 공유하지 않는 것이 좋습니다.

## 주요 기능

- 문자 내용과 발신번호를 바탕으로 피싱 위험도 분석
- URL, 도메인, 단축 URL, IP 주소 URL, 의심 도메인 탐지
- 공식 도메인은 정상 확정이 아니라 감점 신호로만 반영
- 개인정보 요구, 인증번호 요구, 앱 설치 유도, 긴급성 표현 탐지
- 브랜드명과 URL 도메인이 다른 사칭 문자 탐지
- Discord/Steam 같은 영문 이벤트 사칭 문자 탐지
- 검사 결과를 GUI에서 확인하고 복사 가능

## 등급 기준

- 0~2점: 정상 가능성 높음
- 3~5점: 의심
- 6~8점: 위험
- 9점 이상: 고위험

## Command Execution

소스 코드로 실행하려면 `python app.py`를 사용합니다.

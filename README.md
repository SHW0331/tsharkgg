# tshark.gg

## 프로젝트 개요
### 목적
- Python의 `subprocess` 모듈과 `tshark` 명령어를 사용하여 PCAP 데이터를 실시간으로 분석.
- Flask 기반 웹 대시보드를 통해 데이터를 시각화하고 빠르고 간단한 분석 제공.
- Wireshark의 차별화: 쉽고 직관적이며 핵심 정보에 초점.

### 기대효과
- 실시간 네트워크 트래픽 분석 가능.
- 대시보드 상에서 주요 통계를 한눈에 확인.
- 일반 사용자도 이해하기 쉬운 UI 제공.

## 주요 기능
### 데이터 분석
- `tshark`를 통해 실시간으로 PCAP 데이터를 추출.
- 추출 항목:
  - 패킷 개수
  - 프로토콜 분포 (TCP, UDP, HTTP, DNS)
  - 상위 발신/수신 IP 및 포트
  - 특정 키워드 또는 필터 조건 기반 패킷 검색

### 실시간 대시보드
- 주요 섹션:
  - **트래픽 개요**:
    - 총 패킷 수
    - 실시간 패킷 속도
  - **프로토콜 분포 그래프**:
    - 원형 차트 또는 막대그래프로 표시
    - 실시간 패킷 속도 그래프
    - 상위 발신/수신 IP 그래프
    - 상위 사용 포트량 그래프
    - 비정상 트래픽 탐지 그래프
  - **IP 및 포트 통계**:
    - 가장 많이 사용된 IP 주소 및 포트 리스트.
  - **필터링 및 검색**:
    - 특정 프로토콜, IP, 포트, 또는 키워드 기반 실시간 검색.
  - **위험 탐지**:
    - 비정상 트래픽(예: 포트 스캔, DoS 시도 등) 알림.

### 사용자 정의 기능
- **필터 추가**:
  - 특정 프로토콜, IP 주소, 포트를 기반으로 필터 설정.
- **결과 다운로드**:
  - 분석 결과를 CSV 또는 JSON으로 저장.
- **알림 시스템**:
  - 특정 조건 만족 시 사용자에게 알림 제공 (예: 과도한 트래픽 발생).

## 차별화 포인트
1. **사용자 친화적 인터페이스**:
   - 복잡한 메뉴 없이 대시보드에서 바로 데이터 요약 확인 가능.
   - 초보자도 쉽게 사용 가능.
2. **경량화**:
   - Wireshark보다 적은 리소스로 빠른 데이터 분석 제공.
3. **자동화된 알림 (미정)**:
   - 비정상 트래픽 탐지 시 즉시 알림.
4. **웹 기반 접근**:
   - 설치 필요 없이 웹 브라우저로 실시간 접근 가능.

## 시스템 구성
### 흐름도
1. Flask 서버 실행
2. `subprocess`로 `tshark` 실행하여 실시간 데이터 수집
3. 데이터를 JSON으로 변환
4. Flask API로 데이터를 전달
5. Frontend에서 시각화 및 표시

## 실행 환경
- Python 3.12.4
- Flask 3.1.0
- tshark 4.x
- JavaScript (Frontend 시각화 라이브러리: Chart.js 또는 D3.js)

## 필수 라이브러리 설치
1. Flask 애플리케이션 실행 전, 필수 라이브러리를 설치:
   ```bash
   pip install flask
   pip install requests
   ```

## 사용 방법
1. 리포지토리를 클론합니다:
   ```bash
   git clone https://github.com/your-repository/pcap-dashboard.git
   ```
2. Flask 서버를 실행합니다:
   ```bash
   python app.py
   ```
3. 웹 브라우저에서 대시보드에 접근합니다:
   ```
   http://localhost:5000
   ```

## 기대 결과
- 실시간으로 네트워크 트래픽 데이터가 대시보드에 표시.
- 사용자는 직관적으로 트래픽 정보를 탐색하고 분석 가능.
- 간단한 클릭으로 필터를 적용하거나 결과를 다운로드 가능.

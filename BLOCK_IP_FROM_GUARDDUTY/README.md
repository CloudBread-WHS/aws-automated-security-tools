이벤트 브릿지에서 Guardduty 결과를 탐지하면 Lambda 코드에서 공격자 ip를 자동으로 NACL에 차단 정책을 추가하는 코드입니다.

## 작동 과정
1. NACL과 DB정보 가져오기
2. NACL에 있고 DB에 없다면 DB 추가, NACL에 없고 DB에 있다면 DB제거 (관리가 편해짐)
3. NACL 정책이 20개라면 DB에서 가장 오래된 정책을 찾아서 제거
4. 클라우드 와치에서 공격자ip 추출 (위험도 높음을 대상으로으로)
5. 낮은 번호부터 빈자리 찾아서 nacl에 공격자 ip 차단 정책 추가
6. 공격자 ip와 적용 시간을 DB에 저장

# 설정
## Lambda 함수 설정


## EventBridge 설정
Amazon Eventbridge - 버스 - 규칙 - 규칙생성
![1](https://github.com/CloudBread-WHS/aws-automated-security-tools/assets/51049963/9180e31a-24f6-4f31-bc6f-d486031d1bea)
규칙 이름과 설명 작성 후 다음으로 이동
![2](https://github.com/CloudBread-WHS/aws-automated-security-tools/assets/51049963/7942d199-06f3-49fa-91a8-9229cc729688)
이벤트 소스 작성의 이벤트 소스에는 "AWS 이벤트 또는 EventBridge 파트너 이벤트 선택"
나머지는 그대로 유지하고 이벤트 패턴에서 패턴 편집을 누르고 자동대응 할 guardduty finding type json 입력
(eventbridge-in/outbound.json는 예시일 뿐 사용자가 원하는 방법으로 사용해야 한다.)
![image](https://github.com/CloudBread-WHS/aws-automated-security-tools/assets/51049963/930fa888-59fd-4207-bbe5-11b243b94fb2)
![image](https://github.com/CloudBread-WHS/aws-automated-security-tools/assets/51049963/4bc1b8d9-6c6a-4431-aea6-affbf17cdebf)
자동화 하고싶은 guardduty 결과들을 입력하고 다음으로 이동한다
결과 유형 참고(https://docs.aws.amazon.com/ko_kr/guardduty/latest/ug/guardduty_finding-types-active.html)
![제목 ssss없음](https://github.com/CloudBread-WHS/aws-automated-security-tools/assets/51049963/e7a346c5-2ed6-42ab-8495-83a96b381d24)
대상 유형은 AWS  서비스를 선택하고 대상 선택에서 Lambda 함수를 선택해서 방금 생성한 Lambda 함수를 선택하고 다음으로 이동한다.
![제목 ssss없음](https://github.com/CloudBread-WHS/aws-automated-security-tools/assets/51049963/fe4f820d-17ec-41e2-9537-fd655b2834c3)
필요에 따라 태그를 설정 해 줄 수 있지만 여기선 생략한다.
다음으로 이동하고 규칙 생성을 눌러준다.
그러면 내가 자동화 하고싶은 guardduty 결과가 발생할 때 lambda 함수가 동작하여 자동으로 차단을 진행한다.

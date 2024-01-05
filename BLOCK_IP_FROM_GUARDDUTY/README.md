이벤트 브릿지에서 Guardduty 결과를 탐지하면 Lambda 코드에서 공격자 ip를 자동으로 NACL에 차단 정책을 추가하는 코드입니다.

## Lambda 함수 작동 과정
1. NACL과 DB정보 가져오기
2. NACL에 있고 DB에 없다면 DB 추가, NACL에 없고 DB에 있다면 DB제거 (관리가 편해짐)
3. NACL 정책이 20개라면 DB에서 가장 오래된 정책을 찾아서 제거
4. 클라우드 와치에서 공격자ip 추출 (위험도 높음을 대상으로으로)
5. 낮은 번호부터 빈자리 찾아서 nacl에 공격자 ip 차단 정책 추가
6. 공격자 ip와 적용 시간을 DB에 저장

# 환경설정
## Lambda 함수 설정
AWS Lambda - 함수 - 함수 생성
![image](https://github.com/CloudBread-WHS/aws-automated-security-tools/assets/51049963/40964aac-d5fb-4165-b26f-7b35c7e62bea)

함수 이름을 작성하고 런타임은 코드가 3.11버전으로 제작하였기 때문에 Python3.11로  선택한다.
![제목 ssss없음](https://github.com/CloudBread-WHS/aws-automated-security-tools/assets/51049963/f2670e0a-54e7-4f4a-bd11-669c926cfa25)

함수를 생성하면 먼저 코드 소스에 코드를 입력한다.
이 때 DynamoDB의 테이블 이름과 NACL ID는 사용자의 값으로 입력을 해야한다. DynamoDB는 Lambda 함수 생성 이후에 설정한기 때문에 지금은 이름만 입력한다.
![image](https://github.com/CloudBread-WHS/aws-automated-security-tools/assets/51049963/6c415e3f-1aec-4416-9902-7473bc69e299)

그리고 구성으로 이동한다.
이 함수의 실행시간이 3초로는 부족하고 DynamoDB와 NACL 등 조작할 수 있는 권한을 설정해야 한다.
![image](https://github.com/CloudBread-WHS/aws-automated-security-tools/assets/51049963/e18a9d6e-a944-4d59-a5f9-6b3c0cc31617)

제한시간을 10초로 늘리고 권한을 늘리기 위해 하단에 역할 확인을 누른다
![image](https://github.com/CloudBread-WHS/aws-automated-security-tools/assets/51049963/9868baa5-1e4f-4a5b-b627-9cb44f2dc9a9)

그리고 다음과 같이 권한 추가를 누르고 4개의 권한을 추가해준다. 그리고 구성으로 돌아와 저장을 누른다.
![image](https://github.com/CloudBread-WHS/aws-automated-security-tools/assets/51049963/e46a2760-c320-45e1-8470-0b8e76221ee5)

이제 람다 함수에 사용되는 패키지를 설정해야 한다. 람다 환경에서는 패키지를 직접 Layers에 추가해야 한다. 
![image](https://github.com/CloudBread-WHS/aws-automated-security-tools/assets/51049963/8dfc099a-dc75-409d-853c-42749d99e30c)

패키지 파일을 업로드하고 호환 런타임에는 Python 3.11을 선택 후 생성한다. boto3와 datetime 2가지를 모두 진행한다.
![제목 ssss없음](https://github.com/CloudBread-WHS/aws-automated-security-tools/assets/51049963/689f2cee-4170-4e06-877c-268e62b0fe0d)

다시 Labmda 함수로 돌아와서 Layers를 누르고 계층 추가한다.
![image](https://github.com/CloudBread-WHS/aws-automated-security-tools/assets/51049963/f6bc5e7e-a849-4b07-aea5-87c4ca4d9403)

![image](https://github.com/CloudBread-WHS/aws-automated-security-tools/assets/51049963/abe18587-3092-4417-8ebb-6ada73bc2181)

사용자 지정 계층을 선책하고 아까 추가한 boto3와 datetime 패키지를 추가한다.
![제목 ssss없음](https://github.com/CloudBread-WHS/aws-automated-security-tools/assets/51049963/00ef6d6e-3f9b-40db-aade-99b206b36edb)

Lambda 함수는 이렇게 준비가 끝났다.

## DynamoDB 설정
오래된 정책 삭제를 위해 정책 내용과 시간이 담긴 DB를 만들어야 한다.
DynamoDB - 대시보드 - 테이블 생성
![image](https://github.com/CloudBread-WHS/aws-automated-security-tools/assets/51049963/b54fbfe4-93af-454a-86bc-373d16db06a2)

테이블 이름에는 Lambda 함수에 입력했던 테이블 이름을 입력하고 파티션 키에는 nacl을 입력한다. 그리고 테이블을 생성하면 DynamoDB의 설정은 끝이다.
![제목 ssss없음](https://github.com/CloudBread-WHS/aws-automated-security-tools/assets/51049963/978d3068-c0d7-4830-9f90-942008b629f3)

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

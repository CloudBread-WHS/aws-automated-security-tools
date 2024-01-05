EXPIRES_IAM_SESSION_GUARDUTYD.py
- 해당 코드는 GuardDuty 기반 보안이벤트를 통해 임시 자격 증명을 탈취하여 악용하는 이벤트 감지시 해당 IAM 권한 박탈시키는 행동을 수행하는 람다 함수입니다.

## 발생 시나리오 및 대응
<img width="30%" src="https://github.com/CloudBread-WHS/aws-automated-security-tools/assets/125464850/f1d698e1-bff7-4649-ac74-a5e343c43a7c"/>

1. 악의적인 사용자가 웹 취약점을 이용하여 iam 자격 증명을 탈취함.
2. GuardDuty를 이용하여 IMDS 이상호출 이벤트 감지.
3. 해당 이벤트를 EventBridge를 통해 람다함수로 전달.
4. Boto3 모듈 iam_client.put_user_policy를 사용하여 모든 행동과 자원에 대해 deny 룰을 부여하는 람다 함수가 호출됨.

## 람다 함수 구성 과정
- 람다 함수는 특정 이벤트에 대한 트리거로 설정
- 해당 이벤트에서 UserName추출
- put_user_policy로 추출한 UserName에 해당하는 IAM권한 'deny'

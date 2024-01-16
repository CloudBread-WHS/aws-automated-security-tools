🧑🏻‍💻 Start_cloudtrail.py
---
<img width="40%" alt="cloudTrail" src="https://github.com/CloudBread-WHS/aws-automated-security-tools/assets/77061306/47bcabef-a496-48a3-ae13-fc2e0487b33d">


- 해당 코드는 cloudtrail 로깅이 비활성화되었을 때, 다시 활성화 시키는 행동을 수행하는 람다 함수입니다.

## 발생 시나리오 및 대응
1. 악의적인 사용자가 웹 취약점을 이용하여 iam 자격 증명을 탈취함.
2. 탈취한 자격 증명을 이용하여 Cloudtrail 로깅을 비활성화 시킴.
3. 비활성화 된 Cloudtrail 을 재활성화 시키는 람다 함수가 호출됨.

## 람다 함수 구성 과정
- 클라우드 보안감사 모니터링 관점에서 수행하고 있는 액션아이템.
- 람다 함수는 특정 이벤트에 대한 트리거로 설정되어야 함.
- 람다 함수에서 Cloudtrail 을 트리거로 직접 추가하는 것은 불가능함.
- 따라서, CloudWatch Events 을 사용하여 CloudTrail 이벤트를 받아와야 함.

## 필요성은?
- 해커는 자신의 행동을 추적하지 못하게 기록을 남기지 않는 것을 선호함.
- 따라서, 모든 행위를 기록하는 CloudTrail 로깅을 비활성화 시킬 확률이 높음.
- 이에 대한 대응으로 개발한 도구임.

## AWS 인프라 구성

<img width="70%" src="https://github.com/CloudBread-WHS/aws-automated-security-tools/blob/main/aws_infra.png"/>

---
###위 인프라를 기준으로 여러 aws 서비스를 이용하여 자동으로 탐지, 초기침해대응을 하는 도구를 만드는 프로젝트이다.



🔒 **AWS Automated Security Tools Suite** 🔒

**1. WAF 기반 Inbound NACL 차단 도구**

- *설명:* WAF를 활용하여 Inbound NACL을 차단하여 보안을 강화합니다.
- [BLOCK_IP_FROM_GUARDDUTY](https://github.com/CloudBread-WHS/aws-automated-security-tools/tree/main/BLOCK_IP_FROM_GUARDDUTY)

**2. GuardDuty 기반 Inbound/Outbound NACL 차단 도구**

- *설명:* GuardDuty 결과를 기반으로 Inbound/Outbound NACL을 차단하여 보안을 강화합니다.
- [BLOCK_IP_FROM_WAF](https://github.com/CloudBread-WHS/aws-automated-security-tools/tree/main/BLOCK_IP_FROM_WAF)

**3. GuardDuty 기반 IAM 롤 세션 초기화 도구**

- *설명:* GuardDuty 결과를 활용하여 IAM 롤 세션을 초기화하여 보안을 강화합니다.
- [EXPIRES_IAM_SESSION_GUARDDUTY](https://github.com/CloudBread-WHS/aws-automated-security-tools/tree/main/EXPIRES_IAM_SESSION_GUARDDUTY)

**4. CloudTrail 비활성화시 강제 활성 도구**

- *설명:* CloudTrail이 비활성화되었을 때, 강제로 활성화하여 로깅을 지속적으로 유지합니다.
- [START_CLOUDTRAIL_LOGGING](https://github.com/CloudBread-WHS/aws-automated-security-tools/tree/main/START_CLOUDTRAIL_LOGGING)

**5. Discord를 통한 알림 기능 설정**

- *설명:* 각 도구의 알림을 Discord를 통해 설정할 수 있습니다.
- [SEND_DISCODE_SECURITY_ALAM](https://github.com/CloudBread-WHS/aws-automated-security-tools/tree/main/SEND_DISCORD_SECURITY_ALARM)

  

➕ **추후 추가 기능**

**6. Access Log 기반 WAF 룰 자동 업데이트 도구**

- *설명:* Access Log를 분석하여 WAF 룰을 자동으로 업데이트합니다.

**7. VPC 흐름 로그를 통한 EC2 인스턴스 DoS 감지 및 중지 도구**

- *설명:* VPC 흐름 로그를 분석하여 DoS 공격을 탐지하고, 자동으로 EC2 인스턴스를 중지시킵니다.

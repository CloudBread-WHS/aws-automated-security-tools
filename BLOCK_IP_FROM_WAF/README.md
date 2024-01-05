## Block_IP_from_WAF.py
해당 코드는 WAF의 웹 ACL이 트리거된 로그를 기반으로 특정 임계치를 넘으면 NACL inbound를 이용해 차단하는 람다 코드 입니다.

## 서비스 구조
![Block_IP_from_WAF](https://github.com/CloudBread-WHS/aws-automated-security-tools/assets/70023722/53f14359-7efe-43cd-9f90-063d3f486e2f)

## 필요성
- 저비용으로 공격에 대한 빠른 대처 가능

## 작동 과정
1. WAF에서 룰 트리거되면 Firehose를 통해 묶어서 람다로 전달
2. Firehose 데이터에서 공격자 ip 추줄
3. 공격자 ip 중 5개 이상으로 검출되는 같은 ip만 따로 추출해 차단
4. NACL과 DB정보 가져오기
5. NACL에 있고 DB에 없다면 DB 추가, NACL에 없고 DB에 있다면 DB제거
6. nacl 정책이 20개라면 DB에서 가장 오래된 정책을 찾아서 제거
7. 낮은 번호부터 빈자리 찾아서 nacl에 공격자 ip 차단 정책 추가
8. 공격자 ip와 적용 시간을 DB에 저장







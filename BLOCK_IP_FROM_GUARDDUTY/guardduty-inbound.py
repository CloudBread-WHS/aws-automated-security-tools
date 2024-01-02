import boto3
from datetime import datetime
from decimal import Decimal

def get_next_rule_number(nacl_client, network_acl_id, egress):
    # NACL에서 현재 규칙 수 확인
    nacl_describe = nacl_client.describe_network_acls(NetworkAclIds=[network_acl_id])
    rules_key = 'Entries'
    rules = [entry for entry in nacl_describe.get('NetworkAcls', [{}])[0].get(rules_key, []) if entry.get('Egress') is False]
    current_policy_numbers = [int(entry['RuleNumber']) for entry in rules]
    return max(current_policy_numbers, default=1) + 1

def find_available_rule_number(nacl_client, network_acl_id, egress):
    current_rule_number = 1
    
    while True:
        # 중복된 번호 확인
        nacl_describe = nacl_client.describe_network_acls(NetworkAclIds=[network_acl_id])
        rules_key = 'Entries'
        existing_rule_numbers = [int(entry['RuleNumber']) for entry in nacl_describe['NetworkAcls'][0].get(rules_key, []) if entry.get('Egress') is False]
        
        if current_rule_number not in existing_rule_numbers:
            return current_rule_number
        else:
            current_rule_number += 1
            
def get_attacker_ip(event):
    paths_to_try = [
        ["Service", "Action", "NetworkConnectionAction", "RemoteIpDetails", "IpAddressV4"],
        ["Service", "Action", "KubernetesApiCallAction", "RemoteIpDetails", "IpAddressV4"],
        ["Service", "Action", "AwsApiCallAction", "RemoteIpDetails", "IpAddressV4"],
        ["Service", "Action", "RdsLoginAttemptAction", "RemoteIpDetails", "IpAddressV4"]
    ]

    for path in paths_to_try:
        ip_address = event[0]
        for key in path:
            try:
                ip_address = ip_address[key]
            except (KeyError, TypeError):
                break
        else:
            return ip_address

    # 모든 경로에서 IP 주소를 찾지 못한 경우
    return "Unknown"

def verify_nacl_and_db_consistency(nacl_client, dynamodb_client, network_acl_id, dynamodb_table_name, egress=False):
    # 예외로 처리할 정책 번호 (인바운드 정책에서만 처리)
    skip_rule_numbers = {100, 32767}

    # NACL 정책과 DynamoDB 테이블 간의 일관성 검증
    nacl_describe = nacl_client.describe_network_acls(NetworkAclIds=[network_acl_id])
    rules_key = 'Entries'
    nacl_rules = [entry for entry in nacl_describe.get('NetworkAcls', [{}])[0].get(rules_key, []) if entry.get('Egress') is False and entry.get('RuleNumber') not in skip_rule_numbers]

    # DynamoDB에서 모든 항목 가져오기
    db_table = dynamodb_client.Table(dynamodb_table_name)
    db_items = db_table.scan(
        ProjectionExpression='#nacl',
        ExpressionAttributeNames={'#nacl': 'nacl'}
    ).get('Items', [])

    # NACL 정책과 DB 데이터를 비교하여 불일치 항목 처리
    for db_item in db_items:
        nacl_id = db_item.get('nacl')
        
        # NACL 정책과 DB에 동일한 항목이 없으면 해당 DB 항목 삭제
        if not any(rule.get('RuleNumber') == int(nacl_id) for rule in nacl_rules):
            db_table.delete_item(
                Key={
                    'nacl': nacl_id
                }
            )
            print(f"DB 항목이 NACL 정책에 없어서 삭제: {nacl_id}")

    # DB 데이터를 기반으로 NACL 정책 추가
    for nacl_rule in nacl_rules:
        rule_number = nacl_rule.get('RuleNumber')
        attacker_ip = nacl_rule.get('CidrBlock').split('/')[0]  # NACL 정책의 소스에서 attacker_ip 가져오기

        # DB에 동일한 항목이 없으면 해당 NACL 정책 추가
        if not any(item.get('nacl') == str(rule_number) for item in db_items):
            timestamp = Decimal(str(datetime.utcnow().timestamp()))

            db_table.put_item(
                Item={
                    'nacl': str(rule_number),
                    'nacl_id': network_acl_id,
                    'timestamp': timestamp,
                    'egress': False,  # egress 정보 추가
                    'attacker_ip': attacker_ip  # attacker_ip 정보 추가
                }
            )
            print(f"NACL 정책이 DB에 없어서 추가: {rule_number}")

    return {
        'statusCode': 200,
        'body': '일관성 검증이 완료되었습니다.'
    }

def lambda_handler(event, context):
    try:
        # DynamoDB 테이블 설정
        dynamodb_table_name = 'NACL-INBOUND'
        dynamodb_client = boto3.resource('dynamodb')
        table = dynamodb_client.Table(dynamodb_table_name)

        # NACL 관리
        nacl_client = boto3.client('ec2')
        network_acl_id = 'acl-0d61c2ac40440e166'  # 실제 NACL ID로 교체

        # 공격자 IP 주소 가져오기
        attacker_ip = get_attacker_ip(event)
        if not attacker_ip:
            raise ValueError("이벤트에서 공격자 IP를 추출할 수 없습니다.")

        # 일관성 검증 (인바운드 정책만을 대상으로)
        verify_nacl_and_db_consistency(nacl_client, dynamodb_client, network_acl_id, dynamodb_table_name)

        # NACL에서 현재 규칙 수 확인 (인바운드 정책만을 대상으로)
        nacl_describe = nacl_client.describe_network_acls(NetworkAclIds=[network_acl_id])
        inbound_rules = [entry for entry in nacl_describe.get('NetworkAcls', [{}])[0].get('Entries', []) if entry.get('Egress') is False]
        current_policy_count = len(inbound_rules)

        # 현재 시간의 timestamp를 얻기 (Decimal 타입으로 변환)
        current_timestamp = Decimal(str(datetime.utcnow().timestamp()))

        # 총 정책의 갯수가 20개 이상이거나 정확히 20개일 때 오래된 정책 삭제 (인바운드 정책만을 대상으로)
        if current_policy_count >= 20:
            print(f"현재 정책 수: {current_policy_count}")
            
                        # 정책을 timestamp를 기준으로 정렬하여 가장 오래된 정책을 찾음
            oldest_policies = table.scan(
                TableName=dynamodb_table_name,
                ProjectionExpression='#nacl, #timestamp, #egress, #attacker_ip',
                ExpressionAttributeNames={'#nacl': 'nacl', '#timestamp': 'timestamp', '#egress': 'egress', '#attacker_ip': 'attacker_ip'},
                Limit=20
            )

            if 'Items' in oldest_policies and oldest_policies['Items']:
                # 가장 작은 timestamp를 가진 정책을 찾음
                oldest_policy = min(oldest_policies['Items'], key=lambda x: x['timestamp'])
                
                print(f"가장 오래된 정책 정보: {oldest_policy}")

                oldest_nacl = oldest_policy['nacl']
                oldest_timestamp = oldest_policy['timestamp']
                egress = oldest_policy['egress']
                oldest_attacker_ip = oldest_policy['attacker_ip']
                
                # NACL에서 가장 오래된 정책 삭제
                nacl_client.delete_network_acl_entry(
                    NetworkAclId=network_acl_id,
                    RuleNumber=int(oldest_nacl.split('_')[0]),  # Extract rule number from nacl field
                    Egress=egress
                )

                # DynamoDB에서 가장 오래된 정책 삭제
                table.delete_item(
                    Key={
                        'nacl': oldest_nacl
                    }
                )

                print(f"NACL 정책이 가득차 {oldest_nacl}번 정책을 삭제했습니다.")
            else:
                print("삭제할 항목이 없습니다.")

        # 가용한 정책 번호 할당
        egress = False  # 인바운드 규칙으로 설정
        new_rule_number = find_available_rule_number(nacl_client, network_acl_id, egress)

        # NACL에 새로운 정책 추가하여 공격자 IP 차단
        nacl_client.create_network_acl_entry(
            NetworkAclId=network_acl_id,
            RuleNumber=new_rule_number,
            Protocol='-1',
            RuleAction='DENY',
            Egress=egress,
            CidrBlock=f"{attacker_ip}/32"
        )

        print(f"{attacker_ip}이 {new_rule_number}번 정책으로 차단되었습니다.")

        # DynamoDB에 새 NACL 정책 정보 저장 (Decimal 타입으로 저장)
        new_nacl_id = network_acl_id  # Store the currently used NACL ID
        response = table.put_item(
            Item={
                'nacl': str(new_rule_number),
                'nacl_id': new_nacl_id,
                'timestamp': current_timestamp,
                'egress': egress,
                'attacker_ip': attacker_ip
            }
        )
        
        return {
            'statusCode': 200,
            'body': '람다 함수가 성공적으로 실행되었습니다.'
        }
    except Exception as e:
        print("에러:", e)
        return {
            'statusCode': 500,
            'body': f'에러로 인해 람다 함수가 실패하였습니다: {str(e)}'
        }
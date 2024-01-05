import json
import base64
import boto3
import logging
from collections import Counter
from datetime import datetime
from decimal import Decimal

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def get_next_rule_number(nacl_client, network_acl_id, egress):
    # NACL에서 현재 규칙 수 확인
    nacl_describe = nacl_client.describe_network_acls(NetworkAclIds=[network_acl_id])
    rules_key = 'Entries' if egress else 'Entries'
    rules = [entry for entry in nacl_describe.get('NetworkAcls', [{}])[0].get(rules_key, [])]
    current_policy_numbers = [int(entry['RuleNumber']) for entry in rules]
    return max(current_policy_numbers, default=1) + 1

def find_available_rule_number(nacl_client, network_acl_id, egress):
    current_rule_number = 2
    
    while True:
        # 중복된 번호 확인
        nacl_describe = nacl_client.describe_network_acls(NetworkAclIds=[network_acl_id])
        rules_key = 'Entries' if egress else 'Entries'
        existing_rule_numbers = [int(entry['RuleNumber']) for entry in nacl_describe['NetworkAcls'][0].get(rules_key, [])]
        
        if current_rule_number not in existing_rule_numbers:
            return current_rule_number
        else:
            current_rule_number += 1

def get_attacker_ip(payload):
    # WAF 이벤트에서 공격자 IP 주소를 추출
    
    try:
        waf_data = json.loads(payload)
        # 공격자의 IP 주소 추출 (WAF 로그 구조에 따라 변경 가능)
    except Exception as e:
        logger.error(f"예외 발생 waf_data: {waf_data}")
    http_request_data = waf_data.get('httpRequest', {})
    attacker_ip_data = http_request_data.get('clientIp', '')

    return attacker_ip_data 
    
def extract_values(arr):
    # Counter 객체를 사용하여 각 요소의 등장 횟수를 계산
    value_counts = Counter(arr)

    # 5회 이상 등장하는 요소들만 필터링
    values = [value for value, count in value_counts.items() if count >= 5]

    return values


def verify_nacl_and_db_consistency(nacl_client, dynamodb_client, network_acl_id, dynamodb_table_name, egress=False):
    # 예외로 처리할 정책 번호
    skip_rule_numbers = {100, 32767}

    # NACL 정책과 DynamoDB 테이블 간의 일관성 검증
    nacl_describe = nacl_client.describe_network_acls(NetworkAclIds=[network_acl_id])
    rules_key = 'Entries'
    nacl_rules = [entry for entry in nacl_describe.get('NetworkAcls', [{}])[0].get(rules_key, []) if entry.get('RuleNumber') not in skip_rule_numbers]

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
            logger.info(f"")

    

def lambda_handler(event, context):
    # try:
        # DynamoDB 테이블 설정
        dynamodb_table_name = 'NACL-INBOUND'
        dynamodb_client = boto3.resource('dynamodb')
        table = dynamodb_client.Table(dynamodb_table_name)

        # NACL 관리
        nacl_client = boto3.client('ec2')
        network_acl_id = 'acl-0d61c2ac40440e166'  # 실제 NACL ID로 교체
    
    # except Exception as e:
    #     logger.error(f"예외 발생 DynamoDB, NACL: {str(e)}")
    #     output_records = [{'recordId': record['recordId'], 'result': 'ProcessingFailed', 'data': record['data']} for record in event['records']]  # 수정된 부분
    #     return {'records': output_records}
        
    try_ips=[]
    # 공격자 IP 주소 가져오기
    
    for record in event['records']:
        # Firehose에서 전달받은 데이터를 처리
        # Kinesis Data Firehose의 데이터는 base64 인코딩되어 있으므로 디코딩 필요
        payload = base64.b64decode(record['data']).decode('utf-8')
        try_ips.append(get_attacker_ip(payload))
    
    logger.info(try_ips)
    
    if not try_ips:  # 수정된 부분
        raise ValueError(try_ips+"수집 불가능")
        
    # try:
        #ip 수가 5 이상인 ip만 추출
    attacker_ips = (extract_values(try_ips))
    logger.info(attacker_ips)
    # except Exception as e:
    #     logger.error(f"예외 발생 ip 추출: {str(e)}")
    #     output_records = [{'recordId': record['recordId'], 'result': 'ProcessingFailed', 'data': record['data']} for record in event['records']]  # 수정된 부분
    #     return {'records': output_records}
    
    # try:
    for attacker_ip in attacker_ips:
        # 일관성 검증
        verify_nacl_and_db_consistency(nacl_client, dynamodb_client, network_acl_id, dynamodb_table_name)

        # NACL에서 현재 규칙 수 확인
        nacl_describe = nacl_client.describe_network_acls(NetworkAclIds=[network_acl_id])
        inbound_rules = [entry for entry in nacl_describe.get('NetworkAcls', [{}])[0].get('Entries', []) if entry.get('Egress') is False]
        current_policy_count = len(inbound_rules)

        # 현재 시간의 timestamp를 얻기 (Decimal 타입으로 변환)
        current_timestamp = Decimal(str(datetime.utcnow().timestamp()))
                # 총 정책의 갯수가 20개 이상일 때 오래된 정책 삭제
        if current_policy_count >= 20:
            # 정책을 timestamp를 기준으로 정렬하여 가장 오래된 정책을 찾음
            oldest_policies = table.scan(
                TableName=dynamodb_table_name,
                ProjectionExpression='#nacl, #timestamp, #egress, #attacker_ip',
                ExpressionAttributeNames={'#nacl': 'nacl', '#timestamp': 'timestamp', '#egress': 'egress', '#attacker_ip': 'attacker_ip'},
                FilterExpression=Attr('timestamp').gte(2),
                Limit=20
            )
            if 'Items' in oldest_policies and oldest_policies['Items']:
                # 가장 작은 timestamp를 가진 정책을 찾음
                oldest_policy = min(oldest_policies['Items'], key=lambda x: x['timestamp'])
                
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
                
                
            logger.info(f"NACL 정책이 가득차 {oldest_nacl}번 정책을 삭제했습니다.")

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
        
        logger.info(f"{attacker_ip}이 {new_rule_number}번 정책으로 차단되었습니다.")
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
  
    # except Exception as e:
    #     logger.error(f"예외 발생 추가: {str(e)}")
    #     output_records = [{'recordId': record['recordId'], 'result': 'ProcessingFailed', 'data': record['data']} for record in event['records']]  # 수정된 부분
    #     return {'records': output_records}
    output_records = []
    # try:
    for record in event['records']:
        payload = base64.b64decode(record['data']).decode('utf-8')
    
        # WAF 로그에서 'httpRequest' 키의 값, 작동된 룰 ID 추출
        waf_log = json.loads(payload)
        http_request_data = waf_log.get('httpRequest', {})
            # 결과 리스트에 각 레코드에 대한 정보 추가
        output_records.append({
            'recordId': record['recordId'],
            'result': 'Ok',
            'data': base64.b64encode(json.dumps(http_request_data).encode('utf-8')).decode('utf-8')
        })
    return {'records': output_records}
function_name = 'Discord-bot_send'
region_name = 'ap-northeast-2'  # 서울 리전 코드
input_data = 'IMDS-IAM'

# AWS Lambda 클라이언트를 생성합니다.
lambda_client = boto3.client('lambda', region_name=region_name)

# Lambda 함수를 호출합니다.
response = lambda_client.invoke(
    FunctionName=function_name,
    InvocationType='RequestResponse',  # 또는 'Event'로 설정하여 비동기적으로 호출할 수 있습니다.
    Payload=json.dumps({"content" : "Block_IP_from_WAF 함수 동작 "}),
    LogType='Tail'  # Lambda 로그를 확인하려면 'Tail'을 선택합니다.
)

# 호출 결과를 출력합니다.
print(response['Payload'].read().decode())

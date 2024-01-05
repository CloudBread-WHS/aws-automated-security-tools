import boto3
import json

def lambda_handler(event, context):
    # IAM 사용자 이름
    iam_user = event['detail']['Resource']['AccessKeyDetails']['UserName']
    
    # IAM 사용자의 세션 강제 만료
    iam_client = boto3.client('iam')

    try:
        response = iam_client.put_user_policy(
            UserName=iam_user,
            PolicyName='imds_policy',
            PolicyDocument= '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource": "*"}]}'
        )
        
        return {
            'statusCode': 200,
            'body': json.dumps('Access to temporary credentials denied successfully!')
        }

    except Exception as e:
        return {
            'statusCode': 500,
            'body': json.dumps(f'Error: {str(e)}')
        }
function_name = 'Discord-bot_send'
region_name = 'ap-northeast-2'  # 서울 리전 코드
input_data = 'IMDS-IAM'

# AWS Lambda 클라이언트를 생성합니다.
lambda_client = boto3.client('lambda', region_name=region_name)

# Lambda 함수를 호출합니다.
response = lambda_client.invoke(
    FunctionName=function_name,
    InvocationType='RequestResponse',  # 또는 'Event'로 설정하여 비동기적으로 호출할 수 있습니다.
    Payload=json.dumps({"content" : "EXPIRES_IAM_SESSION_GURDDUTY 함수 동작 "}),
    LogType='Tail'  # Lambda 로그를 확인하려면 'Tail'을 선택합니다.
)

# 호출 결과를 출력합니다.
print(response['Payload'].read().decode())

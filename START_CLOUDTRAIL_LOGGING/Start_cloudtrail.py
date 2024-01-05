import json
import boto3

def lambda_handler(event, context):
    print("Received event:", json.dumps(event, indent=2))
    if 'source' in event and event['source'] == 'aws.cloudtrail': #이벤트의 source 에서 aws.cloudtrail 을 가져옴.
        event_name = event['detail']['eventName'] #이벤트의 eventName 을 event_name 변수에 넣음.
        
        if event_name == 'StopLogging': #이때, 발생한 이벤드의 eventName 이 StopLogging 이면
            print("CloudTrail logging is stopped!") #CloudTrail loggin is stopped! 출력.
            enable_cloudtrail_logging() #Cloud trail 을 실행시키는 함수 호출.
            return {
                'statusCode': 200,
                'body': 'CloudTrail logging is stopped and re-enabled!',
                'headers': {'Content-Type': 'application/json'}
            }
    
    print("Unsupported event type or error occurred.") #이벤트 타입이 올바르게 되어 있지 않으면 출력함.
    return {
        'statusCode': 400,
        'body': 'Unsupported event type or error occurred.',
        'headers': {'Content-Type': 'application/json'}
    }

def enable_cloudtrail_logging():
    cloudtrail_client = boto3.client('cloudtrail')
    response = cloudtrail_client.start_logging(
        Name='서비스에서 로깅을 수행하고 있는 Cloudtrail arn 입력'
    )

    print("CloudTrail logging is re-enabled.")
    
function_name = 'Discord-bot_send'
region_name = 'ap-northeast-2'  # 서울 리전 코드

# AWS Lambda 클라이언트를 생성합니다.
lambda_client = boto3.client('lambda', region_name=region_name)

# Lambda 함수를 호출합니다.
response = lambda_client.invoke(
    FunctionName=function_name,
    InvocationType='RequestResponse',  # 또는 'Event'로 설정하여 비동기적으로 호출할 수 있습니다.
    LogType='Tail'  # Lambda 로그를 확인하려면 'Tail'을 선택합니다.
)

# 호출 결과를 출력합니다.
print(response['Payload'].read().decode())

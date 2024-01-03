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

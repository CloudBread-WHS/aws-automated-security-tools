import json
import requests  # requests를 사용하기 위해 botocore의 vendored 패키지 사용
#from botocore.vendored import requests

def lambda_handler(event, context):
    # 웹훅 URL
    discord_webhook_url = "여기에 디스코드 웹후크를 넣으시면 됩니다."

    # HTTP 요청 헤더
    headers = {
        'Content-Type': 'application/json',
    }

    # 요청에 포함될 데이터
    data = {'content': '보안위협이 감지되었습니다.'}

    # Discord 웹훅으로 HTTP POST 요청 보내기
    response = requests.post(discord_webhook_url, headers=headers, json=data)

    # 디버깅을 위해 응답 상태 코드와 내용 출력
    print(f"응답 상태 코드: {response.status_code}")
    print(f"응답 내용: {response.text}")

    # 응답 반환
    return {
        'statusCode': response.status_code,
        'body': json.dumps('Discord로 메시지 전송 완료!')
    }

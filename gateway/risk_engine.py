import requests
RISK_ENGINE_URL = "http://127.0.0.1:8001/api/risk-engine/analyze/"
def send_to_risk_engine(payload):
    try: 
        response = requests.post(
            RISK_ENGINE_URL,
            json=payload,
            headers={
                "Content-Type": "application/json",
                "ngrok-skip-browser-warning": "1"
            },
            timeout=30,
        )
        print("Risk Engine Status:", response.status_code)
        print("Risk Engine Response:", response.text)
        return response
    except Exception as e:
        print("Error sending to Risk Engine:", e)
        return None
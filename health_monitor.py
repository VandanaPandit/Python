import requests
import time
from datetime import datetime

def check_service(url, name):
    try:
        response = requests.get(url, timeout=5)
        status = "UP" if response.status_code == 200 else f"Down{response.status_code}"
        response_time = response.elapsed.total_seconds()
        return{
            'name': name,
            'status': status,
            'response_time': response_time,
            'timestamp' : datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }

    except requests.exceptions.RequestException as e:
        return{
            'name': name,
            'status': f"Down{str(e)}",
            'response_time': response_time,
            'timestamp' : datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }

def monitor_service():
    services = [
        {'name': 'Google', 'url': 'https://www.google.com'},
        {'name': 'GitHub', 'url': 'https://www.github.com'}
        ]
    
    print("Starting healthcheck monitoring")

    while True:
        print(f"\n{'='*60}")
        print(f"Health check at {datetime.now().strftime('%Y-%M-%D %H:%M:%S')}")
        print(f"\n{'='*60}")

        for service in services:
            result = check_service(service['url'], service['name'])
            print(f"{result['name']:15} | {result["status"]:20} | Response:{result['response_time']:.2f}s")
        time.sleep(30)

if __name__ == "__main__":
    monitor_service()


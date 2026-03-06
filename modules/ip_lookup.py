import requests

def lookup_ip(ip):
    if not ip:
        return {"error": "No IP found"}
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}")
        return response.json()
    except Exception as e:
        return {"error": str(e)}

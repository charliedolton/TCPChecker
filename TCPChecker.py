import psutil
import requests
import time
import argparse

parser = argparse.ArgumentParser(prog='TCPChecker',
                                 usage = 'TCPChecker.py -api <api key> (-enterprise)',
                                 description = "This program checks all TCP connections on your computer and checks the" +
                                 "remote IP addresses against the VirusTotal database. It will then print anything that is " +
                                 "suspicious or malicious. If you have the enterprise version of the API, please use the -enterprise flag. " +
                                 "Please allow at least 30 mins to run if using the free VirusTotal API.")

parser.add_argument('-api', required=True, help='api key')
parser.add_argument('-enterprise', action=argparse.BooleanOptionalAction, default=False, help='Use this flag if you have the enterprise version of VirusTotal')

args = parser.parse_args()

malDetected = False

def getIPs():
    IPs = []
    connections = psutil.net_connections(kind='tcp')
    
    for conn in connections:
        if conn.status == 'ESTABLISHED' and conn.raddr.ip != '127.0.0.1':
            IPs.append(conn.raddr.ip)
    return IPs
    
def checkIP(ip):
    url = "https://www.virustotal.com/api/v3/ip_addresses/" + ip
    headers = {"accept": "application/json", "x-apikey": args.api}
    response = requests.get(url, headers=headers)
    result = response.json()
    
    if (result['data']['attributes']['last_analysis_stats']['malicious'] > 0 or result['data']['attributes']['last_analysis_stats']['suspicious'] > 0):
        malDetected = True
        print("IP: " + ip + 
        "\nresults: " + (result.last_analysis_stats) +
        "\nCountry: " + (result.country) + 
        "\nJARM Hash: " + result.jarm)
        
def main():
    IPs = getIPs()
    
    for IP in IPs:
        checkIP(IP)
        if (args.enterprise == False):
            time.sleep(15)

    if (malDetected == False):
        print("No suspicious connections detected!")
    
main()
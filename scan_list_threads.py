import argparse
import csv
import requests
import urllib3
import ssl, socket
socket.setdefaulttimeout(3)
from urllib.parse import urljoin
from lib import decrypt_beacon, decode_config, JsonEncoder
import OpenSSL.crypto as crypto
from queue import Queue
import threading

lock = threading.Lock()


def get_subject(hostname):
    try:
        dst = (hostname, 443)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(dst)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        s = ctx.wrap_socket(s, server_hostname=dst[0])
        cert_bin = s.getpeercert(True)
        x509 = crypto.load_certificate(crypto.FILETYPE_ASN1, cert_bin)
        val = x509.get_subject().CN
    except Exception as e:
        val = str(e)
    return val


def scan(host):
    print("Checking {}".format(host))
    https_domain = get_subject(host)
    # if host.strip() == "":
    #     continue
    host_ori = host
    if not host.startswith("http"):
        host = "https://{}".format(host)
    try:
        r = requests.get(urljoin(host, "/aaa9"), headers={'user-agent': ua}, verify=False, timeout=3)
        if r.status_code == 200:
            data = r.content
            if data.startswith(b"\xfc\xe8"):
                beacon = decrypt_beacon(data)
                if beacon:
                    config = decode_config(beacon)
                    if config:
                        lock.acquire()
                        csvout.writerow([
                            host_ori,
                            "Found",
                            config["ssl"],
                            config["port"],
                            config[".http-get.uri"].split(',')[0],
                            https_domain,
                            config[".http-get.uri"].split(',')[1],
                            config[".http-post.uri"],
                            config[".user-agent"],
                            config[".watermark"]
                        ])
                        lock.release()
                        print("Payload found")
                    else:
                        lock.acquire()
                        csvout.writerow([host, "Config Extraction Failed", "", "", "", "", "", ""])
                        lock.release()
                        print("Config extraction failed")
                else:
                    lock.acquire()
                    csvout.writerow([host, "Beacon Extraction Failed", "", "", "", "", "", ""])
                    lock.release()
                    print("Beacon extraction failed")
            elif data.startswith(b"MZ"):
                beacon = decrypt_beacon(data)
                config = decode_config(beacon)
                if config:
                    lock.acquire()
                    csvout.writerow([
                        host,
                        "Found",
                        config["ssl"],
                        config["port"],
                        config[".http-get.uri"].split(',')[0],
                        https_domain,
                        config[".http-get.uri"].split(',')[1],
                        config[".http-post.uri"],
                        config[".user-agent"],
                        config[".watermark"]
                    ])
                    lock.release()
                    print("Payload found")
                else:
                    lock.acquire()
                    csvout.writerow([host, "Config Extraction Failed", "", "", "", "", "", ""])
                    lock.release()
                    print("Config extraction failed")
            else:
                # csvout.writerow([host, "Not Found", "", "", "", "", "", ""])
                print("No x86 payload")
        else:
            # csvout.writerow([host, "Not Found", "", "", "", "", "", ""])
            print("No x86 payload")
    # except (requests.exceptions.ChunkedEncodingError, requests.exceptions.ConnectionError, requests.exceptions.ReadTimeout, requests.exceptions.TooManyRedirects, requests.exceptions.ContentDecodingError):
    except Exception as e:
        # csvout.writerow([host, "Failed", "", "", "", "", "", ""])
        print(str(e))
        print("Request failed")


def worker():
    while not q.empty():
        host = q.get()
        scan(host)
        q.task_done()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Extract Cobalt Strike beacon and configuration from a list of server')
    parser.add_argument('HOSTLIST', help='List of IP addresses or domains from a fril')
    args = parser.parse_args()

    ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.77 Safari/537.36"
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    with open(args.HOSTLIST) as f:
        hosts = f.read().split('\n')
    fout = open("output2.csv", "w")
    csvout = csv.writer(fout, delimiter=',', quotechar='"')
    csvout.writerow(["Host", "Status", "SSL", "Port", "C2 Server", "Https Cert", "GET uri",  "POST uri", "User Agent", "Watermark"])

    q = Queue()
    print(hosts)
    for host in hosts:
        q.put(host)



    for i in range(10):
        t = threading.Thread(target=worker)
        t.daemon = True
        t.start()
    q.join()

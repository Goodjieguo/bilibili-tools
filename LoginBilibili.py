import time
from PIL import Image
from bilibili_api import login_func

"""
# 环境安装
pip install pillow
pip install bilibili-api-python
"""

def login():
    qrcode_result = login_func.get_qrcode()
    token = qrcode_result[1]
    im = Image.open(qrcode_result[0])
    im.show()
    while True:
        login_result = login_func.check_qrcode_events(token)
        time.sleep(1)
        if len(login_result) > 2:
            im.close()
            break
    return login_result

if __name__ == "__main__":
    cookies = login()
    print(cookies)
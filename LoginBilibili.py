import asyncio
import time
import uuid
import json
import enum
import requests
from PIL import Image, ImageFont, ImageDraw
from bilibili_api import video, login_func
from bilibili_api.utils.Credential import Credential
from bilibili_api.utils.utils import get_api
from bilibili_api.exceptions import LoginError

API = get_api("login")
"""
# 环境安装
pip install pillow
pip install bilibili-api-python
"""

class QrCodeLoginEvents(enum.Enum):
    """
    二维码登录状态枚举

    + SCAN: 未扫描二维码
    + CONF: 未确认登录
    + DONE: 成功
"""
    SCAN = "scan"
    CONF = "confirm"
    DONE = "done"


def check_qrcode_events(login_key):
    """
    检查登录状态。（建议频率 1s，这个 API 也有风控！）

    Args:
        login_key(string): 登录密钥（get_qrcode 的返回值第二项)

    Returns:
        list[QrCodeLoginEvents, str|Credential]: 状态(第一项）和信息（第二项）（如果成功登录信息为凭据类）
    """
    events_api = API["qrcode"]["get_events"]
    data = {"oauthKey": login_key}
    events = json.loads(
        requests.post(
            events_api["url"],
            data=data,
            cookies={"buvid3": str(uuid.uuid1()), "Domain": ".bilibili.com"},
        ).text
    )
    if "code" in events.keys() and events["code"] == -412:
        raise LoginError(events["message"])
    if events["data"] == -4:
        return [QrCodeLoginEvents.SCAN, events["message"]]
    elif events["data"] == -5:
        return [QrCodeLoginEvents.CONF, events["message"]]
    elif isinstance(events["data"], dict):
        url = events["data"]["url"]
        cookies_list = url.split("?")[1].split("&")
        sessdata = ""
        bili_jct = ""
        dede = ""
        for cookie in cookies_list:
            if cookie[:8] == "SESSDATA":
                sessdata = cookie[9:]
            if cookie[:8] == "bili_jct":
                bili_jct = cookie[9:]
            if cookie[:11].upper() == "DEDEUSERID=":
                dede = cookie[11:]
            if cookie[:17] == "DedeUserID__ckMd5":
                ckmd5 = cookie[18:]
            if cookie[:7] == "Expires":
                sid = cookie[8:]
        cookie = f"DedeUserID={dede};DedeUserID__ckMd5={ckmd5};SESSDATA={sessdata};bili_jct={bili_jct};sid={sid};\n"
        credential = Credential(sessdata, bili_jct, dedeuserid=dede)
        return cookie, credential

def login():
    qrcode_result = login_func.get_qrcode()
    token = qrcode_result[1]
    im = Image.open(qrcode_result[0])
    draw = ImageDraw.Draw(im) #修改图片
    font = ImageFont.truetype('FZCCHJW.ttf', 25)
    draw.text((0,0), 'Bilibili客户端扫描二维码登录', 0, font=font)
    im.show()
    while True:
        cookie, credential = check_qrcode_events(token)  # 改写的login_func.check_qrcode_events
        time.sleep(1.5)
        if isinstance(cookie, str):
            im.close()
            break
    return cookie, credential


if __name__ == "__main__":
    cookies, credential = login()
    print(cookies)
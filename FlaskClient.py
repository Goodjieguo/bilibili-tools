import json
import requests

# 更新配置文件
dic = {"aid_list": ["386644197"],  # aid列表
    "watch_enable": True,  # 观看开关
    "like_enable": False,  # 点赞开关
    "reward_enable": False,  # 投币开关
    "reward2_enable": False,  # 投币双倍开关
    "favour_enable": False,  # 收藏开关
    "combo_enable": False,  # 一键三连开关
    "share_enable": False,  # 分享开关
    "danmaku_post_enable": False,  # 弹幕开关
    "danmaku_content": '哔哩哔哩 (゜-゜)つロ 干杯~", "哔哩哔哩 (゜-゜)つロ 干杯~", "哔哩哔哩 (゜-゜)つロ 干杯~',
    "account": "DedeUserID=125972057;DedeUserID__ckMd5=1b69b079234cf232;SESSDATA=679f430d%2C1675933533%2C65823%2A81;bili_jct=f85e615f38c91d26f50cc4a39f115d9b;sid=15551000;\n",
    }

url = 'http://127.0.0.1:9000'
url = 'http://192.168.31.68:9000'
headers = {'content-type': 'application/json'}
h = requests.post(url=url, json=json.dumps(dic, ensure_ascii=False), headers=headers)
return_dic = json.loads(h.text)
print(return_dic)
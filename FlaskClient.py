import json
import requests

def pull_bv_list(user_dic):
    url = 'http://1.14.23.34:9000'
    headers = {'content-type': 'application/json'}
    h = requests.post(url=url, json=json.dumps(user_dic, ensure_ascii=False), headers=headers)
    print(h)
    return_dic = json.loads(h.text)
    return return_dic

def push_bv_list(user_dic):
    url = 'http://1.14.23.34:9000/commit'
    headers = {'content-type': 'application/json'}
    h = requests.post(url=url, json=json.dumps(user_dic, ensure_ascii=False), headers=headers)
    return_dic = json.loads(h.text)
    return return_dic

if __name__ == '__main__':
    """
    switch说明
    1   观看
    0   点赞
    0   投币
    0   投币双倍
    0   收藏
    0   一键三连
    0   分享
    0   弹幕
    """
    user_dic = {"uid": 700140998,
                "online": 1,
                "cookie": "DedeUserID=125972057;DedeUserID__ckMd5=1b69b079234cf232;SESSDATA=679f430d%2C1675933533%2C65823%2A81;bili_jct=f85e615f38c91d26f50cc4a39f115d9b;sid=15551000;\n",
                "bvlist": "BV1CW4y1h7U2;BV1n14y1b7yw;",
                "switch": 10000000,
                }
    res1 = pull_bv_list(user_dic)  # 下载
    res2 = push_bv_list(user_dic)  # 上传
    print(res1)
    print(res2)

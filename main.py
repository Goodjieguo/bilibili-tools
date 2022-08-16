from multiprocessing import freeze_support
import re
import time
import json
import random
import bilibili
import requests
import autoOpenUrl
import LoginBilibili
import PySimpleGUI as sg
from PIL import Image, ImageFont, ImageDraw


class BilibiliGUI():
    def __init__(self) -> None:
        # Define the window's contents
        self.layouttop = [[sg.Submit('启动互助', key="-Ok-"), sg.Button('退出互助', key="Quit"), sg.Text("启动互助后程序会自动隐藏在后台运行.", size=(25), key='-OUTPUT-'), ]
                        ]
        self.layoutr = [[sg.Text("请输入BV号,一行一个(最大支持20)")],
                        [sg.Multiline('BV1CW4y1h7U2\nBV1n14y1b7yw', size=(20,18), key='-bvlist-')]
                        ]
        self.layoutl = [[sg.Text("观看"), sg.Checkbox('   ', key='-watch-', default=True), sg.Text("点赞"), sg.Checkbox('', key='-like-', default=True)],
                        [sg.Text("收藏"), sg.Checkbox('   ', key='-favour-', default=True), sg.Text("分享"), sg.Checkbox('', key='-share-', default=True)],
                        [sg.Text("投币"), sg.Checkbox('   ', key='-reward-'), sg.Text("双倍"), sg.Checkbox('', key='-reward2-')],
                        [sg.Text("弹幕"), sg.Checkbox('   ', key='-danmaku_post-'), sg.Text("三连"), sg.Checkbox('', key='-combo-')],
                        [sg.Text("弹幕内容:")],
                        [sg.Multiline('哔哩哔哩 (゜-゜)つロ 干杯~", "哔哩哔哩 (゜-゜)つロ 干杯~", "哔哩哔哩 (゜-゜)つロ 干杯~', size=(20,10), key='-danmaku_content-')]
                        ]
        self.layout = [[sg.Col(self.layouttop)], [sg.Col(self.layoutl), sg.Col(self.layoutr)]]
        pass

    # 获取gui输入的bilibili参数
    def transforGuiInput(self, cookie):
        """
        switch说明
        1   观看
        0   点赞
        0   投币
        0   投币双倍
        0   收藏
        0   分享
        0   一键三连
        0   弹幕
        user_dic = {"uid": 700140998,
                    "online": 1,
                    "cookie": "DedeUserID=125972057;DedeUserID__ckMd5=1b69b079234cf232;SESSDATA=679f430d%2C1675933533%2C65823%2A81;bili_jct=f85e615f38c91d26f50cc4a39f115d9b;sid=15551000;\n",
                    "bvlist": "BV1CW4y1h7U2;BV1n14y1b7yw;",
                    "switch": 10000000,
                    }
        """
        uid = cookie[11:20]
        bvlist = [x for x in self.values['-bvlist-'].split("\n")]
        bvlist = ";".join(bvlist)
        switch = int(f"{int(self.values['-watch-'])}{int(self.values['-like-'])}{int(self.values['-reward-'])}{int(self.values['-reward2-'])}{int(self.values['-favour-'])}{int(self.values['-share-'])}{int(self.values['-combo-'])}{int(self.values['-danmaku_post-'])}")
        res_dic = {"uid": uid, "online": 1, "cookie": cookie, "bvlist": bvlist, "switch": switch}
        return res_dic

    def bvid_to_aid(self, bvid="BV17x411w7KC"):
        # Snippet source: https://www.zhihu.com/question/381784377/answer/1099438784
        table = "fZodR9XQDSUm21yCkr6zBqiveYah8bt4xsWpHnJE7jL5VG3guMTKNPAwcF"
        tr = {}
        for i in range(58):
            tr[table[i]] = i
        s = [11, 10, 3, 8, 4, 6]
        xor = 177451812
        add = 8728348608
        r = 0
        try:
            for i in range(6):
                r += tr[bvid[s[i]]] * 58 ** i
            return (r - add) ^ xor
        except:
            return None

    # 解析服务器传回来的bv号到url和aid
    def parse_server_bv_list(self, online_return_dic, bvlist_name="bvlist"):
        # 将所有bv号提取到一个列表当中
        online_bv_list = []
        for li in online_return_dic[bvlist_name]:
            if li[0] == None:
                continue
            online_bv_list.extend([x for x in li[0].split(";") if x!= ""])  # 删除空bv号并添加到bvlist里面
        # 添加本地提交的BV号
        online_bv_list.extend(self.values['-bvlist-'].split("\n"))
        # 去重复
        online_bv_list = list(set(online_bv_list))
        # 获取aid列表
        aid_list = []
        for bvid in online_bv_list:
            bv_id = re.search(r'(BV.*?).{10}', bvid).group(0)
            aid = self.bvid_to_aid(bv_id)
            aid_list.append(str(aid))
        url_list = [f"https://www.bilibili.com/video/{x}" for x in online_bv_list]
        return url_list, aid_list

    # 拉取服务器上的所有bvid转换为url_list和aid_list
    def get_url_list_aid_list(self, online_return_dic):
        """拉取服务器上的所有bvid转换为url_list和aid_list"""
        all_url_list, all_aid_list = self.parse_server_bv_list(online_return_dic, bvlist_name="bvlist")
        vip_url_list, vip_aid_list = self.parse_server_bv_list(online_return_dic, bvlist_name="vip_bv_list")
        return all_url_list, all_aid_list, vip_url_list, vip_aid_list

    # 刷vip的观看 点赞 收藏 一键三连 分享 弹幕开关
    def visit_vip_aid(self, cookie, vip_aid_list):
        # 更新配置文件
        for vip_aid in vip_aid_list:
            dic = {"aid_list": [vip_aid],  # aid列表
                    "watch_enable": self.values['-watch-'],  # 观看开关
                    "like_enable": self.values['-like-'],  # 点赞开关
                    "reward_enable": self.values['-reward-'],  # 投币开关
                    "reward2_enable": self.values['-reward2-'],  # 投币双倍开关
                    "favour_enable": self.values['-favour-'],  # 收藏开关
                    "combo_enable": self.values['-combo-'],  # 一键三连开关
                    "share_enable": self.values['-share-'],  # 分享开关
                    "danmaku_post_enable": self.values['-danmaku_post-'],  # 弹幕开关
                    "danmaku_content": [self.values['-danmaku_content-']],
                    "account": f"{cookie}\n",
                    }
            bilibili.main(dic)
            time.sleep(3)

    def run(self, vis_chrome=True):
        cookie, credential = LoginBilibili.login()
        # cookie = "DedeUserID=700140998;DedeUserID__ckMd5=4b0ff4550adde510;SESSDATA=e606e066%2C1676111088%2C7f2fe%2A81;bili_jct=0f585b8281c89043d082f7558ffaa44a;sid=15551000;\n"
        # Create the window
        window = sg.Window('其它酱', self.layout)
        while True:
            self.event, self.values = window.Read(timeout=100)
            if self.event == "-Ok-":  # 互助开启
                sg.popup_auto_close(f"程序后台将自动互助\n无法点击程序是正常情况, 挂机即可", title="互助提醒")
                window.hide()
                upload_dic = self.transforGuiInput(cookie)  # 转换输入数据为上传dict
                online_return_dic = pull_bv_list(upload_dic)  # 拉取数据库数据 获取bvlist
                push_bv_list(upload_dic)
                # 打开一张图片说明
                img = Image.new("RGB", size=(1000, 500),color=(255,255,255))
                draw = ImageDraw.Draw(img)
                draw.text((0,0),
                        f"其他酱正在后台运行, 无需关闭电脑即可互助.(此图可关闭)\n会员到期时间:{online_return_dic['duedate']}\n\n售后 更新 升级请加QQ群 936622419\n\n软件前期为了增加大家的互动, 对会员用户默认开启 观看 点赞 收藏 分享 弹幕 \n实时显示互助效果正在开发中, 请关注下一个版本.",
                        (255,0,0),
                        font = ImageFont.truetype('FZCCHJW.ttf', 25))
                img.show()
                all_url_list, all_aid_list, vip_url_list, vip_aid_list = self.get_url_list_aid_list(online_return_dic)
                self.visit_vip_aid(cookie, vip_aid_list)  # 访问会员aid
                autoOpenUrl.main({"url_list": all_url_list, "vis_chrome": vis_chrome})
            if self.event == sg.WINDOW_CLOSED or self.event == 'Quit':
                break
        # Finish up by removing from the screen
        window.close()

def pull_bv_list(user_dic):
    url = 'http://1.14.23.34:9000'
    headers = {'content-type': 'application/json'}
    h = requests.post(url=url, json=json.dumps(user_dic, ensure_ascii=False), headers=headers)
    print(h.status_code)
    return_dic = json.loads(h.text)
    return return_dic

def push_bv_list(user_dic):
    url = 'http://1.14.23.34:9000/commit'
    headers = {'content-type': 'application/json'}
    h = requests.post(url=url, json=json.dumps(user_dic, ensure_ascii=False), headers=headers)
    return_dic = json.loads(h.text)
    return return_dic

if __name__ == "__main__":
    freeze_support()
    gui = BilibiliGUI()
    gui.run()

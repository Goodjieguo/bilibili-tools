
import time
import random
import rpa as r


class AutoOpenUrl:
    """刷网页"""
    def __init__(self, vis_chrome=False) -> None:
        self.r = r
        self.r.init(visual_automation=True, headless_mode=vis_chrome)

    def wait_sec(self, url_list, delay_sec=random.uniform(5, 20)):
        for url in url_list:
            self.r.url(url)
            self.r.wait(delay_in_seconds=delay_sec)

    def close_window(self):
        self.r.close()

def main(dic):
    openurl = AutoOpenUrl(vis_chrome=dic["vis_chrome"])
    openurl.wait_sec(dic["url_list"])
    openurl.close_window()
    time.sleep(random.uniform(60, 300))

if __name__ == "__main__":
    dic = {"url_list": ["https://www.bilibili.com/video/BV13W4y1a7k2"],  # url列表
            "vis_chrome": False,  # 是否后台开关
            }
    while True:
        main(dic)


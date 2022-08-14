from bilibili_api import sync, video


def main(BV='BV13W4y1a7k2'):
    # 主入口
    v = video.Video(BV)
    video_info = sync(v.get_info())
    info = video_info["stat"]
    dic = {}
    dic["播放"] = info["view"]
    dic["点赞"] = info["like"]
    dic["收藏"] = info["favorite"]
    dic["分享"] = info["share"]
    dic["评论"] = info["reply"]
    dic["弹幕"] = info["danmaku"]
    dic["投币"] = info["coin"]
    print(dic)
    return dic

if __name__ == '__main__':
    main()
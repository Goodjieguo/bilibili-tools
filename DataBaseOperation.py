import sqlite3

class SQLiteOperation():
    def __init__(self) -> None:
        self.UserDataBaseName = "UserData.db"
        self.create_sql()
        pass

    #建一个数据库
    def create_sql(self):
        """
        UserData.db为数据库文件名
        create table if not exists为建立一个数据库指令，如果文件存在就打开，不存在就创建一个
        %s对应后面的四个参数
        'user':表名
        'uid':bilibili uid
        'createDate' 创建日期
        'expireDate' 会员过期日期
        'online' 是否在线
        'cookie'
        'bvlist' bv号列表 ; 隔开 最大支持20个
        'switch' 开关列表 用于管理被互助的项目
        sql.close()是关闭数据库,每次对数据库进行操作后，都要记得进行关闭操作

        数据库的格式
        file:UserData.db
        table:user
        uid    createDate    expireDate    online    cookie    bvlist    switch

        uid	            createDate	         expireDate	      online	cookie	 bvlist	   switch
        325972057	2022-08-14 15:37:59	2022-08-14 15:37:59	    0	     str    bv1;bv2    1000000;
        """
        sql = sqlite3.connect(self.UserDataBaseName)
        sql.execute(f"""create table if not exists
                        {'user'}(
                                {'uid'} INT primary key not null,
                                {'createDate'} TIMESTAMP default (datetime('now', 'localtime')),
                                {'expireDate'} TIMESTAMP default (datetime('now', 'localtime', '+3 day')),
                                {'online'} BOOLEAN default 1,
                                {'logintime'} TIMESTAMP default (datetime('now','localtime')),
                                {'cookie'} varchar(256) not null,
                                {'bvlist'} varchar(260),
                                {'switch'} BLOB not null)"""
            )
        sql.close()

    # 主函数入口
    def main(self, user_dic):
        # 如果用户不存在则添加用户
        if self.judge_user_exists(user_dic):
            # 添加新用户
            self.add_user(user_dic)
        if self.update_user_cookie_judge_expired(user_dic):
            print("没过期所有功能正常使用")
            # 上传BV号 修改访问权限
            # 下载BV号
            # use program()
        else:
            # 下载BV号
            return "已过期, 仍可播放量互助."

    # 判断用户是否存在
    def judge_user_exists(self, user_dic):
        sql = sqlite3.connect(self.UserDataBaseName)
        data = sql.execute(f"select uid from user where uid='{user_dic['uid']}'").fetchone()
        sql.close()
        # 不存在则返回False 存在则返回True
        if data == None:
            return False
        elif len(data) == 1:
            return True
        else:
            return False


    # 更新用户cookie 判断会员是否过期
    def update_user_cookie_judge_expired(self, user_dic):
        """更新用户cookie, 判断会员是否到期"""
        sql = sqlite3.connect(self.UserDataBaseName)
        # 更新cookie
        res = sql.execute(f"update user set cookie='{user_dic['cookie']}' where uid='{user_dic['uid']}'")
        # 判断会员是否过期
        data = sql.execute(f"select expireDate from user where uid='{user_dic['uid']}' and (datetime('now','localtime'))<expireDate").fetchall()
        sql.commit()
        sql.close()
        # 查询不到 则过期
        if data == None:
            return False
        # 存在则返回过期时间
        elif len(data) == 1:
            return True
        else:
            return False

    # 数据库增加用户数据
    def add_user(self, user_dic):
        sql = sqlite3.connect(self.UserDataBaseName)
        sql.execute("insert into user(uid,cookie,switch) values(?,?,?)",
                    (user_dic["uid"], user_dic["cookie"], user_dic["switch"]))
        sql.commit()
        sql.close()
        print("添加成功")

    # 查询会员剩余时间
    def add_user(self, user_dic):
        sql = sqlite3.connect(self.UserDataBaseName)
        data = sql.execute(f"select expireDate from user where uid='{user_dic['uid']}' and (datetime('now','localtime'))<expireDate").fetchall()
        sql.commit()
        sql.close()
        print("查询成功")
        return data[0][0]

    # 互助BV号拉取 在线用户
    def get_all_online_bv_and_switch(self):
        sql = sqlite3.connect(self.UserDataBaseName)
        res = sql.execute(f"select bvlist,switch from user where online=1").fetchall()
        sql.close()
        print("拉取所有在线BV号成功")
        return res

    # 互助BV号拉取 所有用户
    def get_all_bv_and_switch(self):
        sql = sqlite3.connect(self.UserDataBaseName)
        res = sql.execute(f"select bvlist,switch from user").fetchall()
        sql.close()
        print("拉取所有BV号成功")
        return res

    # 更新用户登录状态
    def update_online_status(self):
        """校对用户登录状态 超过五分钟就下线"""
        sql = sqlite3.connect(self.UserDataBaseName)
        sql.execute("UPDATE user SET online=0 where logintime<datetime('now','localtime', '-5 minutes')")
        sql.commit()
        sql.close()
        print("校对登录状态成功")

    # 会员过期或者下线将switch置为1000000
    def update_switch_status(self):
        """校对用户访问权限 每10分钟核对一次权限"""
        sql = sqlite3.connect(self.UserDataBaseName)
        sql.execute("UPDATE user SET switch=1000000 where expireDate<datetime('now','localtime') or online=0")
        sql.commit()
        sql.close()
        print("修改过期用户或下线用户权限成功")

    # 查看所有数据
    def showdata(self):
        sql = sqlite3.connect(self.UserDataBaseName)
        res = sql.execute("select * from user").fetchall()
        print(res)
        sql.commit()
        sql.close()


if __name__ == '__main__':
    user_dic = {"uid": 3259720571,
                "online": 1,
                "cookie": "DedeUserID=125972057;DedeUserID__ckMd5=1b69b079234cf232;SESSDATA=679f430d%2C1675933533%2C65823%2A81;bili_jct=f85e615f38c91d26f50cc4a39f115d9b;sid=15551000;\n",
                "bvlist": "BV1321321;BV23132131",
                "switch": 1111111,
                }
    databaseOperation = SQLiteOperation()
    # databaseOperation.add_data(user_dic)
    # res = databaseOperation.judge_user_exists(user_dic)  # 用户是否存在判断
    # res = databaseOperation.update_user_cookie_judge_expired(user_dic)  # 会员是否过期判断
    # res = databaseOperation.get_all_online_bv_and_switch()  # 拉取所有在线用户的BV号
    # res = databaseOperation.get_all_bv_and_switch()  # 拉取所有用户的BV号
    # print(res)
    # databaseOperation.update_online_status()  # 用户登录状态更新
    # databaseOperation.update_switch_status()  # 会员过期下线权限更新
    databaseOperation.showdata()

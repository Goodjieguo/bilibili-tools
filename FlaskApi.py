import json
import DataBaseOperation
from flask import Flask, request

app = Flask(__name__)

# 有参数
@app.route("/", methods=['POST'])
def pull_bvlist():
    """上传cookie 拉取bvlist进行访问"""
    data = request.get_data(as_text=True)
    temp_json = json.loads(data)
    upload_dic = json.loads(temp_json)
    databaseOperation = DataBaseOperation.SQLiteOperation()
    due_dic = databaseOperation.main(upload_dic)
    return due_dic

# 有参数
@app.route("/commit", methods=['POST'])
def push_bvlist():
    """提交bvlist进行互助 修改互助权限"""
    data = request.get_data(as_text=True)
    temp_json = json.loads(data)
    upload_dic = json.loads(temp_json)
    databaseOperation = DataBaseOperation.SQLiteOperation()
    databaseOperation.update_bv_and_switch_status(upload_dic)
    return {"status": "提交bvlist成功."}

if __name__ == '__main__':
    app.run(host='0.0.0.0',port=9000)

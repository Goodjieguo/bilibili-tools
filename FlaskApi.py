from flask import Flask, request
import os
import json
import bilibili

app = Flask(__name__)

# 有参数
@app.route("/", methods=['POST'])
def bilibili():
    data = request.get_data(as_text=True)
    jsonObj = json.loads(data)
    dic = json.loads(jsonObj)
    bilibili.freeze_support()
    bilibili.main(dic)
    log_path = "./bilibili.log"
    with open(log_path, "r") as file:
        result = file.read()
    os.remove(log_path)
    return result


if __name__ == '__main__':
    app.run(host='0.0.0.0',port=9000)

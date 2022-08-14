FROM python:3.6
WORKDIR /bilibilitools

COPY requirements.txt ./
RUN pip install -r requirements.txt -i https://pypi.tuna.tsinghua.edu.cn/simple

COPY . .

CMD ["python", "FlaskApi:app"]
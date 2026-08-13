FROM python:3.12-slim
WORKDIR /app
COPY app.py ./app.py
RUN mkdir -p /app/data /app/static && printf '%s' '<!doctype html><html lang=zh-CN><meta charset=utf-8><title>抖音私信监控</title><body><h1>抖音私信监控服务</h1><p>服务运行中</p></body></html>' > /app/static/index.html
EXPOSE 8080
CMD ["python", "app.py"]

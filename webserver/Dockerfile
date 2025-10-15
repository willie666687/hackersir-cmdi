FROM python:3.12-slim

# 安裝 ping 工具
RUN apt-get update && apt-get install -y iputils-ping && rm -rf /var/lib/apt/lists/*

# Install tini
RUN apt-get update && apt-get install -y tini && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py /app/
COPY templates /app/templates

COPY flag.txt /

EXPOSE 80
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["python", "app.py"]
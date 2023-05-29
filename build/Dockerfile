FROM python:3.7.16-slim-bullseye

LABEL MAINTANER=david

RUN apt update -y && apt install -y git

ARG CACHEBUST=1

RUN mkdir -p /app

RUN git clone https://git.qsjtyw.com/YunWei/telegram_cloudflare_bot.git /app

WORKDIR /app

RUN pip3 install pip --upgrade

RUN pip3 install -r requirements.txt

CMD ["sh", "-c", "./run.py"]

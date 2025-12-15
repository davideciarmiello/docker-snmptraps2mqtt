FROM python:3.12-slim

WORKDIR /app

RUN apt-get update \
 && apt-get install -y --no-install-recommends wget snmp \
 && echo "deb http://deb.debian.org/debian bookworm main contrib non-free" > /etc/apt/sources.list.d/bookworm.list \
 && apt-get update \
 && apt-get install -y --no-install-recommends snmp-mibs-downloader \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/*

COPY requirements.txt requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY mibs_default /usr/share/snmp/mibs/
COPY app/* .

EXPOSE 162/udp

CMD ["python", "snmp2mqtt.py"]

FROM python:3

WORKDIR /

RUN git clone https://github.com/knavesec/CredMaster
WORKDIR /CredMaster
RUN pip3 install -r requirements.txt
RUN chmod +x /CredMaster/credmaster.py

ENTRYPOINT ["./credmaster.py"]

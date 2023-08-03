FROM ubuntu:22.04
RUN apt update -y && apt upgrade -y
RUN apt install libmagic1 git python3-pip -y
RUN pip install --upgrade pip

WORKDIR "/opt"
RUN git clone https://github.com/dobin/avred

WORKDIR "/opt/avred"
RUN pip install -r requirements.txt


ENV PATH="${PATH}:/opt/avred"

CMD ["python3", "avredweb.py" ]

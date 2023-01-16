FROM kalilinux/kali-last-release

RUN apt-get update && apt-get install -y theharvester git pip
RUN git clone https://github.com/MaguetteDIAW/3SIS3/OSint.git

WORKDIR OSint

RUN git clone https://github.com/rbsec/dnscan.git
RUN pip install -r requirements.txt
RUN chmod +x OSint.py

COPY ./*.txt /Sint/
COPY ./*.yaml /OSint/


ENTRYPOINT ["./OSint.py"]

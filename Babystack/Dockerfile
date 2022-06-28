FROM ubuntu:16.04 

RUN useradd -ms /bin/bash pwn
WORKDIR /home/pwn

ADD babystack /home/pwn
ADD flag.txt /home/pwn

RUN chmod 4 /home/pwn/flag.txt
RUN chmod 5 /home/pwn/babystack

RUN apt-get update -y
RUN apt-get install socat -y
RUN mkdir /cores
USER pwn

EXPOSE 2006

ENTRYPOINT ["sh", "-c", "exec socat -s TCP-LISTEN:2006,reuseaddr,fork EXEC:/home/pwn/babystack,stderr"]
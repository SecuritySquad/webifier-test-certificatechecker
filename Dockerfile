FROM debian:latest

#OPENSSL
RUN apt-get update \
 && apt-get -y install openssl ca-certificates

#PYTHON
RUN apt-get -y install python

COPY check.py /tmp/

CMD python /tmp/check.py $ID $URL
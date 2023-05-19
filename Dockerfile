# Starting with Ubuntu 20.04
FROM ubuntu:20.04
ENV DEBIAN_FRONTEND noninteractive

RUN apt-get update -qq && apt-get install -y git python3.9 python3.9-dev python3-pip

# Installing Cipherchecks dependencies
RUN python3.9 -m pip install nassl==4.0.0 && \
  python3.9 -m pip install sslyze==4.1.0 && \
  python3.9 -m pip install crayons==0.4.0

RUN git clone https://github.com/sensepost/cipherchecks

# Setting up the run script
WORKDIR /cipherchecks/
ENTRYPOINT ["python3.8", "cipherchecks/main.py"]

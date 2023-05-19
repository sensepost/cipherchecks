# Starting with Ubuntu 20.04
FROM ubuntu:20.04

# Boilerplate Timezone Things
ENV TZ=Africa/Johannesburg
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone
RUN sed -i 's/htt[p|ps]:\/\/archive.ubuntu.com\/ubuntu\//mirror:\/\/mirrors.ubuntu.com\/mirrors.txt/g' /etc/apt/sources.list
RUN apt update -qq
RUN apt install -y tzdata
RUN apt install -y git

# Installing Python3.8.10
RUN apt install -y python3.8 python3-pip

# Installing Cipherchecks dependencies
RUN python3.8 -m pip install nassl==4.0.1
RUN python3.8 -m pip install sslyze==4.0
RUN python3.8 -m pip install crayons
WORKDIR /opt
RUN git clone https://github.com/sensepost/cipherchecks

# Setting up the run script
RUN mkdir script
WORKDIR /opt/script
RUN echo "#!/bin/bash" > cipherchecks
RUN echo "python3.8 /opt/cipherchecks/cipherchecks/main.py" >> cipherchecks
RUN chmod +x cipherchecks

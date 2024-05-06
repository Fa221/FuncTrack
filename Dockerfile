FROM ubuntu:22.04

RUN apt update &&\
    apt upgrade -y &&\
    apt install -y vim build-essential git libcapstone-dev clang cmake libelf-dev libdwarf-dev pkg-config
    
COPY src/ /src


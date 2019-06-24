FROM ubuntu:18.04

RUN apt-get update

RUN groupadd felics
RUN useradd felics --gid felics --create-home

RUN mkdir /opt/felics

ADD --chown=felics:felics resources/dependencies.tar.gz /home/felics

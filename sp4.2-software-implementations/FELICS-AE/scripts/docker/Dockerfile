FROM ubuntu:18.04

RUN apt-get update

RUN apt-get install --assume-yes                                                   \
    python3                                                                        \
    make libelf-dev                                                                \
    gcc-avr avr-libc gdb-avr openjdk-8-jre openjdk-8-jdk                           \
    libusb-dev                                                                     \
    binutils-arm-none-eabi bossa-cli gcc-arm-none-eabi gdb-multiarch python-serial \
    gcc gdb

RUN groupadd felics
RUN useradd felics --gid felics --create-home

RUN mkdir /opt/felics

ADD --chown=felics:felics .resources/dependencies.tar.gz /home/felics/dependencies
ADD ./install-dependencies.sh /home/felics
RUN /home/felics/install-dependencies.sh /home/felics/dependencies

ADD --chown=felics:felics .resources/FELICS-AE.tar.gz /home/felics/FELICS-AE

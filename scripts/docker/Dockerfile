FROM ubuntu:18.04

RUN groupadd felics
RUN useradd felics --gid felics --groups dialout --create-home

ADD ./install-distro-dependencies.sh /home/felics
RUN /home/felics/install-distro-dependencies.sh

RUN mkdir /opt/felics

ADD .resources/dependencies.tar.gz /home/felics/dependencies
ADD ./install-dependencies.sh /home/felics
RUN /home/felics/install-dependencies.sh /home/felics/dependencies

ADD .resources/FELICS-AE.tar.gz /home/felics/
RUN cp /home/felics/FELICS-AE/scripts/plumbing/config.sh.template /home/felics/FELICS-AE/scripts/plumbing/config.sh
RUN chown -R felics:felics /home/felics/FELICS-AE

ADD allow-cpu-governor /etc/sudoers.d

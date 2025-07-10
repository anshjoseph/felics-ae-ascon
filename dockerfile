FROM ubuntu:18.04

# Set non-interactive mode for apt
ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=UTC

# Create working directory
WORKDIR /opt/felics-ae

# Update package list and install basic dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    git \
    wget \
    curl \
    unzip \
    sudo \
    python3 \
    python3-pip \
    pkg-config \
    autoconf \
    automake \
    libtool \
    cmake \
    && rm -rf /var/lib/apt/lists/*

# Install AVR-specific dependencies
RUN apt-get update && apt-get install -y \
    gcc-avr \
    avr-libc \
    default-jdk \
    default-jre \
    gdb-avr \
    libelf-dev \
    libfftw3-dev \
    && rm -rf /var/lib/apt/lists/*

# Install MSP-specific dependencies
RUN apt-get update && apt-get install -y \
    libusb-dev \
    && rm -rf /var/lib/apt/lists/*

# Install ARM-specific dependencies
RUN apt-get update && apt-get install -y \
    binutils-arm-none-eabi \
    bossa-cli \
    gcc-arm-none-eabi \
    gdb-multiarch \
    python3-serial \
    && rm -rf /var/lib/apt/lists/*

# Install PC-specific dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    gdb \
    linux-tools-common \
    linux-tools-generic \
    && rm -rf /var/lib/apt/lists/*

RUN apt-get update
RUN apt-get install -y freeglut3-dev libglu1-mesa-dev
# Create user and add to dialout group
RUN useradd -m -s /bin/bash felics && \
    usermod -aG dialout felics && \
    usermod -aG sudo felics && \
    echo "felics ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers


RUN apt-get install -y libreadline-dev
# Install simavr (version 1.6)
RUN git clone https://github.com/buserror/simavr.git /tmp/simavr && \
    cd /tmp/simavr && \
    git checkout v1.6 && \
    make && \
    make install && \
    ldconfig && \
    rm -rf /tmp/simavr

# Install MSPDebug (version 0.25)
RUN git clone https://github.com/dlbeer/mspdebug.git /tmp/mspdebug && \
    cd /tmp/mspdebug && \
    git checkout v0.25 && \
    make && \
    make install && \
    rm -rf /tmp/mspdebug

# Download and install MSP430-GCC (version 7.3.2.154)
RUN cd /tmp && \
    wget -O msp430-gcc.tar.bz2 "http://software-dl.ti.com/msp430/msp430_public_sw/mcu/msp430/MSPGCC/9_2_0_0/export/msp430-gcc-9.2.0.50_linux64.tar.bz2" && \
    tar -xjf msp430-gcc.tar.bz2 && \
    mv msp430-gcc-9.2.0.50_linux64 /opt/msp430-gcc && \
    rm msp430-gcc.tar.bz2

# Download and install ARM GNU Embedded Toolchain
RUN cd /tmp && \
    wget -O gcc-arm-none-eabi.tar.bz2 "https://developer.arm.com/-/media/Files/downloads/gnu-rm/10.3-2021.10/gcc-arm-none-eabi-10.3-2021.10-x86_64-linux.tar.bz2" && \
    tar -xjf gcc-arm-none-eabi.tar.bz2 && \
    mv gcc-arm-none-eabi-10.3-2021.10 /opt/gcc-arm-none-eabi && \
    rm gcc-arm-none-eabi.tar.bz2

# Download and install J-Link Software (headless version)

RUN apt-get update && \
    apt-get install -y udev && \
    rm -rf /var/lib/apt/lists/*
RUN cd /tmp && \
    wget --post-data 'accept_license_agreement=accepted' -O JLink_Linux_x86_64.deb \
    "https://www.segger.com/downloads/jlink/JLink_Linux_x86_64.deb" && \
    dpkg -i JLink_Linux_x86_64.deb || apt-get install -f -y && \
    rm JLink_Linux_x86_64.deb

# Download and install nRF Command Line Tools
RUN cd /tmp && \
    wget -O nRF-Command-Line-Tools.tar.gz \
    "https://www.nordicsemi.com/-/media/Software-and-other-downloads/Desktop-software/nRF-command-line-tools/sw/Versions-10-x-x/10-15-4/nrf-command-line-tools-10.15.4_linux-amd64.tar.gz" && \
    tar -xzf nRF-Command-Line-Tools.tar.gz && \
    dpkg -i nrf-command-line-tools_*.deb || apt-get install -f -y && \
    rm -rf nrf-command-line-tools_* nRF-Command-Line-Tools.tar.gz

# Install STLink
RUN wget -O /tmp/stlink_1.8.0-1_amd64.deb https://github.com/stlink-org/stlink/releases/download/v1.8.0/stlink_1.8.0-1_amd64.deb && \
dpkg -i /tmp/stlink_1.8.0-1_amd64.deb || apt-get install -f -y && \
rm /tmp/stlink_1.8.0-1_amd64.deb

# Install python-serial via pip
RUN pip3 install pyserial

# Set up environment variables
ENV PATH="/opt/msp430-gcc/bin:/opt/gcc-arm-none-eabi/bin:${PATH}"

# Clone FELICS-AE repository
RUN git clone https://gitlab.inria.fr/minier/felics-ae.git /opt/felics-ae/src

# Create cpupower sudoers entry
RUN echo "felics ALL = NOPASSWD: \\" > /etc/sudoers.d/allow-cpu-governor && \
    echo "    /usr/bin/cpupower -c [0-9] frequency-set -g powersave,\\" >> /etc/sudoers.d/allow-cpu-governor && \
    echo "    /usr/bin/cpupower -c [0-9] frequency-set -g schedutil,\\" >> /etc/sudoers.d/allow-cpu-governor && \
    echo "    /usr/bin/cpupower -c [0-9] frequency-set -g performance" >> /etc/sudoers.d/allow-cpu-governor

# Copy and set up configuration files
WORKDIR /opt/felics-ae/src

# Create config.sh from template
RUN if [ -f scripts/plumbing/config.sh.template ]; then \
        cp scripts/plumbing/config.sh.template scripts/plumbing/config.sh; \
    fi

# Create a setup script for Avrora (requires manual intervention)
RUN echo '#!/bin/bash' > /opt/setup_avrora.sh && \
    echo 'echo "To set up Avrora, please follow the instructions at:"' >> /opt/setup_avrora.sh && \
    echo 'echo "https://www.cryptolux.org/index.php/FELICS_Avrora_patch"' >> /opt/setup_avrora.sh && \
    chmod +x /opt/setup_avrora.sh

# Create cpupower fix script
RUN echo '#!/bin/bash' > /opt/felics-ae/src/scripts/docker/fixup-cpupower.sh && \
    echo 'cd /tmp' >> /opt/felics-ae/src/scripts/docker/fixup-cpupower.sh && \
    echo 'apt-get update && apt-get install -y linux-tools-common linux-tools-generic' >> /opt/felics-ae/src/scripts/docker/fixup-cpupower.sh && \
    chmod +x /opt/felics-ae/src/scripts/docker/fixup-cpupower.sh

# Set proper ownership
RUN chown -R felics:felics /opt/felics-ae

# Switch to felics user
USER felics

# Set working directory
WORKDIR /opt/felics-ae/src

# Create entrypoint script
USER root
RUN echo '#!/bin/bash' > /docker-entrypoint.sh && \
    echo 'echo "FELICS-AE Docker Container"' >> /docker-entrypoint.sh && \
    echo 'echo "=========================="' >> /docker-entrypoint.sh && \
    echo 'echo "Working directory: /opt/felics-ae/src"' >> /docker-entrypoint.sh && \
    echo 'echo "User: felics"' >> /docker-entrypoint.sh && \
    echo 'echo ""' >> /docker-entrypoint.sh && \
    echo 'echo "Available tools:"' >> /docker-entrypoint.sh && \
    echo 'echo "- AVR toolchain (gcc-avr, simavr)"' >> /docker-entrypoint.sh && \
    echo 'echo "- MSP430 toolchain (/opt/msp430-gcc/bin)"' >> /docker-entrypoint.sh && \
    echo 'echo "- ARM toolchain (/opt/gcc-arm-none-eabi/bin)"' >> /docker-entrypoint.sh && \
    echo 'echo "- J-Link tools"' >> /docker-entrypoint.sh && \
    echo 'echo "- STLink tools"' >> /docker-entrypoint.sh && \
    echo 'echo ""' >> /docker-entrypoint.sh && \
    echo 'echo "Note: Run /opt/setup_avrora.sh for Avrora setup instructions"' >> /docker-entrypoint.sh && \
    echo 'echo ""' >> /docker-entrypoint.sh && \
    echo 'su - felics' >> /docker-entrypoint.sh && \
    chmod +x /docker-entrypoint.sh

ENTRYPOINT ["/docker-entrypoint.sh"]

# Expose any necessary ports (if needed)
# EXPOSE 8080

# Set labels
LABEL maintainer="FELICS-AE Setup" \
      description="Docker container for FELICS-AE cryptographic benchmarking framework" \
      version="1.0"
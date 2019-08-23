#!/bin/bash

set -eux

docker_dir=$(dirname $(realpath $0))
resources_dir=$1

run-bg ()
{
    local logfile="$@".log
    > ${logfile}

    date &>> ${logfile}
    "$@" &>> ${logfile}
    date &>> ${logfile}
}

get-simavr ()
{
    wget "https://github.com/buserror/simavr/archive/v1.6.tar.gz" \
         -O simavr-v1.6.tar.gz

    tar xf simavr-v1.6.tar.gz

    (
        cd simavr-1.6
        patch -p1 < "${docker_dir}"/simavr.patch
    )
}

get-msp430-gcc ()
{
    wget "http://software-dl.ti.com/msp430/msp430_public_sw/mcu/msp430/MSPGCC/latest/exports/msp430-gcc-8.2.0.52_linux64.tar.bz2"
    wget "http://software-dl.ti.com/msp430/msp430_public_sw/mcu/msp430/MSPGCC/latest/exports/msp430-gcc-support-files-1.207.zip"
    tar xf msp430-gcc-8.2.0.52_linux64.tar.bz2
    unzip msp430-gcc-support-files-1.207.zip
    cp -r msp430-gcc-support-files msp430-gcc-8.2.0.52_linux64/support-files
}

get-mspdebug ()
{
    wget "https://github.com/dlbeer/mspdebug/archive/v0.25.tar.gz" -O mspdebug.tar.gz
    tar xf mspdebug.tar.gz
}

get-avrora ()
{
    cvs -d:pserver:anonymous@a.cvs.sourceforge.net:/cvsroot/avrora co -P avrora
    wget https://www.cryptolux.org/images/4/4e/FELICS_Avrora_patch.txt
    patch -p0 < FELICS_Avrora_patch.txt
}

get-jlink ()
{
    local url="https://www.segger.com/downloads/jlink/JLink_Linux_x86_64.deb"

    curl "${url}"                               \
         -X POST                                \
         -F "accept_license_agreement=accepted" \
         -F "non_emb_ctr=confirmed"             \
         -F "submit=Download+software"          \
         -o JLink_Linux_x86_64.deb
}

get-nRF-tools ()
{
    local url="https://www.nordicsemi.com/-/media/Software-and-other-downloads/Desktop-software/nRF-command-line-tools/sw/Versions-10-x-x/nRFCommandLineTools1021Linuxamd64tar.gz"

    wget "${url}"
    tar -xzf nRFCommandLineTools1021Linuxamd64tar.gz ./nRF-Command-Line-Tools_10_2_1_Linux-amd64.deb
}

get-open-stlink ()
{
    local url="https://github.com/texane/stlink/archive/v1.5.1.tar.gz"
    
    wget "${url}"
    tar -xzf v1.5.1.tar.gz
}

(
    cd "${resources_dir}"

    downloads=(
        get-simavr
        get-msp430-gcc
        get-mspdebug
        get-avrora
        get-jlink
        get-nRF-tools
        get-open-stlink
    )

    for dl in ${downloads[@]}
    do
        run-bg ${dl} &
    done

    # Plain "wait" sometimes proceeds without waiting for the
    # background commands to start.

    for dl in ${downloads[@]}
    do
        if ! wait -n
        then
            tail *.log
            exit 1
        fi
    done

    # Put everything into a tarball, so that Docker's ADD command
    # extracts its content.
    tar czf dependencies.tar.gz                 \
        simavr-1.6                              \
        msp430-gcc-8.2.0.52_linux64             \
        mspdebug-0.25                           \
        avrora                                  \
        JLink_Linux_x86_64.deb                  \
        nRF-Command-Line-Tools_10_2_1_Linux-amd64.deb \
        stlink-1.5.1
)

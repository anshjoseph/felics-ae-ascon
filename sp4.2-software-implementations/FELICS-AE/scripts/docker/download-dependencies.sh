#!/bin/bash

set -eux

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
}

get-msp430-gcc ()
{
    wget "http://software-dl.ti.com/msp430/msp430_public_sw/mcu/msp430/MSPGCC/latest/exports/msp430-gcc-7.3.2.154_linux64.tar.bz2"
    tar xf msp430-gcc-7.3.2.154_linux64.tar.bz2
}

get-avrora ()
{
    cvs -d:pserver:anonymous@a.cvs.sourceforge.net:/cvsroot/avrora co -P avrora
    wget https://www.cryptolux.org/images/4/4e/FELICS_Avrora_patch.txt
    patch -p0 < FELICS_Avrora_patch.txt
}

get-jlink ()
{
    wget https://www.segger.com/downloads/jlink/JLink_Linux_x86_64.deb
}

mkdir -p resources
(
    cd resources
    run-bg get-simavr &
    run-bg get-msp430-gcc &
    run-bg get-avrora &
    run-bg get-jlink &

    wait

    # Put everything into a tarball, so that Docker's ADD command
    # extracts its content.
    tar czf dependencies.tar.gz                 \
        simavr-1.6                              \
        msp430-gcc-7.3.2.154_linux64            \
        avrora                                  \
        JLink_Linux_x86_64.deb
)

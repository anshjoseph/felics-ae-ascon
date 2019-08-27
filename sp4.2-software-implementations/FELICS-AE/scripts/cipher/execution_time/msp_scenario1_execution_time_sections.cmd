#
# University of Luxembourg
# Laboratory of Algorithmics, Cryptology and Security (LACS)
#
# FELICS - Fair Evaluation of Lightweight Cryptographic Systems
#
# Copyright (C) 2015 University of Luxembourg
#
# Written in 2015 by Daniel Dinu <dumitru-daniel.dinu@uni.lu>
#
# This file is part of FELICS.
#
# FELICS is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# FELICS is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, see <http://www.gnu.org/licenses/>.
#

# Select the file to debug
prog felics_bench.elf


#
# Set the breakpoints
#
setbreak crypto_aead_encrypt
setbreak EndEncryption

setbreak crypto_aead_decrypt
setbreak EndDecryption


# Add the benchmark execution time debug device to the IO's simulator's bus
simio add tracer debugDevice


# Run the program
run
# Print status information before encrypting.
simio info debugDevice


# Run the program
run
# Print status information after encrypting.
simio info debugDevice


# Run the program
run
# Print status information before decrypting.
simio info debugDevice


# Run the program
run
# Print status information after decrypting.
simio info debugDevice


# Exit from simulator
exit

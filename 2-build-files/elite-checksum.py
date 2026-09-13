#!/usr/bin/env python
#
# ******************************************************************************
#
# DISC ELITE CHECKSUM SCRIPT
#
# Written by Mark Moxon
#
# This script applies encryption and checksums to the compiled binary for the
# main game code. It reads these unencrypted binary files:
#
#   * ELITE4.unprot.bin
#   * D.CODE.unprot.bin
#   * T.CODE.unprot.bin
#
# and generates encrypted versions as follows:
#
#   * ELITE4.bin
#   * D.CODE.bin
#   * T.CODE.bin
#
# ******************************************************************************

from __future__ import print_function
import sys

argv = sys.argv
argc = len(argv)
encrypt = True
Scramble = True
release = 1

for arg in argv[1:]:
    if arg == "-u":
        encrypt = False
    if arg == "-rel1":
        release = 1
    if arg == "-rel2":
        release = 2
    if arg == "-rel3":
        Scramble = False
        release = 3

print("Disc Elite Checksum")
print("Encryption = ", encrypt)
print("Scramble main code = ", Scramble)

# Configuration variables for scrambling code and calculating checksums
#
# Values must match those in 3-assembled-output/compile.txt
#
# If you alter the source code, then you should extract the correct values for
# the following variables and plug them into the following, otherwise the game
# will fail the checksum process and will hang on loading
#
# You can find the correct values for these variables by building your updated
# source, and then searching compile.txt for "elite-checksum.py", where the new
# values will be listed

load_address = 0x1900

# TVT1code block
scramble1_from = 0x29A3     # TVT1code
scramble1_to = 0x2AA3       # ELITE
scramble1_eor = 0xA5

# LOADcode block
scramble2_from = 0x1B16     # LOADcode
scramble2_to = 0x1B90       # CATDcode
scramble2_eor = 0x18

# DIALS, SHIP_MISSILE and WORDS blocks
scramble3_from = 0x1D8C     # DIALS
scramble3_to = 0x298C       # OSBmod
scramble3_eor = 0xA5

# ELITE, ASOFT and CpASOFT blocks, plus padding to the end of the file
if release == 1 or release == 2:
    scramble4_from = 0x2AA3     # ELITE
    scramble4_to = 0x2E41       # End of ELITE4 file
    scramble4_eor = 0xA5
elif release == 3:
    scramble4_from = 0x2AA3     # ELITE
    scramble4_to = 0x2E31       # End of ELITE4 file (at PROT4)
    scramble4_eor = 0xA5

# Commander file checksum
tvt1_code = 0x29A3          # TVT1code
tvt1 = 0x1100               # TVT1
na_per_cent = 0x1181        # NA%
chk2 = 0x11D3               # CHK2

# Adaptive *TV interlace support: LINSCN and VSCANOP (both inside the
# resident &1100 block) get patched at load time by ENTRY to match whatever
# *TV interlace setting is in force, so the &55FF checksum below has to be
# precomputed for both possible states. LINSCN_offset/VSCANOP_offset are each
# label's offset from TVT1 (i.e. from &1100), and chk55ff is where the two
# precomputed values get poked into ELITE4, for LOAD to pick between at
# runtime - see CHK55FF in elite-loader3.asm
linscn_offset = 0x1D        # (LINSCN + 1) - TVT1, i.e. the operand byte of
                             # LINSCN's "LDA #nn" instruction, matching the
                             # "STA LINSCN+1" used to patch it in ENTRY
vscanop_offset = 0x24       # (VSCANOP + 1) - TVT1, likewise for VSCANOP
chk55ff = 0x1B63            # CHK55FF (address within ELITE4, as LOADcode is
                             # ORG'd to &0B00 - see compile.txt)

# Load assembled code files for ELITE4 and T.CODE
#
# T.CODE is loaded here too (rather than further down, where it's normally
# processed) because computing the two adaptive &55FF checksums below needs
# T.CODE's own bytes, but the result has to be patched into ELITE4, which is
# scrambled and written out before T.CODE is normally touched

data_block = bytearray()

elite_file = open("3-assembled-output/ELITE4.unprot.bin", "rb")
data_block.extend(elite_file.read())
elite_file.close()

tcode_file = open("3-assembled-output/T.CODE.unprot.bin", "rb")
tcode_data_block = bytearray(tcode_file.read())
tcode_file.close()

# Commander data checksum

na_per_cent_offset = na_per_cent - tvt1 + tvt1_code - load_address
checksum_offset = chk2 - tvt1 + tvt1_code - load_address
CH = 0x4B - 2
CY = 0
for i in range(CH, 0, -1):
    CH = CH + CY + data_block[na_per_cent_offset + i + 7]
    CY = (CH > 255) & 1
    CH = CH % 256
    CH = CH ^ data_block[na_per_cent_offset + i + 8]

print("Commander checksum = ", hex(CH))

data_block[checksum_offset] = CH ^ 0xA9
data_block[checksum_offset + 1] = CH

# Extract unscrambled &1100-&11E3 for use in &55FF checksum below

start_1100 = scramble1_from - load_address
end_1100 = start_1100 + 0xE3
block_1100 = data_block[start_1100:end_1100]

# Precompute the &55FF checksum for both possible *TV interlace states, by
# patching LINSCN/VSCANOP's bytes in a copy of block_1100 to match each state,
# then running the same checksum algorithm LOAD itself uses at runtime (see
# below, where this is done for real over whichever state actually applies).
#
# LOAD computes this checksum immediately after loading T.CODE fresh off
# disk, with no decryption step in between, so it's checksumming T.CODE's
# bytes exactly as the SC routine's EOR scramble leaves them on disk, not the
# plain, unscrambled bytes - hence scrambling a copy of tcode_data_block here
# with the same parameters T.CODE's own processing uses further down, to
# match what LOAD will actually see at runtime

tcode_scramble_load_address = 0x11E3
tcode_scramble_from = 0x1300
tcode_scramble_to = 0x6000
tcode_scramble_eor = 0x33

tcode_data_block_scrambled = bytearray(tcode_data_block)
if Scramble:
    for n in range(tcode_scramble_from, tcode_scramble_to):
        i = n - tcode_scramble_load_address
        tcode_data_block_scrambled[i] = tcode_data_block_scrambled[i] ^ (n % 256) ^ tcode_scramble_eor

def calc_55ff_checksum(block_1100_variant, tcode_bytes):
    block_to_checksum = block_1100_variant + tcode_bytes
    checksum = 0x11
    carry = 1
    for x in range(0x11, 0x54):
        for y in [0] + list(range(255, 0, -1)):
            i = x * 256 + y
            checksum += block_to_checksum[i - 0x1100] + carry
            if checksum > 255:
                carry = 1
            else:
                carry = 0
            checksum = checksum % 256
        carry = 0
        checksum = checksum % 256
    return checksum % 256

block_1100_interlace = bytearray(block_1100)
block_1100_interlace[linscn_offset] = 30
block_1100_interlace[vscanop_offset] = 57

block_1100_noninterlace = bytearray(block_1100)
block_1100_noninterlace[linscn_offset] = 222
block_1100_noninterlace[vscanop_offset] = 56

chk_interlace = calc_55ff_checksum(block_1100_interlace, tcode_data_block_scrambled)
chk_noninterlace = calc_55ff_checksum(block_1100_noninterlace, tcode_data_block_scrambled)

print("&55FF checksum (interlace) = ", hex(chk_interlace))
print("&55FF checksum (non-interlace) = ", hex(chk_noninterlace))

if encrypt:
    data_block[chk55ff - load_address] = chk_interlace
    data_block[chk55ff - load_address + 1] = chk_noninterlace

# EOR bytes in the various blocks

for n in range(scramble1_from, scramble1_to):
    data_block[n - load_address] = data_block[n - load_address] ^ scramble1_eor

for n in range(scramble2_from, scramble2_to):
    data_block[n - load_address] = data_block[n - load_address] ^ scramble2_eor

for n in range(scramble3_from, scramble3_to):
    data_block[n - load_address] = data_block[n - load_address] ^ scramble3_eor

for n in range(scramble4_from, scramble4_to):
    data_block[n - load_address] = data_block[n - load_address] ^ scramble4_eor

# Write output file for ELITE4

output_file = open("3-assembled-output/ELITE4.bin", "wb")
output_file.write(data_block)
output_file.close()

print("3-assembled-output/ELITE4.bin file saved")

# Configuration variables for D.CODE

load_address = 0x11E3
scramble_from = 0x1300
scramble_to = 0x5600
scramble_eor = 0x33

# Load assembled code file for D.CODE

data_block = bytearray()

elite_file = open("3-assembled-output/D.CODE.unprot.bin", "rb")
data_block.extend(elite_file.read())
elite_file.close()

# SC routine, which EORs bytes between &1300 and &55FF

# if Scramble:
#    for n in range(scramble_from, scramble_to):
#        data_block[n - load_address] = data_block[n - load_address] ^ (n % 256) ^ scramble_eor

# Write output file for D.CODE

output_file = open("3-assembled-output/D.CODE.bin", "wb")
output_file.write(data_block)
output_file.close()

print("3-assembled-output/D.CODE.bin file saved")

# Configuration variables for T.CODE

load_address = 0x11E3
scramble_from = 0x1300
scramble_to = 0x6000
scramble_eor = 0x33

# Use the T.CODE bytes already loaded above (needed there to precompute the
# adaptive &55FF checksums before ELITE4 was written out)

data_block = tcode_data_block

# SC routine, which EORs bytes between &1300 and &9FFF

if Scramble:
    for n in range(scramble_from, scramble_to):
        data_block[n - load_address] = data_block[n - load_address] ^ (n % 256) ^ scramble_eor

# LOAD routine, which calculates checksum at &55FF in docked code
#
# This is the checksum for whichever *TV interlace state block_1100 happens
# to be assembled with by default. For the STH/IB_DISC builds, LOAD's own
# adaptive patch (see CHK55FF in elite-loader3.asm) overwrites this value at
# load time to match whichever state is actually in force, so this is really
# just a sensible, self-consistent default for T.CODE's own on-disk copy of
# &55FF, in case that runtime patch is ever bypassed (e.g. _REMOVE_CHECKSUMS)

checksum_address = 0x55FF
block_to_checksum = block_1100 + data_block

d_checksum = 0x11
carry = 1
for x in range(0x11, 0x54):
    for y in [0] + list(range(255, 0, -1)):
        i = x * 256 + y
        d_checksum += block_to_checksum[i - 0x1100] + carry
        if d_checksum > 255:
            carry = 1
        else:
            carry = 0
        d_checksum = d_checksum % 256
    carry = 0
    d_checksum = d_checksum % 256
d_checksum = d_checksum % 256

if release == 3:
    # Override the checksum to match value in binary, as the
    # checksum is disabled in LOAD in the sideways RAM variant
    d_checksum = 0xE6

if encrypt:
    data_block[checksum_address - load_address] = d_checksum

print("&55FF docked code checksum = ", hex(d_checksum))

# Write output file for T.CODE

output_file = open("3-assembled-output/T.CODE.bin", "wb")
output_file.write(data_block)
output_file.close()

print("3-assembled-output/T.CODE.bin file saved")

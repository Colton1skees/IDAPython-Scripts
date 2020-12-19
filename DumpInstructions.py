"""
This script is designed to dump all instructions and their corresponding bytes to a text file.

Intended purpose - emulation with unicorn to validate virtualizer results

"""

from idautils import *
from idaapi import *
from idc import *
import binascii

fout = open("C:\Users\colton\Desktop\DumpedInstructions.txt", "w+") 

for segea in Segments():
    for funcea in Functions(segea, SegEnd(segea)):
        functionName = GetFunctionName(funcea)
        for (startea, endea) in Chunks(funcea):
            for head in Heads(startea, endea):
                fout.write("0x%08x"%(head) + ":" + binascii.hexlify(idc.GetManyBytes(head, ItemSize(head))) + ":" + GetDisasm(head) + "\n")
                 
"""
This script automatically reverses cryengine functions with leftover debug
strings.

It parses every string for the pattern ClassName::MethodName and automatically
renames the method to its proper name. It dumps the address + actual name of the
function to a .txt file.
"""
import re

import idaapi
import idautils


STRINGS = idautils.Strings()

for string in STRINGS:
    programString = str(string)
    if '::' not in programString:
        continue
    programString = programString.replace("~", "_")
    programString = re.search(r"[^ :\[<]+::[^ :>\]]+", programString)
    if programString:
        programString = programString.group(0)
    else:
        continue
    xrefs = idautils.XrefsTo(string.ea)
    # count elements in generator
    if sum(1 for _ in xrefs) != 1:
        continue
    xrefsNew = idautils.XrefsTo(string.ea)
    for xref in xrefsNew:
        func = idaapi.get_func(xref.frm)
        name = idaapi.get_func_name(xref.frm)
        if name is not None:
            print("RandomName: {}, ActualName: {}".format(name, programString))
            address = idaapi.GetFunctionAttr(xref.frm, idaapi.FUNCATTR_START)
            print(address)
            # idc.MakeNameEx(address, programString, 0x00)

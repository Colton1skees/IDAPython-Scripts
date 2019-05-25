# This script is designed to automatically reverse cryengine functions with left over debug strings.
# It parses every string for the pattern ClassName::MethodName and automatically renames the method to it's proper name. (This is accurate in 99% of cases)
# Finally, it dumps the address + actual name of the function to a .txt, which is useful in other programs.
# I personally used the .txt file for my Reclass.NET plugin, which parses the txt file and automatically renames/identifies applicable Vtable methods and classes. This also makes code generation very clean/

import idautils
import idc
from idaapi import *
strings = idautils.Strings()
invalidStrings = [",", "/", "\\", ".", "(", ")", "-", "<", ">", " "]


for string in strings:
    programString = str(string)
    if '::' in programString:
        programString = programString.split(" ", 1)[0]
        programString = programString.replace("~", "_")
        for invalidString in invalidStrings:
            programString = programString.translate(None, invalidString) 
        if programString.count("[") == 1 and programString.count("]") == 1:
            programString = programString[programString.find("[")+1:programString.find("]")]
        xrefs = idautils.XrefsTo(string.ea)
        count = sum(1 for _ in xrefs)
        if count == 1:
            xrefsNew = idautils.XrefsTo(string.ea)
            for xref in xrefsNew:
                    func = idaapi.get_func(xref.frm)
                    name = get_func_name(xref.frm)
                    if 'None' not in str(name):
                        print("RandomName: {}, ActualName: {}".format(name, programString))
                        address = (GetFunctionAttr(xref.frm, FUNCATTR_START))
                        print(address)
                       # idc.MakeNameEx(address, programString, 0x00)
                        
    
    

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
                        
    
    
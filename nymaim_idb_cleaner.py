import struct
import idc
import pdb


PATTRN = "55 89 e5 50 8b 45 04 89 45 10 8b 45 0c ?? 45 08"
COUNT = 0
MOVE_FUNC_ADDR = None # 0x41F271


PERFORM = [
    "03", # ADD
    "33", # XOR
    "2B"  # SUB
]


REGISTRY_TABLE = {
    0x8: "EAX",
    0x9: "ECX",
    0xA: "EDX",
    0xB: "EBX",
    0xC: "???",
    0xD: "EBP",
    0xE: "ESI",
    0xF: "EDI "
}


def get_value_from_address(address, offset=0):
    return struct.unpack("I", idc.GetManyBytes(address + offset, 0x4))[0]
 

def get_value_from_address2(address, offset=4):
    return (struct.unpack("I", idc.GetManyBytes(address + offset, 0x4)[::1])[0] & 0xFFFFFFFF)


def get_address(address, operation):
    num1 = get_value_from_address2(address, -4)
    num2 = get_value_from_address2(address, -9)

    if operation == "03":
        o1 = (0xFFFFFFFF & (num2 + num1))

    if operation == "33":
        o1 = (0xFFFFFFFF & (num2 ^ num1))

    if operation == "2B":
        o1 = (0xFFFFFFFF & (num2 - num1))

    next_instuction = address + 5

    next_inst1 = (0xFFFFFFFF & (next_instuction + o1))

    idc.MakeComm(address, "Jump to {address1}".format(address1=hex(next_inst1).replace("L", '')))


def find_unreferenced_calls(operation):
    global COUNT
    xrefs = []
    ea = 0

    while ea != BADADDR:
        ea = idc.FindBinary(ea, SEARCH_NEXT|SEARCH_DOWN|SEARCH_CASE, PATTRN.replace("??", operation))

        for xref in XrefsTo(ea):
            if xref.frm not in xrefs:
                COUNT += 1

                # xrefs.append(xref.frm)
                MakeName(xref.to, "unreferenced_call_{count}".format(count=COUNT))

                # MakeName(xref.to, "")
                get_address(xref.frm, operation)


def move_registry_to_the_stack(funaddr):
    MakeName(funaddr, "move_registry")

    for xref in XrefsTo(funaddr):
        argument = ord(GetManyBytes(xref.frm - 1, 0x1))
        registry = REGISTRY_TABLE[argument]
        MakeComm(xref.frm, "MOV [ESP] , {reg}".format(reg=registry))

##
# MAIN
##

print "[*] Stage 1: Looking for the unreferenced calls"
for op in PERFORM:
    find_unreferenced_calls(op)
print "\t[+] Done. {count} unreferenced calls found.".format(count=COUNT)

# print "[*] Stage 2: Renaming regisrty custom MOV"
# move_registry_to_the_stack(MOVE_FUNC_ADDR)
# print "\t[+] Done."

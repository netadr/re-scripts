# Decrypt strings and log messages present in a Solaris SPARC Equation Group sample (identifies itself as "Sbz 2.6.1.0 (Lla 4.2)")
# Contains derivative code from https://github.com/SamL98/GhidraStackStrings/blob/master/emulator_utils.py and
# https://maxkersten.nl/binary-analysis-course/analysis-scripts/ghidra-script-to-decrypt-strings-in-amadey-1-09/

from pydoc import resolve
from ghidra.app.decompiler import (
    ClangFuncNameToken,
    ClangNode,
    ClangOpToken,
    ClangTokenGroup,
    ClangVariableToken,
    DecompInterface,
)
from ghidra.app.util import PseudoDisassembler
from ghidra.program.flatapi import FlatProgramAPI
from ghidra.program.model.address import Address
from ghidra.program.model.pcode import PcodeOp

import jarray
import time

from emulator import Emulator

STRING_ADDR = 0x27568
STRING_START = 0x27568
STRING_END = 0x275A8
MESSAGE_ADDR = 0x2AB5C
MESSAGE_START = 0x2A1EC
MESSAGE_END = 0x2A27C
UMUL_START = 0x73440
UMUL_END = 0x2A1CC

NUMBER = 0
BEGIN = 0


def get_xrefs_to_addr(addr):
    xrefs = []

    for ref in currentProgram.referenceManager.getReferencesTo(toAddr(addr)):
        if not ref.isEntryPointReference() and not ref.isExternalReference():
            xrefs.append(ref.getFromAddress())

    return xrefs


def get_indirect_ptr(addr):
    dis = PseudoDisassembler(currentProgram)
    return dis.getIndirectAddr(addr)


def get_byte(addr):
    api = FlatProgramAPI(currentProgram)
    return api.getByte(addr)


def get_bytes(addr, size):
    api = FlatProgramAPI(currentProgram)
    return bytearray(api.getBytes(addr, size))


def set_comment(addr, string):
    listing = currentProgram.getListing()
    code_unit = listing.getCodeUnitAt(addr)
    code_unit.setComment(code_unit.PLATE_COMMENT, string)
    code_unit.setComment(code_unit.PRE_COMMENT, string)


def strlen(addr):
    pos = 0

    while True:
        if get_byte(addr.add(pos)) == 0:
            break
        pos = pos + 1

    return pos


def get_call_arguments(addr):
    if not isinstance(addr, Address):
        addr = toAddr(addr)

    args = []

    caller = getFunctionBefore(addr)
    if not caller:
        raise Exception("Failed to get function before address!")

    decomp_interface = DecompInterface()
    decomp_interface.openProgram(currentProgram)
    decomp_result = decomp_interface.decompileFunction(caller, 10, monitor)
    if not decomp_result.decompileCompleted():
        raise Exception("Failed to decompile function!")

    high_function = decomp_result.getHighFunction()
    ops = high_function.getPcodeOps(addr)

    while ops.hasNext():
        op = ops.next()

        if op.getOpcode() == PcodeOp.CALL:
            inputs = op.getInputs()

            for arg in inputs[1:]:
                args.append(arg)

    return args


def resolve_string_loc(varnode):
    if varnode.isUnique():
        return None  # TODO: Resolve unique variables
    else:
        return get_indirect_ptr(varnode.getAddress())


def decrypt_string(buf, size):
    emu = Emulator()

    emu.write_mem(0x0AAAAAAA, buf)
    emu.emulate_range(
        STRING_START,
        STRING_END,
        regs={"o0": 0x0BBBBBBB, "o1": 0x0AAAAAAA, "o2": size},
    )

    out = bytearray(emu.read_mem(0x0BBBBBBB, size))
    out.pop()

    return out.decode("ascii")


def umul_handler(ctx):
    result = ctx.get_reg("o0") * ctx.get_reg("o1")
    ctx.set_reg("o0", result)
    ctx.set_pc(UMUL_END)


def decrypt_message(buf, size):
    emu = Emulator()

    emu.write_mem(0x0AAAAAAA, buf)
    emu.emulate_range(
        MESSAGE_START,
        MESSAGE_END,
        regs={"o0": 0x0BBBBBBB, "o1": 0x0AAAAAAA, "o2": size},
        hooks={UMUL_START: umul_handler},
    )

    out = bytearray(emu.read_mem(0x0BBBBBBB, size))

    return out.decode("ascii")


def do_strings():
    global NUMBER

    xrefs = get_xrefs_to_addr(STRING_ADDR)

    for xref in xrefs:
        args = get_call_arguments(xref)

        if not args:
            print(
                "WARNING - unable to resolve arguments for {:#x}".format(
                    xref.getOffset()
                )
            )
            continue

        size = args[2]
        enc_buf_ptr = resolve_string_loc(args[1])

        if not size:
            print("WARNING - unable to resolve size for {:#x}".format(xref.getOffset()))
            continue

        if not enc_buf_ptr:
            print(
                "WARNING - unable to resolve string location for {:#x}".format(
                    xref.getOffset()
                )
            )
            continue

        enc_buf = get_bytes(enc_buf_ptr, size.getOffset() + 1)
        dec = decrypt_string(enc_buf, size.getOffset())
        set_comment(xref, dec)
        print('{:#x} - "{}"'.format(xref.getOffset(), dec))
        NUMBER = NUMBER + 1


def do_messages():
    global NUMBER

    xrefs = get_xrefs_to_addr(MESSAGE_ADDR)

    for xref in xrefs:
        args = get_call_arguments(xref)

        if not args:
            print(
                "WARNING - unable to resolve arguments for {:#x}".format(
                    xref.getOffset()
                )
            )
            continue

        enc_buf_ptr = resolve_string_loc(args[3])

        if not enc_buf_ptr:
            print(
                "WARNING - unable to resolve string location for {:#x}".format(
                    xref.getOffset()
                )
            )
            continue

        size = strlen(enc_buf_ptr)
        enc_buf = get_bytes(enc_buf_ptr, size)
        dec = decrypt_message(enc_buf, size)
        set_comment(xref, dec)
        print('{:#x} - "{}"'.format(xref.getOffset(), dec))
        NUMBER = NUMBER + 1


def main():
    global BEGIN
    BEGIN = time.time()

    do_strings()
    do_messages()

    elapsed = time.time() - BEGIN
    print("{} strings decrypted in {} seconds.".format(NUMBER, elapsed))


main()

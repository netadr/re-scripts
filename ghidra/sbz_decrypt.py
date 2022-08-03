# Decrypt strings and log messages present in a Solaris SPARC Equation Group sample (identifies itself as "Sbz 2.6.1.0 (Lla 4.2)")
# Contains derivative code from https://github.com/SamL98/GhidraStackStrings/blob/master/emulator_utils.py and
# https://maxkersten.nl/binary-analysis-course/analysis-scripts/ghidra-script-to-decrypt-strings-in-amadey-1-09/

from ghidra.app.decompiler import (
    ClangFuncNameToken,
    ClangNode,
    ClangOpToken,
    ClangTokenGroup,
    ClangVariableToken,
    DecompInterface,
)
from ghidra.app.emulator import EmulatorHelper
from ghidra.app.util import PseudoDisassembler
from ghidra.program.flatapi import FlatProgramAPI
from ghidra.program.model.address import Address

import jarray
import time

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


class Emulator(object):
    def __init__(self):
        self.emulator = EmulatorHelper(currentProgram)
        self.pc = self.emulator.getPCRegister()
        self.sp = self.emulator.getStackPointerRegister()
        self.hooks = {}

    def get_pc(self):
        return self.emulator.readRegister(self.pc)

    def set_pc(self, value):
        return self.emulator.writeRegister(self.pc, value)

    def get_sp(self):
        return self.emulator.readRegister(self.sp)

    def set_sp(self, value):
        return self.emulator.writeRegister(self.sp, value)

    def read_mem(self, addr, size):
        if not isinstance(addr, Address):
            addr = toAddr(addr)

        return self.emulator.readMemory(addr, size)

    def write_mem(self, addr, buf):
        if not isinstance(addr, Address):
            addr = toAddr(addr)

        return self.emulator.writeMemory(addr, bytearray_to_java_bytes(buf))

    def get_reg(self, name):
        return self.emulator.readRegister(name)

    def set_reg(self, name, value):
        return self.emulator.writeRegister(name, value)

    def emulate_range(self, start, end, reg_args=None, hooks=None):
        self.set_sp(0x0FFFFFFF)

        if reg_args:
            for reg, value in reg_args.items():
                self.set_reg(reg, value)

        if hooks:
            for address, handler in hooks.items():
                self.hooks[address] = handler

        self.set_pc(start)

        while True:
            self.emulator.step(monitor)

            for address, handler in self.hooks.items():
                if self.get_pc() == address:
                    handler(self)

            if self.get_pc() == end:
                break


def bytearray_to_java_bytes(buf):
    return jarray.array(((x if x < 128 else (x - 256)) for x in bytearray(buf)), "b")


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


def iter_pcode_ops(addr):
    ops = []

    caller = getFunctionBefore(addr)
    if not caller:
        raise Exception("Failed to get function before address!")

    decomp_interface = DecompInterface()
    decomp_interface.openProgram(currentProgram)
    decomp_result = decomp_interface.decompileFunction(caller, 10, monitor)
    if not decomp_result.decompileCompleted():
        raise Exception("Failed to decompile function!")

    high_function = decomp_result.getHighFunction()
    pcodes = high_function.getPcodeOps(addr)

    for op in pcodes:
        ops.append(op)

    return ops


def get_token_group(addr):
    caller = getFunctionBefore(addr)
    if not caller:
        raise Exception("Failed to get function before address!")

    decomp_interface = DecompInterface()
    decomp_interface.openProgram(currentProgram)
    decomp_result = decomp_interface.decompileFunction(caller, 10, monitor)
    if not decomp_result.decompileCompleted():
        raise Exception("Failed to decompile function!")

    token_group = decomp_result.getCCodeMarkup()

    return token_group


# This is probably horribly inefficient. But... it works.
def get_func_statement_at_addr(token, addr):
    if isinstance(token, ClangNode):
        min_address = token.getMinAddress()
        max_address = token.getMaxAddress()

        if (
            min_address == addr
            and max_address == addr
            and isinstance(token, ClangFuncNameToken)
        ):
            return token.Parent()

        if isinstance(token, ClangTokenGroup):
            for child in token.iterator():
                result = get_func_statement_at_addr(child, addr)
                if result:
                    return result

    return None


# This only works for single variable arguments or constants.
def get_arg_from_statement(statement, idx, input):
    counter = 0
    arg_idx = 0

    while counter != statement.numChildren():
        child = statement.Child(counter)
        if isinstance(child, ClangVariableToken):
            if arg_idx == idx:
                inputs = child.getPcodeOp().getInputs()

                if inputs[input]:
                    return inputs[input]
                else:
                    return None
        elif isinstance(child, ClangOpToken):
            if child.toString() == ",":
                arg_idx = arg_idx + 1

        counter = counter + 1

    return None


def decrypt_string(buf, size):
    emu = Emulator()

    emu.write_mem(0x0AAAAAAA, buf)
    emu.emulate_range(
        STRING_START,
        STRING_END,
        reg_args={"o0": 0x0BBBBBBB, "o1": 0x0AAAAAAA, "o2": size},
    )

    out = bytearray(emu.read_mem(0x0BBBBBBB, size))
    out.pop()

    return out.decode("ascii")


def umul_handler(ctx):
    result = ctx.get_reg("o0") * ctx.get_reg("o1")
    ctx.set_reg("o0", result)
    ctx.set_pc(UMUL_END)


def decrypt_messages(buf, size):
    emu = Emulator()

    emu.write_mem(0x0AAAAAAA, buf)
    emu.emulate_range(
        MESSAGE_START,
        MESSAGE_END,
        reg_args={"o0": 0x0BBBBBBB, "o1": 0x0AAAAAAA, "o2": size},
        hooks={UMUL_START: umul_handler},
    )

    out = bytearray(emu.read_mem(0x0BBBBBBB, size))

    return out.decode("ascii")


def do_strings():
    global NUMBER

    xrefs = get_xrefs_to_addr(STRING_ADDR)

    for xref in xrefs:
        group = get_token_group(xref)
        match = get_func_statement_at_addr(group, xref)

        if not match:
            print(
                "WARNING - unable to resolve function at {:#x}".format(xref.getOffset())
            )
            continue

        enc_buf_indirect = get_arg_from_statement(match, 1, 2).getAddress()
        size = get_arg_from_statement(match, 2, 3).getAddress()

        if not enc_buf_indirect or not size or enc_buf_indirect.isUniqueAddress():
            print(
                "WARNING - unable to resolve arguments for {:#x}".format(
                    xref.getOffset()
                )
            )
            continue

        enc_buf_ptr = get_indirect_ptr(enc_buf_indirect)
        enc_buf = get_bytes(enc_buf_ptr, size.getOffset() + 1)
        dec = decrypt_string(enc_buf, size.getOffset())
        set_comment(xref, dec)
        print('{:#x} - "{}"'.format(xref.getOffset(), dec))
        NUMBER = NUMBER + 1


def do_messages():
    global NUMBER

    xrefs = get_xrefs_to_addr(MESSAGE_ADDR)

    for xref in xrefs:
        group = get_token_group(xref)
        match = get_func_statement_at_addr(group, xref)

        if not match:
            print(
                "WARNING - unable to resolve function at {:#x}".format(xref.getOffset())
            )
            continue

        enc_buf_indirect = get_arg_from_statement(match, 3, 4).getAddress()

        if not enc_buf_indirect or enc_buf_indirect.isUniqueAddress():
            print(
                "WARNING - unable to resolve arguments for {:#x}".format(
                    xref.getOffset()
                )
            )
            continue

        enc_buf_ptr = get_indirect_ptr(enc_buf_indirect)
        size = strlen(enc_buf_ptr)
        enc_buf = get_bytes(enc_buf_ptr, size)
        dec = decrypt_messages(enc_buf, size)
        set_comment(xref, dec)
        print('{:#x} - "{}"'.format(xref.getOffset(), dec))
        NUMBER = NUMBER + 1


def main():
    global BEGIN
    BEGIN = time.time()

    do_strings()
    do_messages()

    elapsed = time.time() - BEGIN
    print("{} strings decrypted in {} seconds.".format(NUMBER, (elapsed % 60)))


main()

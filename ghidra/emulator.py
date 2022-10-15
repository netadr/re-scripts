# More Python-y wrapper around Ghidra's EmulatorHelper class.

from __main__ import *

from ghidra.app.emulator import EmulatorHelper
from ghidra.program.model.address import Address

import jarray

def bytearray_to_java_bytes(buf):
    return jarray.array(((x if x < 128 else (x - 256)) for x in bytearray(buf)), "b")

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

    def emulate_range(self, start, end, sp, regs=None, hooks=None):
        self.set_sp(sp)

        if regs:
            for reg, value in regs.items():
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

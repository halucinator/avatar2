from capstone import *
from keystone.keystone_const import *
from unicorn import *
from unicorn.arm_const import *
from unicorn.arm64_const import *
from .architecture import Architecture
import avatar2

from avatar2.installer.config import QEMU, PANDA, OPENOCD, GDB_MULTI


class ARM(Architecture):

    get_qemu_executable = Architecture.resolve(QEMU)
    get_panda_executable = Architecture.resolve(PANDA)
    get_gdb_executable = Architecture.resolve(GDB_MULTI)
    get_oocd_executable = Architecture.resolve(OPENOCD)

    qemu_name = 'arm'
    gdb_name = 'arm'
    # Based on gdb profile
    registers = {'r0': 0, 'r1': 1, 'r2': 2, 'r3': 3, 'r4': 4, 'r5': 5, 'r6': 6,
                 'r7': 7, 'r8': 8, 'r9': 9, 'r10': 10, 'r11': 11, 'r12': 12, 'ip': 12,
                 'sp': 13, 'lr': 14, 'pc': 15, 'cpsr': 25,
                 }
    unicorn_registers = {'r0': UC_ARM_REG_R0, 'r1': UC_ARM_REG_R1, 'r2': UC_ARM_REG_R2,
                         'r3': UC_ARM_REG_R3, 'r4': UC_ARM_REG_R4, 'r5': UC_ARM_REG_R5,
                         'r6': UC_ARM_REG_R6, 'r7': UC_ARM_REG_R7, 'r8': UC_ARM_REG_R8,
                         'r9': UC_ARM_REG_R9, 'r10': UC_ARM_REG_R10, 'r11': UC_ARM_REG_R11,
                         'r12': UC_ARM_REG_R12, 'sp': UC_ARM_REG_SP, 'lr': UC_ARM_REG_LR,
                         'pc': UC_ARM_REG_PC, 'cpsr': UC_ARM_REG_CPSR}
    pc_name = 'pc'
    sr_name = 'cpsr'
    unemulated_instructions = ['mcr', 'mrc']
    capstone_arch = CS_ARCH_ARM
    capstone_mode = CS_MODE_LITTLE_ENDIAN
    keystone_arch = KS_ARCH_ARM
    keystone_mode = KS_MODE_ARM
    unicorn_arch = UC_ARCH_ARM
    unicorn_mode = UC_MODE_ARM


class ARM_CORTEX_M3(ARM):
    cpu_model = 'cortex-m3'
    qemu_name = 'arm'
    gdb_name = 'arm'

    capstone_mode = CS_MODE_LITTLE_ENDIAN | CS_MODE_THUMB | CS_MODE_MCLASS
    keystone_arch = KS_ARCH_ARM
    keystone_mode = KS_MODE_LITTLE_ENDIAN | KS_MODE_THUMB
    unicorn_arch = UC_ARCH_ARM
    unicorn_mode = UC_MODE_LITTLE_ENDIAN | UC_MODE_THUMB
    sr_name = 'xpsr'
    # The xpsr register has different register numbers across QEmu and OpenOCD, so we make sure to read/write it only by name
    special_registers = {'xpsr': {'gdb_expression': "$xpsr", 'format': "{:d}"}}

    @staticmethod
    def register_write_cb(avatar, *args, **kwargs):

        if isinstance(kwargs['watched_target'],
                      avatar2.targets.qemu_target.QemuTarget):
            qemu = kwargs['watched_target']

            # xcps/cpsr encodes the thumbbit diffently accross different
            # ISA versions. Panda_target does not cleanly support cortex-m yet,
            # and hence uses the thumbbit as stored on other ARM versions.
            if isinstance(qemu, avatar2.targets.panda_target.PandaTarget):
                shiftval = 5
            else:
                shiftval = 24

            if args[0] == 'pc' or args[0] == 'cpsr':
                cpsr = qemu.protocols.registers.read_register('cpsr')
                if cpsr & 1 << shiftval:
                    return
                else:
                    cpsr |= 1 << shiftval
                    qemu.protocols.registers.write_register('cpsr', cpsr)

    @staticmethod
    def init(avatar):
        avatar.watchmen.add('TargetRegisterWrite', 'after',
                            ARM_CORTEX_M3.register_write_cb)

        pass



ARMV7M = [ARM_CORTEX_M3]


class ARMBE(ARM):
    qemu_name = 'armeb'
    capstone_mode = CS_MODE_BIG_ENDIAN


class ARM64(Architecture):
    get_qemu_executable = Architecture.resolve(QEMU)
    get_panda_executable = Architecture.resolve(PANDA)
    get_gdb_executable  = Architecture.resolve(GDB_MULTI)
    get_oocd_executable = Architecture.resolve(OPENOCD)

    qemu_name = 'arm64'
    gdb_name = 'aarch64'
    registers = {'x0': 0, 'x1': 1, 'x2': 2, 'x3': 3, 'x4': 4, 'x5': 5, 'x6': 6,
                 'x7': 7, 'x8': 8, 'x9': 9, 'x10': 10, 'x11': 11, 'x12': 12,
                 'sp': 13, 'lr': 14, 'pc': 15, 'nzcv': 25,
                 }
    unicorn_registers = {'x0' : UC_ARM64_REG_X0,  'x1'  : UC_ARM64_REG_X1,  'x2' : UC_ARM64_REG_X2,
                         'x3' : UC_ARM64_REG_X3,  'x4'  : UC_ARM64_REG_X4,  'x5' : UC_ARM64_REG_X5,
                         'x6' : UC_ARM64_REG_X6,  'x7'  : UC_ARM64_REG_X7,  'x8' : UC_ARM64_REG_X8,
                         'x9' : UC_ARM64_REG_X9,  'x10' : UC_ARM64_REG_X10, 'x11': UC_ARM64_REG_X11,
                         'x12': UC_ARM64_REG_X12, 'sp'  : UC_ARM64_REG_SP,  'lr' : UC_ARM64_REG_LR,
                         'pc' : UC_ARM64_REG_PC,  'nzcv': UC_ARM64_REG_NZCV}
    pc_name = 'pc'
    sr_name = 'nzcv'
    unemulated_instructions = ['mcr', 'mrc']
    capstone_arch = CS_ARCH_ARM64
    capstone_mode = CS_MODE_LITTLE_ENDIAN
    keystone_arch = KS_ARCH_ARM64
    unicorn_arch = UC_ARCH_ARM64
    unicorn_mode = UC_MODE_ARM

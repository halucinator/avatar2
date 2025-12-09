from capstone import (CS_ARCH_PPC, CS_MODE_BIG_ENDIAN,
    CS_MODE_LITTLE_ENDIAN, CS_MODE_32, CS_MODE_64)
from keystone.keystone_const import (
    KS_ARCH_PPC, KS_MODE_PPC32, KS_MODE_PPC64)
from unicorn import UC_ARCH_PPC, UC_MODE_PPC32, UC_MODE_PPC64
import unicorn.ppc_const as upc

from avatar2.archs.architecture import Architecture
from avatar2.installer.config import QEMU, PANDA, OPENOCD, GDB_MULTI


class PPCBase(Architecture):
    """Common PowerPC base for 32- and 64-bit variants."""
    get_qemu_executable = Architecture.resolve(QEMU)
    get_panda_executable = Architecture.resolve(PANDA)
    get_gdb_executable = Architecture.resolve(GDB_MULTI)
    get_oocd_executable = Architecture.resolve(OPENOCD)

    # common registers r0-r31 + special regs
    registers = {f"r{i}": i for i in range(32)}
    registers.update({
        "sp": 1, "pc": 64, "msr": 65, "cr": 66,
        "lr": 67, "ctr": 68, "xer": 69
    })

    # common unicorn mapping
    unicorn_registers = {f"r{i}": getattr(upc, f"UC_PPC_REG_{i}")
                        for i in range(32)}
    unicorn_registers.update({
        "pc": upc.UC_PPC_REG_PC, "nip": upc.UC_PPC_REG_PC,
        "cr0": upc.UC_PPC_REG_CR0, "cr1": upc.UC_PPC_REG_CR1,
        "cr2": upc.UC_PPC_REG_CR2, "cr3": upc.UC_PPC_REG_CR3,
        "cr4": upc.UC_PPC_REG_CR4, "cr5": upc.UC_PPC_REG_CR5,
        "cr6": upc.UC_PPC_REG_CR6, "cr7": upc.UC_PPC_REG_CR7,
        "lr": upc.UC_PPC_REG_LR, "xer": upc.UC_PPC_REG_XER,
        "ctr": upc.UC_PPC_REG_CTR, "msr": upc.UC_PPC_REG_MSR
    })

    pc_name = "pc"
    sr_name = "cr"
    capstone_arch = CS_ARCH_PPC
    keystone_arch = KS_ARCH_PPC
    unicorn_arch = UC_ARCH_PPC


class PPC32(PPCBase):
    """32-bit PowerPC."""
    qemu_name = "ppc"
    gdb_name = "powerpc:common"
    endian = "big"
    capstone_mode = CS_MODE_BIG_ENDIAN | CS_MODE_32
    keystone_mode = KS_MODE_PPC32
    unicorn_mode = UC_MODE_PPC32


class PPC64(PPCBase):
    """64-bit PowerPC."""
    qemu_name = "ppc64"
    gdb_name = "powerpc64:common"
    endian = "big"
    capstone_mode = CS_MODE_BIG_ENDIAN | CS_MODE_64
    keystone_mode = KS_MODE_PPC64
    unicorn_mode = UC_MODE_PPC64


class PPC_MPC8544DS(PPC32):
    """QEMU's MPC8544DS variant."""
    gdb_name = "powerpc:MPC8XX"


class PPC_BE(PPC32):
    """Alias for big-endian PPC32."""
    pass


class PPC_LE(PPC32):
    """Little-endian PPC32."""
    capstone_mode = CS_MODE_LITTLE_ENDIAN | CS_MODE_32
    unicorn_mode = UC_MODE_PPC32 | CS_MODE_LITTLE_ENDIAN


class PPC64_BE(PPC64):
    """Alias for big-endian PPC64."""
    pass


class PPC64_LE(PPC64):
    """Little-endian PPC64."""
    capstone_mode = CS_MODE_LITTLE_ENDIAN | CS_MODE_64
    unicorn_mode = UC_MODE_PPC64 | CS_MODE_LITTLE_ENDIAN

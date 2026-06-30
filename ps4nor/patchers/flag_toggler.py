import struct
from ..utils.nor_defs import UART_OFFSET, UART_BACKUP_OFFSET


class FlagToggler:
    def __init__(self, data):
        self.data = bytearray(data)

    def enable_uart(self, fw_version=None):
        off = UART_OFFSET
        if off < len(self.data):
            self.data[off] = 0x01
            bck = off + UART_BACKUP_OFFSET
            if bck < len(self.data):
                self.data[bck] = 0x01
            return True, f"UART enabled at 0x{off:06X}"
        return False, "Could not enable UART"

    def disable_uart(self, fw_version=None):
        off = UART_OFFSET
        if off < len(self.data):
            self.data[off] = 0x00
            bck = off + UART_BACKUP_OFFSET
            if bck < len(self.data):
                self.data[bck] = 0x00
            return True, f"UART disabled at 0x{off:06X}"
        return False, "Could not disable UART"

    def toggle_flag(self, offset, bit_position, enable=True):
        if offset >= len(self.data):
            return False, f"Offset 0x{offset:06X} out of range"
        current = self.data[offset]
        if enable:
            self.data[offset] = current | (1 << bit_position)
        else:
            self.data[offset] = current & ~(1 << bit_position)
        return True, f"Flag {'enabled' if enable else 'disabled'} at 0x{offset:06X} bit {bit_position}"

    def get_data(self):
        return bytes(self.data)

    FLAGS = {
        "UART":             (UART_OFFSET, 0, "Enable UART debugging"),
        "IDU Mode":         (0x1F0001, 0, "Enable IDU/Kiosk Mode"),
        "Safe Mode Boot":   (0x1F0002, 0, "Boot to Safe Mode"),
        "Update Mode":      (0x1F0003, 0, "Enable Update Mode"),
        "Memory Test":      (0x1F0004, 0, "Enable Memory Test on boot"),
        "ARCADE Mode":      (0x1F0005, 0, "Enable Arcade Mode"),
        "MANU Mode":        (0x1F0006, 0, "Enable MANU/Service Mode"),
        "Registry Recover": (0x1F0007, 0, "Enable Registry Recovery"),
        "Slow HDD Mode":    (0x1F0008, 0, "Enable Slow HDD Mode"),
        "Memory Budget":    (0x1F0009, 0, "Toggle Memory Budget Mode"),
        "Boot Param Dev":   (0x1F000A, 0, "Set Boot Parameter to Dev"),
        "Boot Param Assist":(0x1F000B, 0, "Set Boot Parameter to Assist"),
        "Swap X/O":         (0x1F000C, 0, "Swap X and O buttons"),
        "Reset Resolution": (0x1F000D, 0, "Reset display resolution"),
        "RNG Test":         (0x1F000E, 0, "Enable RNG/Keystorage Test"),
    }

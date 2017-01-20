#!/usr/bin/env python
# drivecom - Phison USB flasher and utilities
# 04/21/2016
# Brandon Wilson
#
# I despise software licenses, and I despise thinking about them.
# I really do not care what you do with this, if anything, nor will I ever.
import argparse
import os
import re
import sys
import struct
import array
from enum import Enum
from binascii import b2a_qp, a2b_qp, hexlify, unhexlify
import random
import threading
import queue
import ctypes
import time

# Uncomment to enable debug output
# os.environ['PYUSB_DEBUG'] = 'debug'

# Try importing windll on Windows
use_win = True
try:
    from ctypes import windll
    import ctypes.wintypes as wintypes
except:
    use_win = False
    import fcntl

use_libusb = True
try:
    import usb.core
except:
    use_libusb = False

IOCTL_SCSI_PASS_THROUGH_DIRECT = 0x4D014
SENSE_LENGTH = 32
SCSI_TIMEOUT_SECS = 30
SG_IO = 0x2285
FILEACCESS_READWRITE = 0x03
FILESHARE_READWRITE = 0x03
FILEMODE_OPEN = 0x03
FILEATTRIBUTES_NOBUFFERING = 0x20000000
USB_MSD_CLASS = 0x08
USB_MSD_SUBCLASS = 0x06
USB_MSD_PROTOCOL = 0x50

if use_win:
    class SCSI_PASS_THROUGH_DIRECT(ctypes.Structure):
        _fields_ = [
            ('Length', wintypes.USHORT),
            ('ScsiStatus', wintypes.BYTE),
            ('PathId', wintypes.BYTE),
            ('TargetId', wintypes.BYTE),
            ('Lun', wintypes.BYTE),
            ('CdbLength', wintypes.BYTE),
            ('SenseInfoLength', wintypes.BYTE),
            ('DataIn', wintypes.BYTE),
            ('DataTransferLength', wintypes.ULONG),
            ('TimeOutValue', wintypes.ULONG),
            ('DataBuffer', ctypes.POINTER(ctypes.c_char)),
            ('SenseInfoOffset', wintypes.ULONG),
            ('Cdb', wintypes.BYTE * 16)
            ]

    class SCSI_PASS_THROUGH_DIRECT_WITH_BUFFER(ctypes.Structure):
        _fields_ = [
            ('sptd', SCSI_PASS_THROUGH_DIRECT),
            ('sense', wintypes.BYTE * 32)
            ]
else:
    class scsi_args(ctypes.Structure):
        _fields_ = [
            ('interface_id', ctypes.c_int),
            ('dxfer_direction', ctypes.c_int),
            ('cmd_len', ctypes.c_ubyte),
            ('mx_sb_len', ctypes.c_ubyte),
            ('iovec_count', ctypes.c_ushort),
            ('dxfer_len', ctypes.c_uint),
            ('dxferp', ctypes.POINTER(ctypes.c_char)),
            ('cmdp', ctypes.c_char_p),
            ('sbp', ctypes.POINTER(ctypes.c_char)),
            ('timeout', ctypes.c_uint),
            ('flags', ctypes.c_uint),
            ('pack_id', ctypes.c_int),
            ('usr_ptr', ctypes.POINTER(ctypes.c_char)),
            ('status', ctypes.c_ubyte),
            ('masked_status', ctypes.c_ubyte),
            ('msg_status', ctypes.c_ubyte),
            ('sb_len_wr', ctypes.c_ubyte),
            ('host_status', ctypes.c_ushort),
            ('driver_status', ctypes.c_ushort),
            ('resid', ctypes.c_int),
            ('duration', ctypes.c_uint),
            ('info', ctypes.c_uint)
        ]

class find_msd_device(object):
    def __call__(self, device):
        try:
            for cfg in device:
                intf = None
                try:
                    intf = usb.util.find_descriptor(cfg, bInterfaceClass=USB_MSD_CLASS,
                                                    bInterfaceSubClass=USB_MSD_SUBCLASS,
                                                    bInterfaceProtocol=USB_MSD_PROTOCOL)
                    if intf is not None:
                        return True
                except:
                    pass
        except:
            pass
        return False

class FlashDrive(object):
    @classmethod
    def fromdevice(cls, device):
        ret = FlashDrive()
        ret.device = device
        return ret

    @classmethod
    def frompath(cls, path):
        ret = FlashDrive()
        
        if use_win:
            ret.device_handle = windll.kernel32.CreateFileW("\\\\.\\" + path + ":", FILEACCESS_READWRITE,
                                                            FILESHARE_READWRITE, None, FILEMODE_OPEN,
                                                            FILEATTRIBUTES_NOBUFFERING, None);
        else:
            ret.device_handle = open(path, 'r')

        return ret

    def __init__(self):
        self.device_handle = None
        self.device = None
        self.condition = None
        self.data_remaining = 0
        self.incoming_data = None

    def detach_kernel_driver(self):
        print('Detaching claimed interface(s)')
        c = 1
        for config in self.device:
            print('\tChecking Config {} Interfaces {}:'.format(c, config.bNumInterfaces))
            for i in range(config.bNumInterfaces):
                if self.device.is_kernel_driver_active(i):
                    self.device.detach_kernel_driver(i)
                    print('\t\tDetaching interface #{}'.format(i))
                else:
                    print('\t\tInterface #{} not claimed'.format(i))
            c += 1

    def initialize(self):
        if self.device is not None:
            if use_libusb and not use_win:
                self.detach_kernel_driver()

            self.device.set_configuration()
            cfg = self.device.get_active_configuration()
            intf = usb.util.find_descriptor(cfg, bInterfaceClass=USB_MSD_CLASS,
                                            bInterfaceSubClass=USB_MSD_SUBCLASS,
                                            bInterfaceProtocol=USB_MSD_PROTOCOL)
            self.ep_read = usb.util.find_descriptor(intf,
                                                   custom_match = \
                                                       lambda e: \
                                                       usb.util.endpoint_direction(e.bEndpointAddress) == \
                                                       usb.util.ENDPOINT_IN)
            self.ep_write = usb.util.find_descriptor(intf,
                                                    custom_match = \
                                                        lambda e: \
                                                        usb.util.endpoint_direction(e.bEndpointAddress) == \
                                                        usb.util.ENDPOINT_OUT)

            self.init_threads()

    def init_threads(self):
        thread = threading.Thread(name="Handle_MSD_Data", target=FlashDrive.handle_msd_data, args=(self,))
        thread.daemon = True
        thread.start()

    def send_scsi_command(self, cmd, data):
        out_direction = isinstance(data, array.array) or isinstance(data, bytes)

        if self.device is not None:
            if self.condition is None:
                self.condition = threading.Condition()
            self.condition.acquire()

            if out_direction:
                dir = 0x00
                length = len(data)
                self.data_remaining = 0
            else:
                dir = 0x80
                length = data
                self.data_remaining = length
            sequence = random.randint(1, 0xFFFFFFFF)
            FlashDrive.send_msd_data(self, [0x55, 0x53, 0x42, 0x43, (sequence >> 24) & 0xFF, (sequence >> 16) & 0xFF,
                                            (sequence >> 8) & 0xFF, sequence & 0xFF,
                                            (length >> 24) & 0xFF, (length >> 16) & 0xFF,
                                            (length >> 8) & 0xFF, length & 0xFF,
                                            dir, 0x00, len(cmd)] + cmd + ([0] * (16 - len(cmd))))
            if out_direction:
                FlashDrive.send_msd_data(self, data)
            self.condition.wait()
            ret = self.incoming_data
            self.incoming_data = None
            self.condition.release()

            if self.csw[len(self.csw)-1] != 0:
                return None
            else:
                return ret
        elif use_win:
            scsi = SCSI_PASS_THROUGH_DIRECT_WITH_BUFFER()
            scsi.sptd.Length = ctypes.sizeof(scsi.sptd)
            scsi.sptd.TimeOutValue = SCSI_TIMEOUT_SECS
            scsi.sptd.SenseInfoOffset = SCSI_PASS_THROUGH_DIRECT_WITH_BUFFER.sense.offset
            scsi.sptd.SenseInfoLength = ctypes.sizeof(scsi.sense)
            scsi.sptd.CdbLength = len(cmd)
            scsi.sptd.Cdb = (ctypes.c_byte * 16)(*cmd)
            scsi.sptd.DataIn = 0
            scsi.sptd.DataTransferLength = 0
            if out_direction:
                scsi.sptd.DataBuffer = ctypes.cast(data, ctypes.POINTER(ctypes.c_char))
                scsi.sptd.DataTransferLength = len(data)
            else:
                scsi.sptd.DataIn = 1
                scsi.sptd.DataTransferLength = data
                scsi.sptd.DataBuffer = ctypes.cast(ctypes.create_string_buffer(data), ctypes.POINTER(ctypes.c_char))

            p_scsi = ctypes.pointer(scsi)
            ret = windll.kernel32.DeviceIoControl(self.device_handle,IOCTL_SCSI_PASS_THROUGH_DIRECT, p_scsi,
                                                  ctypes.sizeof(scsi), p_scsi, ctypes.sizeof(scsi), None, None)
            if ret > 0 and scsi.sptd.ScsiStatus == 0:
                return [scsi.sptd.DataBuffer[i][0] for i in range(scsi.sptd.DataTransferLength)]
            else:
                raise AssertionError("Failure sending SCSI command (IOCTL {}, SCSI status {})".format(hex(ret),
                                                                                                      hex(scsi.sptd.ScsiStatus)))
        else:
            sense = ctypes.create_string_buffer(SENSE_LENGTH)
            args = scsi_args()
            args.interface_id = ord('S')
            args.cmdp = bytes(cmd)
            args.cmd_len = len(cmd)
            args.sbp = ctypes.cast(sense, ctypes.POINTER(ctypes.c_char))
            args.mx_sb_len = SENSE_LENGTH
            args.timeout = SCSI_TIMEOUT_SECS * 1000
            args.dxfer_direction = 0x00

            if out_direction:
                    args.dxferp = ctypes.cast(data, ctypes.POINTER(ctypes.c_char))
                    args.dxfer_len = len(data)
            else:
                    args.dxfer_direction = 0x01
                    args.dxferp = ctypes.cast(ctypes.create_string_buffer(data), ctypes.POINTER(ctypes.c_char))
                    args.dxfer_len = data

            ret = fcntl.ioctl(self.device_handle, SG_IO, args)
            if ret != 0:
                raise AssertionError("Failure sending SCSI command (IOCTL {})".format(hex(ret)))
            else:
                return [args.dxferp[i][0] for i in range(args.dxfer_len)]

    def transfer_file_data(self, data, header, body):
        size = len(data) - 1024

        # Send header
        FlashDrive.send_scsi_command(self, [0x06, 0xB1, header, 0x00, 0x00, 0x00, 0x00, 0x00,
                                            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], data[0:0x200])

        # Get response
        response = FlashDrive.send_scsi_command(self, [0x06, 0xB0, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00,
                                                       0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], 8)
        if len(response) == 0 or response[0] != 0x55:
            raise AssertionError("Header not accepted")

        # Send body
        address = 0
        while size > 0:
            if size > 0x8000:
                chunk_size = 0x8000
            else:
                chunk_size = size

            cmd_address = address >> 9
            cmd_chunk = chunk_size >> 9
            FlashDrive.send_scsi_command(self, [0x06, 0xB1, body, (cmd_address >> 8) & 0xFF, cmd_address & 0xFF,
                                                0x00, 0x00, (cmd_chunk >> 8) & 0xFF, cmd_chunk & 0xFF,
                                                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
                                         data[0x200 + address : 0x200 + address + chunk_size])

            # Get response
            response = FlashDrive.send_scsi_command(self, [0x06, 0xB0, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00,
                                                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], 8)
            if len(response) == 0 or response[0] != 0xA5:
                raise AssertionError("Body not accepted")

            address += chunk_size
            size -= chunk_size

    def handle_msd_data(self):
        while True:
            buffer = FlashDrive.receive_msd_data(self, 0)
            if self.data_remaining > 0:
                if self.incoming_data is not None:
                    self.incoming_data += buffer
                else:
                    self.incoming_data = buffer
                self.data_remaining -= len(buffer)
            elif self.data_remaining <= 0:
                self.csw = buffer
                self.condition.acquire()
                self.condition.notify()
                self.condition.release()

    def send_msd_data(self, data):
        self.ep_write.write(data)

    def receive_msd_data(self, timeout):
        return self.ep_read.read(self.ep_read.wMaxPacketSize, timeout)

    def find_all():
        ret = usb.core.find(find_all=True, custom_match = find_msd_device())
        r = []
        for i, item in enumerate(ret):
            r.append(FlashDrive.fromdevice(item))
        return r

def find_drive(args):
    device = None
    ids_specified = args.device_ids is not None and len(args.device_ids) == 2
    loc_specified = args.device_loc is not None and len(args.device_loc) == 2
    path_specified = args.path is not None and len(args.path) > 0

    if path_specified:
        # drive path
        device = FlashDrive.frompath(args.path)
    else:
        # vid and pid, or bus and address
        devices = FlashDrive.find_all()
        for item in devices:
            if ids_specified:
                if item.device.idVendor == args.device_ids[0] and item.device.idProduct == args.device_ids[1]:
                    device = item
                    break
            elif loc_specified:
                if item.device.bus == args.device_loc[0] and item.device.address == args.device_loc[1]:
                    device = item
                    break

    if device is None:
        # If we were trying to use a specific one, freak out
        if ids_specified or loc_specified or path_specified:
            print("Specified USB drive not detected!")
        else:
            print("No USB drive specified!")
        exit()
    else:
        print("Using USB drive:")
        if device.device is not None:
            print("\tVendor ID: {}, Product ID: {}".format(hex(device.device.idVendor), hex(item.device.idProduct)))
            print("\tBus: {}, Address: {}\n".format(hex(device.device.bus), hex(device.device.address)))
        else:
            print("\tPath: {}\n".format(args.path))
    device.initialize()

    return device

def drivecom_list_devices(args):
    if use_libusb:
        i = 1
        devices = FlashDrive.find_all()
        print("{} libusb mass storage device{} found.\r\n".format(len(devices), "s" if len(devices) != 1 else ""))
        for item in devices:
            print("Device {}:".format(i))
            print("\tVendor ID: {}, Product ID: {}".format(hex(item.device.idVendor), hex(item.device.idProduct)))
            print("\tBus: {}, Address: {}".format(hex(item.device.bus), hex(item.device.address)))
            i += 1
    else:
        print("libusb is not set up or installed properly.")

def drivecom_get_info(args):
    device = find_drive(args)
    ret = device.send_scsi_command([0x06, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01], 512 + 16)
    if ret is not None:
        mode = ''.join(chr(x) for x in ret[0xA0:0xA8])
        print("Image version: {:02X}.{:02X}.{:02X}".format(ret[0x94], ret[0x95], ret[0x96]))
        print("Chip type: {:02X}{:02X}".format(ret[0x17E], ret[0x17F]))
        ret = device.send_scsi_command([0x06, 0x56, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], 512)
        print("Flash chip ID: " + ''.join(format(x, '02X') for x in ret[0:6]))
        if mode == " PRAM   ":
            print("Mode: Boot")
        elif mode == " FW BURN":
            print("Mode: Burner")
        elif mode == " HV TEST":
            print("Mode: Hardware Test/Verify")
        else:
            print("Mode: Firmware")
    else:
        print("No/Invalid response received")

def drivecom_transfer_file(args):
    device = find_drive(args)

    print("Opening file {}...".format(args.file_name))
    with open(args.file_name, mode='rb') as file:
        data = file.read()
    print("File data read.")

    print("Transferring file to RAM...")
    device.transfer_file_data(data, 0x03, 0x02)
    print("File transfer is complete.")

def drivecom_flash_firmware(args):
    device = find_drive(args)

    print("Opening firmware image {}...".format(args.file_name))
    with open(args.file_name, mode='rb') as file:
        data = file.read()
    print("Firmware image read.")

    print("Transferring firmware...")
    device.transfer_file_data(data, 0x01, 0x00)
    device.send_scsi_command([0x06, 0xEE, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], 64 + 8)
    time.sleep(2)
    device.transfer_file_data(data, 0x03, 0x02)
    device.send_scsi_command([0x06, 0xEE, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00], 64 + 8)
    time.sleep(2)
    device.send_scsi_command([0x06, 0xEE, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], 64 + 8)
    time.sleep(2)
    device.send_scsi_command([0x06, 0xEE, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00], 64 + 8)
    time.sleep(2)

    print("Executing...")
    device.send_scsi_command([0x06, 0xB3, 0x00,
                              0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], 0)
    time.sleep(2)

    print("Firmware transfer is complete.")

def drivecom_execute_ram(args):
    device = find_drive(args)

    print("Running executable in RAM...")
    flags = 0x00
    if args.flags is not None:
        flags = args.flags
    device.send_scsi_command([0x06, 0xB3, flags,
                              0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], 0)
    print("The command has completed.")

def drivecom_set_boot(args):
    device = find_drive(args)

    print("Please be aware that this command may fail or time out.\n")
    print("Setting boot/test mode...")
    try:
        flags = 0x00
        if args.flags is not None:
            flags = args.flags

        device.send_scsi_command([0x06, 0xBF, flags,
                                  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], 0)
        print("The command has completed.\n")
    except Exception as e:
        print("The command has failed, which may or may not be normal.\n")
    print("If the device is not accessible, please be patient and wait for the device to re-enumerate.")
    print("If it does not re-enumerate, try shorting the NAND pins while plugging in the device instead.")

def drivecom_test(args):
    device = find_drive(args)
    ret = device.send_scsi_command([0x06, 0x77, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], 512)
    print("Data: " + str(ret))
    print("Done.")

def drivecom_erase_firmware(args):
    device = find_drive(args)
    print("Erasing firmware (takes many seconds)...")
    device.send_scsi_command([0x06, 0xB7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], 0)
    print("Done.")

def drivecom_read_memory(args):
    device = find_drive(args)
    print("Reading memory at address {:04X}...".format(args.address))
    data = device.send_scsi_command([0x06, 0x05, 0x52, 0x41, (args.address >> 8) & 0xFF, args.address & 0xFF,
                                     0x00, 0x00, 0x00, 0x00, 0x00, 0x00], 512 + 16)
    print("Value read: " + str(data[0:args.size]))

def drivecom_write_memory(args):
    device = find_drive(args)
    print("Writing value {:02X} to address {:04X}...".format(args.value, args.address))
    device.send_scsi_command([0x06, 0x0C, 0x00, 0x50, 0x68, 0x49, (args.address >> 8) & 0xFF, args.address & 0xFF,
                              args.value & 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], 4)
    print("Value written.")

def drivecom_split_firmware(args):
    print("Splitting firmware image {}...".format(args.file_name))

    with open(args.file_name, "rb") as file:
        if args.header_file is not None:
            print("Writing header to {}...".format(args.header_file))
            with open(args.header_file, "wb") as output:
                output.write(file.read(args.header_size))
        else:
            file.seek(args.header_size)
        
        chunk = file.read(args.first_chunk_size)
        i = 0
        while len(chunk) >= args.chunk_size:
            if i == 0:
                file_name = "base.bin"
                if args.prefix is not None:
                    file_name = args.prefix + file_name
                print("Writing base page to {}...".format(file_name))
            else:
                file_name = "page{:02X}.bin".format(i)
                if args.prefix is not None:
                    file_name = args.prefix + file_name
                print("Writing page {:02X} to {}...".format(i, file_name))

            with open(file_name, "wb") as output:
                output.write(chunk)
            i += 1
            chunk = file.read(args.chunk_size)
        if len(chunk) > 0 and args.footer_file is not None:
            print("Writing footer to {}...".format(args.footer_file))
            with open(args.footer_file, "wb") as output:
                output.write(chunk)

    print("Split complete.")

def auto_int(x):
    return int(x, 0)

def add_device_arguments(subparser):
    group = subparser.add_mutually_exclusive_group()
    group.add_argument("--device-loc", nargs=2, type=auto_int, metavar=("bus","address"),
                       help="USB device location (bus and address)")
    group.add_argument("--device-ids", nargs=2, type=auto_int, metavar=("vendor_id", "product_id"),
                       help="USB device vendor ID and product ID")
    group.add_argument("--path", help="USB device path (drive letter on Windows)")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Phison USB flasher and utilities",
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    subparsers = parser.add_subparsers(dest="cmd", help="The action to perform.")
    formatter = argparse.RawDescriptionHelpFormatter
    device_required = "\r\n\r\nYou should specify a USB device with this command, "
    device_required += "either by vendor and product ID, by bus and address, or by device path (drive letter)."

    # Split firmware image
    help = "Splits firmware image into separate pieces for easy disassembly."
    subparser = subparsers.add_parser("split_firmware", help=help, description=help, formatter_class=formatter)
    subparser.add_argument("file_name", help="firmware image file name")
    subparser.add_argument("--header-file", help="header file name")
    subparser.add_argument("--footer-file", help="footer file name")
    subparser.add_argument("--prefix", help="split file name prefix")
    subparser.add_argument("--header-size", help="header size", type=auto_int, default=0x200)
    subparser.add_argument("--first-chunk-size", help="size of first chunk", type=auto_int, default=0x8000)
    subparser.add_argument("--chunk-size", help="size of chunks beyond first", type=auto_int, default=0x4000)
    subparser.set_defaults(func=drivecom_split_firmware)

    # List libusb devices
    help = "Lists USB mass storage devices accessible via libusb and how to specify them."
    subparser = subparsers.add_parser("list_devices", help=help, description=help, formatter_class=formatter)
    subparser.set_defaults(func=drivecom_list_devices)

    # Get information
    help = "Retrives and displays information about the specified device."
    description = help + device_required
    subparser = subparsers.add_parser("get_info", help=help, description=description, formatter_class=formatter)
    add_device_arguments(subparser)
    subparser.set_defaults(func=drivecom_get_info)

    # Set boot mode
    help = "Switches the specified device to boot/test mode."
    description = help + device_required
    subparser = subparsers.add_parser("set_boot", help=help, description=description, formatter_class=formatter)
    add_device_arguments(subparser)
    subparser.add_argument("--flags", type=auto_int, help="command flags")
    subparser.set_defaults(func=drivecom_set_boot)

    # Test
    help = "Executes test code."
    description = help + device_required
    subparser = subparsers.add_parser("test", help=help, description=description, formatter_class=formatter)
    add_device_arguments(subparser)
    subparser.set_defaults(func=drivecom_test)

    # Read XDATA memory
    help = "Reads memory."
    description = help + device_required
    subparser = subparsers.add_parser("read_memory", help=help, description=description, formatter_class=formatter)
    add_device_arguments(subparser)
    subparser.add_argument("address", type=auto_int, help="memory address")
    subparser.add_argument("--size", type=auto_int, default=1, help="number of bytes to retrieve")
    subparser.set_defaults(func=drivecom_read_memory)

    # Write XDATA memory
    help = "Writes memory."
    description = help + device_required
    subparser = subparsers.add_parser("write_memory", help=help, description=description, formatter_class=formatter)
    add_device_arguments(subparser)
    subparser.add_argument("address", type=auto_int, help="memory address")
    subparser.add_argument("value", type=auto_int, help="value to write")
    subparser.set_defaults(func=drivecom_write_memory)

    # Erase firmware
    help = "Erases firmware area of NAND."
    subparser = subparsers.add_parser("erase_firmware", help=help, description=description, formatter_class=formatter)
    add_device_arguments(subparser)
    subparser.set_defaults(func=drivecom_erase_firmware)

    # Flash firmware
    help = "Flashes firmware file."
    description = help + device_required
    subparser = subparsers.add_parser("flash_firmware", help=help, description=description, formatter_class=formatter)
    add_device_arguments(subparser)
    subparser.add_argument("file_name", help="path to firmware image")
    subparser.set_defaults(func=drivecom_flash_firmware)

    # Transfer file to RAM
    help = "Places code in RAM for future execution."
    description = help + device_required
    subparser = subparsers.add_parser("transfer_file", help=help, description=description, formatter_class=formatter)
    add_device_arguments(subparser)
    subparser.add_argument("file_name", help="path to file to transfer")
    subparser.set_defaults(func=drivecom_transfer_file)

    # Execute code in RAM
    help = "Executes code placed in RAM."
    description = help + device_required
    subparser = subparsers.add_parser("execute_ram", help=help, description=description, formatter_class=formatter)
    add_device_arguments(subparser)
    subparser.add_argument("--flags", type=auto_int, help="command flags")
    subparser.set_defaults(func=drivecom_execute_ram)

    # Handle the command
    args = parser.parse_args()
    header = parser.prog + " - " + parser.description
    print(header)
    print("-" * len(header))
    if args.cmd is not None:
        print("Handling command '" + args.cmd + "'...\r\n")
        args.func(args)
    else:
        print("Nothing to do (no command specified), exiting...")

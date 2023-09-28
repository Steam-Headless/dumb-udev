#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import asyncio
import logging
import os
import signal
import stat
import time
import socket
import struct

import pyudev

from murmurhash2 import murmurhash2

# Constants for NETLINK socket and UDEV monitoring
NETLINK_KOBJECT_UEVENT = 15
UDEV_MONITOR_UDEV = 2
UDEV_MONITOR_MAGIC = 0xfeedcafe

supported_sys_device_paths = [
    "/sys/devices/virtual/input"
]
udev_paths = [
    ("/dev/input", 0o755),
    ("/run/udev", 0o755),
    ("/run/udev/data", 0o755),
]


class DumbUdevRelay:
    def __init__(self, loop: asyncio.AbstractEventLoop):
        self.loop = loop
        self.context: pyudev.Context | None = None
        self.kmonitor: pyudev.Monitor | None = None

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        self.stop()

    def start(self):
        """Start the DumbUdevRelay."""
        logging.info("Starting DumbUdevRelay...")
        self.ensure_udev_paths()
        self.context = pyudev.Context()
        self.kmonitor = pyudev.Monitor.from_netlink(self.context, "kernel")
        self.kmonitor.filter_by("input")
        self.kmonitor.start()
        self.umonitor = pyudev.Monitor.from_netlink(self.context, "udev")
        self.umonitor.start()
        self.loop.add_reader(self.kmonitor.fileno(), self.handle_kernel_event, self.kmonitor)
        logging.info("DumbUdevRelay running.")

    def stop(self):
        """Stop the DumbUdevRelay and clean up resources."""
        logging.info("Stopping DumbUdevRelay...")
        try:
            if self.kmonitor is not None:
                self.kmonitor = None
                self.context = None
            logging.info("DumbUdevRelay stopped.")
        except Exception as e:
            logging.error(f"An error occurred during shutdown: {str(e)}")

    def ensure_udev_paths(self):
        # Create directories and set permissions
        for path, permissions in udev_paths:
            if not os.path.exists(path):
                os.makedirs(path, mode=permissions)
            else:
                os.chmod(path, permissions)

        # Create the control file as a FIFO with the desired permissions
        # if not os.path.exists("/run/udev/control"):
        #    os.mkfifo("/run/udev/control", mode=0o755)
        if not os.path.exists("/run/udev/control"):
            with open("/run/udev/control", "w"):
                pass  # Create an empty control file

    def handle_kernel_event(self, monitor: pyudev.Monitor):
        # Fetch the device announced
        device = monitor.poll(0)
        if device is None:
            return
        # Ensure that the device is supported
        if not any(device.sys_path.startswith(sys_path) for sys_path in supported_sys_device_paths):
            # TODO: Change to debug log
            logging.info(f"Ignoring kernel event: {device.sys_path} action: {device.action}")
            return

        # Process the add or removal of the device
        logging.info(f"Received kernel event: {device.sys_path} action: {device.action}")
        if device.action == "add":
            dev_from_sys_path = pyudev.Devices.from_sys_path(self.context, device.sys_path)
            asyncio.ensure_future(self.add_device(device))
        elif device.action == "remove":
            asyncio.ensure_future(self.remove_device(device))

    def manage_device_node(self, action, device_node: str, device_number: int):
        if action == "add":
            try:
                st = os.stat(device_node)
                if st.st_rdev == device_number:
                    logging.info(
                        f"The device node {device_node} already exists has the correct major and minor numbers.")
                    return
                else:
                    # Remove current device node
                    logging.info(
                        f"The device node {device_node} already exists but does not have the correct major and minor numbers. Removing existing node.")
                    os.remove(device_node)
            except FileNotFoundError:
                logging.info(f"The device node {device_node} does not yet exist.")
            except Exception as e:
                logging.info(f"An error occurred: {e}")
            # Create a device node
            logging.info(f"Creating device node {device_node}.")
            os.mknod(device_node, stat.S_IFCHR | 0o666, device_number)
        elif action == "remove":
            if os.path.exists(device_node):
                os.remove(device_node)

    def manage_udev_data(self, action: str, device, init_usec=None):

        def build_data_content(dev):
            # 1) /run/udev/data/c13:0
            # ```
            # I:2463480226353
            # E:ID_INPUT=1
            # E:ID_INPUT_JOYSTICK=1
            # E:ID_SERIAL=noserial
            # G:seat
            # G:uaccess
            # ```
            #
            # 2) /run/udev/data/c13:79
            # ```
            # I:2463480236889
            # E:ID_INPUT=1
            # E:ID_INPUT_JOYSTICK=1
            # E:ID_SERIAL=noserial
            # G:seat
            # G:uaccess
            # ```
            #
            # 3) /run/udev/data/+input:input2383
            # ```
            # I:2463480225689
            # E:ID_INPUT=1
            # E:ID_INPUT_JOYSTICK=1
            # E:ID_SERIAL=noserial
            # G:seat
            # ```
            # Create the file content
            file_content = [
                f"I:{init_usec}\n",
                "E:ID_INPUT=1\n",
                "E:ID_INPUT_JOYSTICK=1\n",
                "E:ID_SERIAL=noserial\n",
            ]
            file_content.append("G:seat\n")
            if dev.device_node is not None:
                # Devices also need uaccess
                file_content.append("G:uaccess\n")
                # file_content.append("Q:seat\n")
                # file_content.append("Q:uaccess\n")
                # file_content.append("V:1\n")
            return file_content

        def get_udev_data_path(dev):
            if dev.device_node is None:
                # This is an input event rather than the device itself. We handle these differently.
                return os.path.join("/run/udev/data", f"+input:{dev.sys_name}")
            # Return path for device.
            major = os.major(dev.device_number)
            minor = os.minor(dev.device_number)
            return os.path.join("/run/udev/data", f"c{major}:{minor}")

        def write_udev_data_content(path, file_content_list):
            with open(path, "w") as file:
                file.write("".join(file_content_list))
            os.chmod(path, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH)

        def remove_udev_data(path):
            if os.path.exists(path):
                os.remove(path)

        # Create the required files in /run/udev/data
        path = get_udev_data_path(device)
        if action == "add":
            content_list = build_data_content(device)
            write_udev_data_content(path, content_list)
            logging.info(f"Added udev data '{path}'.")
        elif action == "remove":
            remove_udev_data(path)
            logging.info(f"Removed udev data '{path}'.")

    def send_custom_udev_event(self, action: str, device, init_usec=None):
        def build_header(proplen, subsys, devtype, taghash):
            header_fmt = "8s8I"
            header_size = struct.calcsize(header_fmt)
            subsys_hash = 0
            devtype_hash = 0

            if subsys:
                subsys_hash = murmurhash2(subsys.encode(), 0)

            if devtype:
                devtype_hash = murmurhash2(devtype.encode(), 0)

            tag_low = socket.htonl(taghash & 0xffffffff)
            tag_high = socket.htonl(taghash >> 32)

            return struct.pack(header_fmt, b"libudev", socket.htonl(UDEV_MONITOR_MAGIC),
                               header_size, header_size, proplen, subsys_hash, devtype_hash,
                               tag_low, tag_high)

        def bloom_hash(tag):
            bits = 0
            hash = murmurhash2(tag.encode(), 0)
            bits = bits | 1 << (hash & 63)
            bits = bits | 1 << ((hash >> 6) & 63)
            bits = bits | 1 << ((hash >> 12) & 63)
            bits = bits | 1 << ((hash >> 18) & 63)
            return bits

        def build_message(dev):
            subsys = dev.subsystem
            devtype = dev.device_type

            # Add properties list
            proplist = bytearray()
            for p in dev.properties:
                proppair = p + "=" + dev.properties[p]
                proplist = proplist + proppair.encode() + bytes([0])

            # Add some additional properties
            proplist = proplist + "ID_INPUT=1".encode() + bytes([0])
            proplist = proplist + "ID_INPUT_JOYSTICK=1".encode() + bytes([0])
            proplist = proplist + "ID_SERIAL=noserial".encode() + bytes([0])
            if init_usec is not None:
                proplist = proplist + f"USEC_INITIALIZED={init_usec}".encode() + bytes([0])

            # Add tags
            tag_string = ":seat:"
            if dev.device_node is not None:
                tag_string = ":uaccess:seat:"
            proplist = proplist + f"TAGS={tag_string}".encode() + bytes([0])

            tag_hash = 0
            for t in dev.tags:
                tag_hash = tag_hash | bloom_hash(t)

            hdr = build_header(len(proplist), subsys, devtype, tag_hash)

            return hdr + proplist

        def send_message(message):
            sendfd = socket.socket(socket.AF_NETLINK, socket.SOCK_DGRAM, NETLINK_KOBJECT_UEVENT)
            try:
                sendfd.sendto(message, (0, UDEV_MONITOR_UDEV))
            except ConnectionRefusedError:
                pass
            sendfd.close()

        udev_message = build_message(device)
        send_message(udev_message)
        logging.info(f"Sent custom udev event message for input '{device.sys_path}'.")

    async def add_device(self, device: pyudev.Device):
        # Add a microseconds timestring for stamping the events
        time_now = time.time()
        # TODO: Just use the USEC_INITIALIZED value
        init_usec = int(time_now * 1_000)

        # Check if this was the device or an input event
        if device.device_node is not None:
            # Create the device node if it does not yet exist
            self.manage_device_node("add", device.device_node, device.device_number)

        # Create the udev data files
        self.manage_udev_data("add", device, init_usec)

        # Send a modified udev event message so applications subscribed to libudev will see the newly added device
        self.send_custom_udev_event("add", device, init_usec)
        await asyncio.sleep(0.1)

        # Add the device to our sources dict
        if device.device_node is None:
            device_name = device.get("NAME").strip('"')
            logging.info(f"Finished adding new input {device.sys_path} with name '{device_name}'.")
        else:
            device_name = device.parent.get("NAME").strip('"')
            logging.info(f"Finished adding new device {device.device_node} for input '{device_name}'.")

    async def remove_device(self, device):
        if device.device_node is not None:
            # Remove the device node if it exist
            self.manage_device_node("remove", device.device_node, device.device_number)
            await asyncio.sleep(0.1)

        # Create the udev data files
        self.manage_udev_data("remove", device)

        # Send a modified udev event message so libudev applications are told that the device was removed
        self.send_custom_udev_event("remove", device)
        await asyncio.sleep(0.1)

        logging.info(f"Removed input '{device.sys_path}'.")


async def shutdown(signal_name, relay: DumbUdevRelay, loop: asyncio.AbstractEventLoop):
    logging.info(f"Received exit signal {signal_name}...")
    relay.stop()
    loop.stop()


def main():
    logging.basicConfig(level=logging.INFO)
    loop = asyncio.new_event_loop()

    with DumbUdevRelay(loop) as relay:
        signals = (signal.SIGHUP, signal.SIGTERM, signal.SIGINT)
        for s in signals:
            loop.add_signal_handler(
                s, lambda s=s: asyncio.create_task(shutdown(s, relay, loop))
            )
        try:
            relay.start()
            loop.run_forever()
        finally:
            loop.stop()


if __name__ == "__main__":
    main()

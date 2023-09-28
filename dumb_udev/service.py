#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations

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


class DumbUdevRelay:
    """Relay for udev events to emulate the behavior of libudev.

    This class provides functionality to relay udev events and create the necessary
    device files and data files for udev event processing.

    Attributes:
        loop (asyncio.AbstractEventLoop): The asyncio event loop.
        context (pyudev.Context | None): The udev context.
        kmonitor (pyudev.Monitor | None): The udev kernel monitor.
        log (logging.Logger): The logger for this class.
    """

    def __init__(self, loop: asyncio.AbstractEventLoop):
        """Initialize the DumbUdevRelay.

        Args:
            loop (asyncio.AbstractEventLoop): The asyncio event loop.
        """
        self.loop = loop
        self.context: pyudev.Context | None = None
        self.kmonitor: pyudev.Monitor | None = None
        self.log = logging.getLogger(__class__.__name__)

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        self.stop()

    def start(self):
        """Start the DumbUdevRelay."""
        self.log.info(f"Starting monitors...")
        self.ensure_udev_paths()
        self.context = pyudev.Context()
        self.kmonitor = pyudev.Monitor.from_netlink(self.context, "kernel")
        self.kmonitor.filter_by("input")
        self.kmonitor.start()
        self.loop.add_reader(self.kmonitor.fileno(), self.handle_kernel_event, self.kmonitor)
        self.log.info(f"Monitors running.")

    def stop(self):
        """Stop the DumbUdevRelay and clean up resources."""
        self.log.info(f"Stopping monitors...")
        try:
            if self.kmonitor is not None:
                self.kmonitor = None
                self.context = None
            self.log.info(f"Monitors stopped.")
        except Exception as e:
            self.log.error(f"An error occurred during shutdown: {str(e)}")

    @staticmethod
    def ensure_udev_paths():
        """Ensure the existence of udev-related paths and set permissions."""
        # Create directories and set permissions
        udev_paths = [
            ("/dev/input", 0o755),
            ("/run/udev", 0o755),
            ("/run/udev/data", 0o755),
        ]
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
        """Handle kernel events.

        :param monitor: The kernel event monitor.
        :return:
        """
        # Fetch the device announced
        device = monitor.poll(0)
        if device is None:
            return
        # Ensure that the device is supported
        supported_sys_device_paths = [
            "/sys/devices/virtual/input"
        ]
        if not any(device.sys_path.startswith(sys_path) for sys_path in supported_sys_device_paths):
            self.log.debug(f"Ignoring kernel event: {device.sys_path} action: {device.action}")
            return

        # Process the add or removal of the device
        self.log.info(f"Received kernel event: {device.sys_path} action: {device.action}")
        if device.action == "add":
            dev_from_sys_path = pyudev.Devices.from_sys_path(self.context, device.sys_path)
            asyncio.ensure_future(self.add_device(device))
        elif device.action == "remove":
            asyncio.ensure_future(self.remove_device(device))

    def manage_device_node(self, action: str, device_node: str, device_number: int):
        """Manage the creation or removal of a device node.

        This function handles the creation or removal of a device node in the filesystem.
        It checks if the device node already exists and has the correct major and minor numbers.
        If the device node doesn't exist or doesn't have the correct numbers, it will be created.

        :param action: The action to perform, either "add" or "remove."
        :param device_node: The path to the device node.
        :param device_number: The major and minor numbers for the device.
        :return:
        """
        if action == "add":
            try:
                st = os.stat(device_node)
                if st.st_rdev == device_number:
                    self.log.info(
                        f"The device node {device_node} already exists has the correct major and minor numbers.")
                    return
                else:
                    # Remove current device node
                    self.log.info(
                        f"The device node {device_node} already exists but does not have the correct major and minor numbers. Removing existing node.")
                    os.remove(device_node)
            except FileNotFoundError:
                self.log.info(f"The device node {device_node} does not yet exist.")
            except Exception as e:
                self.log.info(f"An error occurred: {e}")
            # Create a device node
            self.log.info(f"Creating device node {device_node}.")
            os.mknod(device_node, stat.S_IFCHR | 0o666, device_number)
        elif action == "remove":
            if os.path.exists(device_node):
                os.remove(device_node)

    def manage_udev_data(self, action: str, device: pyudev.Device):
        """Manage the creation or removal of udev data files.

        This function handles the creation or removal of udev data files for a given device.
        It generates the content of these data files and writes them to the appropriate location
        in the filesystem based on the device's properties.

        :param action: The action to perform, either "add" or "remove."
        :param device: The device for which udev data files are managed.
        :return:
        """

        def build_data_content(dev: pyudev.Device):
            """Adds udev data files as required.

            This inner function generates the content for the udev data files based on the
            properties of the provided device.

            EG:
                /run/udev/data/c13:0
                ```
                I:2463480226353
                E:ID_INPUT=1
                E:ID_INPUT_JOYSTICK=1
                E:ID_SERIAL=noserial
                G:seat
                G:uaccess
                ```

                /run/udev/data/c13:79
                ```
                I:2463480236889
                E:ID_INPUT=1
                E:ID_INPUT_JOYSTICK=1
                E:ID_SERIAL=noserial
                G:seat
                G:uaccess
                ```

                /run/udev/data/+input:input2383
                ```
                I:2463480225689
                E:ID_INPUT=1
                E:ID_INPUT_JOYSTICK=1
                E:ID_SERIAL=noserial
                G:seat
                ```

            :param dev: The device for which udev data files are generated.
            :return: A list of strings representing the content of the data files.
            """
            # Add a microseconds timestring for stamping the events
            time_now = time.time()
            # TODO: Just use the USEC_INITIALIZED value. Read from pyudev.Devices.from_sys_path
            init_usec = int(time_now * 1_000)
            # Create the file content
            file_content = [
                f"I:{init_usec}\n",
                "E:ID_INPUT=1\n",
                "E:ID_INPUT_JOYSTICK=1\n",
                "E:ID_SERIAL=noserial\n",
                "G:seat\n",
            ]
            if dev.device_node is not None:
                # Devices also need uaccess
                file_content.append("G:uaccess\n")
                # file_content.append("Q:seat\n")
                # file_content.append("Q:uaccess\n")
                # file_content.append("V:1\n")
            return file_content

        def get_udev_data_path(dev: pyudev.Device):
            """Determines the path to the udev/data file for this device

            :param dev: The device for which udev data files are generated.
            :return:
            """
            if dev.device_node is None:
                # This is an input event rather than the device itself. We handle these differently.
                return os.path.join("/run/udev/data", f"+input:{dev.sys_name}")
            # Return path for device.
            major = os.major(dev.device_number)
            minor = os.minor(dev.device_number)
            return os.path.join("/run/udev/data", f"c{major}:{minor}")

        def write_udev_data_content(data_path: str, file_content_list: list):
            """Write udev data content to a file.

            :param data_path: The path to the udev data file.
            :param file_content_list: A list of strings representing the content to be written.
            :return:
            """
            with open(data_path, "w") as file:
                file.write("".join(file_content_list))
            os.chmod(data_path, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH)

        def remove_udev_data(data_path):
            """Remove a udev data file if it exists.

            :param data_path: The path to the udev data file to be removed.
            :return:
            """
            if os.path.exists(data_path):
                os.remove(data_path)

        # Create the required files in /run/udev/data
        path = get_udev_data_path(device)
        if action == "add":
            content_list = build_data_content(device)
            write_udev_data_content(path, content_list)
            self.log.info(f"Added udev data '{path}'.")
        elif action == "remove":
            remove_udev_data(path)
            self.log.info(f"Removed udev data '{path}'.")

    def send_custom_udev_event(self, action: str, device: pyudev.Device):
        """Send a custom udev event message.

        This function constructs a custom udev event message and sends it to the
        NETLINK_KOBJECT_UEVENT socket for processing by libudev.

        :param action: The action to perform, either "add" or "remove."
        :param device: The device for which the custom udev event message is sent.
        :return:
        """

        def build_header(prop_len: int, subsys: str, dev_type: str, tag_hash: int):
            """Build the header for the custom udev event message.

            :param prop_len: Length of the properties list.
            :param subsys: The device subsystem.
            :param dev_type: The device type.
            :param tag_hash: Hash of device tags.
            :return:
            """
            header_fmt = "8s8I"
            header_size = struct.calcsize(header_fmt)
            subsys_hash = 0
            dev_type_hash = 0

            if subsys:
                subsys_hash = murmurhash2(subsys.encode(), 0)

            if dev_type:
                dev_type_hash = murmurhash2(dev_type.encode(), 0)

            tag_low = socket.htonl(tag_hash & 0xffffffff)
            tag_high = socket.htonl(tag_hash >> 32)

            return struct.pack(header_fmt, b"libudev", socket.htonl(UDEV_MONITOR_MAGIC),
                               header_size, header_size, prop_len, subsys_hash, dev_type_hash,
                               tag_low, tag_high)

        def bloom_hash(tag: str):
            """Compute a bloom hash for a given tag.

            :param tag: The tag to hash.
            :return:
            """
            bits = 0
            tag_hash = murmurhash2(tag.encode(), 0)
            bits = bits | 1 << (tag_hash & 63)
            bits = bits | 1 << ((tag_hash >> 6) & 63)
            bits = bits | 1 << ((tag_hash >> 12) & 63)
            bits = bits | 1 << ((tag_hash >> 18) & 63)
            return bits

        def build_message(dev: pyudev.Device):
            """Build the custom udev event message.

            :param dev: The device for which the message is constructed.
            :return:
            """
            subsys = dev.subsystem
            dev_type = dev.device_type

            # Build a properties list
            prop_list = bytearray()

            # If this is an "add" action, then re-read the device from the sys path to get missing information.
            if action == "add":
                seqnum = dev.properties.get("SEQNUM")
                prop_list = prop_list + f"ACTION={action}".encode() + bytes([0])
                prop_list = prop_list + f"SEQNUM={seqnum}".encode() + bytes([0])
                # Re-read device from sys path. Some information is missing from the initial poll device.
                dev = pyudev.Devices.from_sys_path(self.context, device.sys_path)

            # Add properties to list
            for p in dev.properties:
                prop_pair = p + "=" + dev.properties[p]
                prop_list = prop_list + prop_pair.encode() + bytes([0])

            tag_hash = 0
            for t in dev.tags:
                tag_hash = tag_hash | bloom_hash(t)

            hdr = build_header(len(prop_list), subsys, dev_type, tag_hash)

            return hdr + prop_list

        def send_message(message: bytes):
            """Send the custom udev event message to the NETLINK_KOBJECT_UEVENT socket.

            :param message: The custom udev event message bytes.
            :return:
            """
            sendfd = socket.socket(socket.AF_NETLINK, socket.SOCK_DGRAM, NETLINK_KOBJECT_UEVENT)
            try:
                sendfd.sendto(message, (0, UDEV_MONITOR_UDEV))
            except ConnectionRefusedError:
                pass
            sendfd.close()

        udev_message = build_message(device)
        send_message(udev_message)
        self.log.info(f"Sent custom udev event message for input '{device.sys_path}'.")

    async def add_device(self, device: pyudev.Device):
        """Add a new device and perform necessary udev-related actions.

        This function handles the addition of a new device, creates the device node (if applicable),
        generates udev data files, and sends a custom udev event message to notify libudev applications
        of the newly added device.

        :param device: The device to be added.
        :return:
        """
        # Check if this was the device or an input event
        if device.device_node is not None:
            # Create the device node if it does not yet exist
            self.manage_device_node("add", device.device_node, device.device_number)

        # Create the udev data files
        self.manage_udev_data("add", device)

        # Send a modified udev event message so applications subscribed to libudev will see the newly added device
        self.send_custom_udev_event("add", device)
        await asyncio.sleep(0.1)

        # Add the device to our sources dict
        if device.device_node is None:
            device_name = device.get("NAME").strip('"')
            self.log.info(f"Finished adding new input {device.sys_path} with name '{device_name}'.")
        else:
            device_name = device.parent.get("NAME").strip('"')
            self.log.info(f"Finished adding new device {device.device_node} for input '{device_name}'.")

    async def remove_device(self, device: pyudev.Device):
        """Remove a device and perform necessary udev-related actions.

        This function handles the removal of a device, removes the device node (if applicable),
        deletes udev data files, and sends a custom udev event message to notify libudev applications
        of the removed device.

        :param device: The device to be removed.
        :return:
        """
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


async def shutdown(signal_name: str, relay: DumbUdevRelay, loop: asyncio.AbstractEventLoop):
    """Shutdown handler for graceful exit.

    :param signal_name: The name of the received signal.
    :param relay: The DumbUdevRelay instance.
    :param loop: The asyncio event loop.
    :return:
    """
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

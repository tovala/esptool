# SPDX-FileCopyrightText: 2009-2015 Chris Liechti
# SPDX-FileContributor: 2020-2024 Espressif Systems (Shanghai) CO LTD
# SPDX-License-Identifier: BSD-3-Clause
#
# Redirect data from a TCP/IP connection to a serial port and vice versa using RFC 2217.

###################################################################################
# redirect data from a TCP/IP connection to a serial port and vice versa
# using RFC 2217
#
# (C) 2009-2015 Chris Liechti <cliechti@gmx.net>
#
# SPDX-License-Identifier: BSD-3-Clause

import os
import logging
import socket
import sys
import serial
import threading

from esp_rfc2217_server.redirector import Redirector
from esptool.reset import (
    ClassicReset,
    DEFAULT_RESET_DELAY,
    UnixTightReset,
)
def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="RFC 2217 Serial to Network (TCP/IP) redirector.",
        epilog="NOTE: no security measures are implemented. "
        "Anyone can remotely connect to this service over the network.\n"
        "Only one connection at once is supported. "
        "When the connection is terminated it waits for the next connect.",
    )

    parser.add_argument("SERIALPORT")

    parser.add_argument(
        "-p",
        "--localport",
        type=int,
        help="local TCP port, default: %(default)s",
        metavar="TCPPORT",
        default=2217,
    )

    parser.add_argument(
        "-v",
        "--verbose",
        dest="verbosity",
        action="count",
        help="print more diagnostic messages (option can be given multiple times)",
        default=0,
    )

    parser.add_argument(
        "-n",
        "--no-reset",
        dest="no_reset",
        action="store_true",
        help="don't reset the device on client connection",
    )

    parser.add_argument(
        "--r0",
        help="Use delays necessary for ESP32 revision 0 chips",
        action="store_true",
    )

    args = parser.parse_args()

    if args.verbosity > 3:
        args.verbosity = 3
    level = (logging.WARNING, logging.INFO, logging.DEBUG, logging.NOTSET)[
        args.verbosity
    ]
    logging.basicConfig(format="%(levelname)s: %(message)s", level=logging.INFO)
    logging.getLogger("rfc2217").setLevel(level)

    # connect to serial port
    ser = serial.serial_for_url(args.SERIALPORT, do_not_open=True, exclusive=True)
    ser.timeout = 1  # required so that the reader thread can exit
    # reset control line as no _remote_ "terminal" has been connected yet
    logging.info("RFC 2217 TCP/IP to Serial redirector - type Ctrl-C / BREAK to quit")

    try:
        ser.open()
    except serial.SerialException as e:
        logging.error(" Could not open serial port {}: {}".format(ser.name, e))
        sys.exit(1)

    client = None
    alive = True

    def reader():
        """loop forever and copy serial->socket"""
        logging.debug("reader thread started")
        while True:
            try:
                data = ser.read(ser.in_waiting or 1)
                if data == b'':
                    continue

                try:
                    print(str(data, 'utf-8'), end="")
                except:
                    pass

                if client and client.alive:
                    # escape outgoing data when needed (Telnet IAC (0xff) character)
                    client.write(b"".join(client.rfc2217.escape(data)))

            except socket.error as msg:
                # client got disconnected. It's fine.
                logging.error("remote socket error: {}".format(msg))
                if client:
                    client.stop()

            except serial.SerialException as e:
                # serial port got disconnected. Not so fine!
                logging.error("serial port was closed: {}".format(msg))
                alive = False
                break


    reader_thread = threading.Thread(target=reader)
    reader_thread.daemon = True
    reader_thread.name = "serial->socket"
    reader_thread.start()

    # Do one reset: put it into bootloader
    if os.name != "nt":
        UnixTightReset(ser)()
    else:
        ClassicReset(ser)()

    logging.info("Serving serial port: {}".format(ser.name))

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("", args.localport))
    srv.listen(1)
    logging.info(" TCP/IP port: {}".format(args.localport))
    while alive:
        try:
            client_socket, addr = srv.accept()
            logging.info("Connected by {}:{}".format(addr[0], addr[1]))
            client_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            client = Redirector(ser, client_socket, args.verbosity > 0, args.r0)
            ser.reset_input_buffer()

            if not args.no_reset:
                logging.info("Resetting device on connection")
                client.rfc2217.reset_device()
                ser.rts = True
                ser.dtr = True
            # enter network <-> serial loop
            try:
                client.shortcircuit()
            finally:
                logging.info("Disconnected")
                client.stop()
                client_socket.close()
                client = None
#                ser.dtr = False
#                ser.rts = False
                # Restore port settings (may have been changed by RFC 2217
                # capable client)
#                ser.apply_settings(settings)
        except KeyboardInterrupt:
            sys.stdout.write("\n")
            break
        except socket.error as msg:
            logging.error(str(msg))

    logging.info("--- exit ---")


if __name__ == "__main__":
    main()

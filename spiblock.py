#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# SPIblock
# Copyright (C) 2020 Björn Ruytenberg <bjorn@bjornweb.nl>
#
# This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
# This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details. You should have
# received a copy of the GNU General Public License along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
# SPIblock is a SPI manipulation tool allowing to configure on-flash write protection.

import argparse
import sys
import logging
import re
import os
from pyBusPirateLite.SPI import SPI


class SpiDevice:
    # Public members
    Connected = False
    ManufacturerIdStr = ""
    DeviceIdStr = ""
    FrDevConst = ""
    # Flashrom constants
    _frTestedConst = ""
    _frManuConst = ""
    _frUnlockFunction = ""
    # UART device
    _spiDev = None
    # Connection strings
    _spiDevPath = ""
    _uartSpeed = ""
    _timeout = ""
    _spiSpeed = ""

    def Connect(self, force):
        self._spiDev = SPI(portname=self._spiDevPath, speed=int(self._uartSpeed),
                           timeout=float(self._timeout), connect=True)
        self._spiDev.pins = SPI.PIN_POWER | SPI.PIN_CS
        self._spiDev.config = SPI.CFG_PUSH_PULL | SPI.CFG_IDLE
        self._spiDev.spiSpeed = self._spiSpeed

        self.Connected = True
        self._probe(force)

    def Disconnect(self):
        self._spiDev.disconnect()
        self.Connected = False

    def _getSpiDeviceInfo(self):
        self._spiDev.cs = True
        ret = self._spiDev.transfer([0x9f, 0xFF, 0xFF, 0xFF])
        self._spiDev.cs = False
        return ret

    def _parseFrConstsByIdStr(self, force):
        # Find manufacturer in 'flashchips.h'
        f = open("flashrom/flashchips.h", "r")
        content = f.read()
        f.close()

        # Get manufacturer const
        pattern = re.compile(
            r"#define ([^/\t]*)_ID.*" + self.ManufacturerIdStr + ".*")
        result = pattern.search(content)

        if(result == None):
            if force == True:
                logging.warning("Manufacturer unrecognized by flashrom.")
                return
            else:
                raise Exception("Manufacturer unrecognized by flashrom.")

        self._frManuConst = result.group(1)

        # Get device const
        pattern = re.compile(
            r"#define (" + self._frManuConst + "[^/\t]+).*" + self.DeviceIdStr + ".*")
        result = pattern.search(content)

        if(result == None):
            if force == True:
                logging.warning("Device model unrecognized by flashrom.")
                return
            else:
                raise Exception("Device model unrecognized by flashrom.")

        self.FrDevConst = result.group(1)

        # Find device in 'flashchips.c'
        f = open("flashrom/flashchips.c", "r")
        content = f.read()
        f.close()

        contentLines = content.splitlines()
        foundDevice = False
        foundTested = False

        for idx, line in enumerate(contentLines):
            if foundDevice == False:
                if self.FrDevConst in line:
                    foundDevice = True
            if foundDevice == True:
                # Looking for testing constant x in '.tested = (x),'
                if ".tested" in line:
                    pattern = re.compile(r".*= (.*),")
                    result = pattern.search(line)
                    if(result == None):
                        raise Exception(
                            "Found device, but unexpected syntax encountered in parsing 'tested' member.")
                    else:
                        self._frTestedConst = result.group(1)
                        foundTested = True
                        break

        if foundDevice == False:
            raise Exception(
                "Mismatch between 'flashchips.h' and 'flashchips.c'.")
        if foundDevice == True and foundTested == False:
            raise Exception(
                "Found device, but could not find 'tested' constant.")

        # Get unlock function for device
        foundUnlock = False
        for i in range(idx, len(contentLines)):
            if ".unlock" in contentLines[i]:
                pattern = re.compile(r".*= (.*),")
                result = pattern.search(contentLines[i])
                if(result == None):
                    raise Exception(
                        "Found device, but unexpected syntax encountered in parsing 'unlock' member.")
                else:
                    self._frUnlockFunction = result.group(1)
                    foundUnlock = True
                    break

        if foundUnlock == False:
            raise Exception("No unlock method available for device.")

    def _getStatusReg(self):
        self._spiDev.cs = True
        ret = self._spiDev.transfer([0x05, 0xFF])
        self._spiDev.cs = False
        return list(ret)[1]

    def _bytesToInt(self, x, len):
        return int.from_bytes(x, byteorder='big', signed=False)

    # Get Status Register Protect
    def _getSrp(self):
        return (self._getStatusReg() >> 7 & 1)

    # Get Write Enable Latch
    def _getWel(self):
        return (self._getStatusReg() >> 1 & 1)

    # Change Write Enable
    def _changeWe(self, enableDisable):
        val = 0x06 if enableDisable == True else 0x04
        self._spiDev.cs = True
        self._spiDev.transfer([val])
        self._spiDev.cs = False
        return self._getWel()

    def _getBpStatus(self):
        status = self._getStatusReg()
        return (status >> 2 & 1) + (status >> 3 & 1) + (status >> 4 & 1)

    def _probe(self, force):
        try:
            assert self.Connected == True, "Not connected to SPI device."

            ret = self._bytesToInt(self._getSpiDeviceInfo(), 3)
            if(ret == 0xffffff or ret == 0x000000):
                raise Exception(
                    "Invalid return value. Either the SPI device is not connected or there was a bus collision.")

            retStr = hex(ret)
            self.ManufacturerIdStr = "0x" + retStr[4:6].upper()
            self.DeviceIdStr = "0x" + retStr[6:10].upper()

            self._parseFrConstsByIdStr(force)
            if self._frTestedConst != "TEST_OK_PREW":
                logging.warning(
                    "Enabling block protection for SPI device unsupported (flashrom status: '" + self._frTestedConst + "').")

            # TODO: Add support for additional methods
            if self._frUnlockFunction != "spi_disable_blockprotect":
                logging.warning("Flashrom lists an unknown unlock method (" +
                                self._frUnlockFunction + ") for this device.")

        except Exception as e:
            raise Exception("Cannot connect to SPI device:", e)

    def __init__(self, spiDevPath: str, uartSpeed: str, timeout: str, spiSpeed: str):
        self._spiDevPath = spiDevPath
        self._uartSpeed = uartSpeed
        self._timeout = timeout
        self._spiSpeed = spiSpeed

    def GetDeviceStatus(self):
        wel = self._getWel()
        srp = self._getSrp()
        bp = self._getBpStatus()
        welStr = "Enabled" if wel == 1 else "Disabled"
        srpStr = "Enabled" if srp == 1 else "Disabled"
        bpStr = "Enabled (" + str(bp) + ")" if bp > 0 else "Disabled"

        status = {"Status Register S0": hex(self._getStatusReg()),
                  "Write Enable Latch WEL": welStr,
                  "Status Register Protect SRP0": srpStr,
                  "Block Protection BPx": bpStr}
        return status

    def EnableBlockProtection(self, force):
        assert self.Connected == True, "Not connected to SPI device."

        if self._frUnlockFunction == "" or self._frUnlockFunction != "spi_disable_blockprotect":
            if force == True:
                logging.warning("Unsupported device. This action may fail.")
            else:
                raise Exception(
                    "Unsupported device. Cannot enable block protection.")

        val = self._getBpStatus()
        if val > 1 and val < 3:
            logging.warning("Some block protection has already been enabled.")
        elif val == 3:
            raise Exception("Block protection has already been enabled.")

        # Enable 'Write Enable'
        if self._getSrp() != 0x00:
            logging.warning(
                "WP pin control enabled. Make sure to de-assert WP pin, otherwise this action will fail.")
            logging.warning(
                "If successful, this action will disable WP pin control.")
        if(self._changeWe(True) != 1):
            raise Exception("Device does not allow changing status registers.")

        # Write Status Register to enable block protection
        self._spiDev.cs = True
        self._spiDev.transfer([0x01, 0x1E])
        self._spiDev.cs = False

        if self._getBpStatus() == 0:
            if(self._getSrp() == 1):
                raise Exception(
                    "Device does not allow changing status registers. Disable WP pin control (SRP) first.")
            else:
                raise Exception("Failed to enable block protection.")

        # Disable 'Write Enable'
        if(self._changeWe(False) != 0):
            raise Exception("Failed to disable Write Enable.")

    def DisableBlockProtection(self, force):
        assert self.Connected == True, "Not connected to SPI device."
        if self._frUnlockFunction == "" or self._frUnlockFunction != "spi_disable_blockprotect":
            if force == True:
                logging.warning("Unsupported device. This action may fail.")
            else:
                raise Exception(
                    "Unsupported device. Cannot disable block protection.")

        if self._getBpStatus() == 0:
            raise Exception(
                "Block protection has already been disabled.")

        # Enable 'Write Enable'
        if self._getSrp() != 0x00:
            logging.warning(
                "WP pin control enabled. Make sure to de-assert WP pin, otherwise this action will fail.")
            logging.warning(
                "If successful, this action will disable WP pin control.")
        if(self._changeWe(True) != 1):
            raise Exception("Device does not allow changing status registers.")

        # Write Status Register to disable block protection
        self._spiDev.cs = True
        self._spiDev.transfer([0x01, 0x00])
        self._spiDev.cs = False

        if self._getBpStatus() > 0:
            if(self._getSrp() == 1):
                raise Exception(
                    "Device does not allow changing status registers. Disable WP pin control (SRP) first.")
            else:
                raise Exception("Failed to disable block protection.")

        # Disable 'Write Enable'
        if(self._changeWe(False) != 0):
            raise Exception("Failed to disable Write Enable.")

    def EnableWpControl(self):
        assert self.Connected == True, "Not connected to SPI device."

        if self._getSrp() == 0x01:
            raise Exception(
                "Device already configured to enable WP pin control.")

        # Get current SR value
        sr = self._getStatusReg()

        # Enable 'Write Enable'
        if(self._changeWe(True) != 1):
            raise Exception("Device does not allow changing status registers.")

        # Write to Status Register to enable SRP
        val = sr | 1 << 7
        self._spiDev.cs = True
        self._spiDev.transfer([0x01, val])
        self._spiDev.cs = False

        if self._getSrp() != 0x01:
            if(self._getSrp() == 1):
                raise Exception(
                    "Device does not allow changing status registers. De-assert WP pin first.")
            else:
                raise Exception("Failed to enable WP pin control.")

        # Disable 'Write Enable'
        if(self._changeWe(False) != 0):
            raise Exception("Failed to disable Write Enable.")

    def DisableWpControl(self):
        assert self.Connected == True, "Not connected to SPI device."

        if self._getSrp() == 0x00:
            raise Exception(
                "Device already configured to disable WP pin control.")

        # Get current SR value
        sr = self._getStatusReg()

        # Enable 'Write Enable'
        if(self._changeWe(True) != 1):
            raise Exception(
                "Device does not allow changing status registers.")

        # Write to Status Register to disable SRP
        val = sr & ~(1 << 7)
        self._spiDev.cs = True
        self._spiDev.transfer([0x01, val])
        self._spiDev.cs = False

        if self._getSrp() != 0x00:
            if(self._getSrp() == 1):
                raise Exception(
                    "Device does not allow changing status registers. De-assert WP pin first.")
            else:
                raise Exception("Failed to disable WP pin control.")

        # Disable 'Write Enable'
        if(self._changeWe(False) != 0):
            raise Exception("Failed to disable Write Enable.")


def main():
    parser = argparse.ArgumentParser(description='SPIblock')
    parser.add_argument("-u", "--uspeed", dest="uspeed",
                        action="store", default="250000", help="Set UART speed")
    parser.add_argument("-x", "--speed", dest="speed",
                        action="store", default="1Mhz", help="Set SPI speed")
    parser.add_argument("-d", "--dev", dest="dev", action="store",
                        default="/dev/tty.usbmodem000000011", help="Set Bus Pirate device path")
    parser.add_argument("-t", "--timeout", dest="timeout",
                        action="store", default="0.1", help="Set SPI timeout in seconds")
    parser.add_argument("-v", "--verbose", dest="verbose",
                        action="store_true", help="Enable verbose output")
    parser.add_argument("-f", "--force", dest="force",
                        action="store_true", help="Assume SPI device supports generic write protection")
    parser.add_argument("-p", "--probe", dest="probe",
                        action="store_true",  help="Probe for SPI device")
    parser.add_argument("-s", "--status", dest="status",
                        action="store_true", help="Get SPI device status")
    parser.add_argument("-b", "--bp-state", dest="bp", action="store",
                        help="Enable (1) or disable (0) block protection")
    parser.add_argument("-w", "--wp-state", dest="wp", action="store",
                        help="Enable (1) or disable (0) WP pin control")
    parser.add_argument("--version", action="version",
                        version="SPIblock 1.0{0}(c) 2020 Björn Ruytenberg{0}https://thunderspy.io{0}{0}Licensed under GNU GPLv3 or later <http://gnu.org/licenses/gpl.html>.".format(os.linesep))
    args = parser.parse_args()

    logging.basicConfig(format='%(name)s: %(levelname)s: %(message)s',
                        level=logging.DEBUG if args.verbose else logging.INFO)

    try:
        spiDev = SpiDevice(args.dev, args.uspeed, args.timeout, args.speed)
        spiDev.Connect(args.force)

        if args.probe == True:
            print("Manufacturer ID:", spiDev.ManufacturerIdStr)
            print("Device ID:", spiDev.DeviceIdStr)
            print("Device: " + spiDev.FrDevConst)
            logging.debug("ManuConst: " + spiDev._frManuConst)
            logging.debug("TestedConst: " + spiDev._frTestedConst)
            logging.debug("UnlockFunction: " + spiDev._frUnlockFunction)
        elif args.status == True:
            parms = spiDev.GetDeviceStatus()
            for parm in parms:
                print(parm, ":", parms[parm])
        elif args.bp == "1":
            spiDev.EnableBlockProtection(args.force)
            print("Succesfully enabled block protection.")
        elif args.bp == "0":
            spiDev.DisableBlockProtection(args.force)
            print("Succesfully disabled block protection.")
        elif args.wp == "1":
            spiDev.EnableWpControl()
            print("Succesfully enabled WP pin control.")
        elif args.wp == "0":
            spiDev.DisableWpControl()
            print("Succesfully disabled WP pin control.")
        else:
            parser.print_help()

        spiDev.Disconnect()

    except Exception as e:
        print("Error:", e)


if __name__ == '__main__':
    if (sys.version_info <= (3, 2)):
        print("This script requires Python 3.2 or higher. Aborting.")
    else:
        main()

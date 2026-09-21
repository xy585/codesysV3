#!/usr/bin/env python3
"""
Wait for the application on the runtime to be replaced, then exercise
CmpIecVarAccess against it (read, write, read back).

  python wait_and_test.py <seconds-to-wait>

Start it, then press Download / Online Change in the IDE.
"""

import os
import struct
import sys
import time

sys.path.insert(0, r'C:\Users\Xingy\Desktop\scripts')
from codesys_udp_ds import (CodesysClient, ChannelUnavailable, tag, parse_tags,
                            find_tag_deep, _flatten)

APP = r"C:\ProgramData\CODESYS\CODESYSControlWinV3\1DCA8F9\PlcLogic\App\App.app"
TARGET = "192.168.125.129"
LIMIT = int(sys.argv[1]) if len(sys.argv) > 1 else 240

VARS = ["App.PLC_PRG.iTest", "App.PLC_PRG.xTest"]


def app_stamp():
    try:
        st = os.stat(APP)
        return (st.st_size, int(st.st_mtime))
    except OSError:
        return None


def connect():
    for port in (1741, 1742, 1743):
        for _ in range(4):
            try:
                c = CodesysClient(TARGET, local_port=port, verbose=False)
                c.open_channel()
                return c
            except Exception:
                time.sleep(3 if port in (1741, 1742) else 1)
    return None


def read_vars(c, names):
    h, tags = c.var_register(names)
    if h is None:
        return None, tags
    try:
        resp, rtags = c.var_read(h)
        st = CodesysClient.var_status(rtags)
        vals = [t["value"][4:] for t in _flatten(rtags) if t["id"] == 0x1D]
        return (st, vals), rtags
    finally:
        c.var_release(h)


def main():
    base = app_stamp()
    print(f"current app: size={base[0]} mtime={base[1]}", flush=True)
    print(f"waiting up to {LIMIT}s for it to change (do the Download now)...",
          flush=True)

    deadline = time.time() + LIMIT
    while time.time() < deadline:
        now = app_stamp()
        if now and now != base:
            print(f"\n*** app replaced: size={now[0]} mtime={now[1]}\n", flush=True)
            break
        time.sleep(2)
    else:
        print("timed out waiting for a download; nothing tested", flush=True)
        return 1

    time.sleep(4)                       # let the runtime settle

    for attempt in range(4):
        c = connect()
        if c is None:
            print("could not open a channel", flush=True)
            return 1
        try:
            c.identify(); c.create_session()
            pem, ch = c.get_public_key()
            st, _ = c.login(pem, ch, "test", "test")
            print(f"login status = {st}", flush=True)
            if st != 0:
                c.close(); time.sleep(3); continue

            print("\n--- READ ---")
            out, tags = read_vars(c, VARS)
            if out is None:
                print("register failed", flush=True)
            else:
                status, vals = out
                print(f"status = {status}", flush=True)
                for n, v in zip(VARS, vals):
                    print(f"  {n:24} = {v.hex(' ')}  ({int.from_bytes(v,'little')})",
                          flush=True)
                if not vals:
                    for t in _flatten(tags):
                        print(f"    tag 0x{t['id']:02x} {t['value'].hex(' ')}",
                              flush=True)

            if out and out[0] == 0:
                print("\n--- WRITE App.PLC_PRG.iTest = 1234 ---")
                resp, wtags = c.var_write("App.PLC_PRG.iTest",
                                          struct.pack("<h", 1234))
                print(f"write status = {CodesysClient.var_status(wtags)}", flush=True)
                time.sleep(1.0)
                print("--- READ BACK ---")
                out2, _ = read_vars(c, ["App.PLC_PRG.iTest"])
                print(f"  {out2}", flush=True)
            c.close()
            return 0
        except Exception as e:
            print(f"attempt failed: {e}", flush=True)
            try:
                c.close()
            except Exception:
                pass
            time.sleep(4)
    return 1


if __name__ == "__main__":
    sys.exit(main())

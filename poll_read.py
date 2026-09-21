#!/usr/bin/env python3
"""
Retry the variable read until the runtime stops refusing it.

  python poll_read.py [seconds]

Start it, then press Run (F5) / restart the application in the IDE.  It prints
immediately when the status changes away from 0x14, and then does a full
write -> read-back round trip.
"""

import struct
import sys
import time

sys.path.insert(0, r'C:\Users\Xingy\Desktop\scripts')
from codesys_udp_ds import CodesysClient, parse_tags, find_tag_deep, _flatten

TARGET = "192.168.125.129"
VARS = ["App2.PLC_PRG.iTest", "App2.PLC_PRG.xTest"]
LIMIT = int(sys.argv[1]) if len(sys.argv) > 1 else 300
NOT_FOUND = 0x14


def connect():
    for port in (1741, 1742, 1743):
        for _ in range(2):
            try:
                c = CodesysClient(TARGET, local_port=port, verbose=False)
                c.open_channel()
                return c
            except Exception:
                time.sleep(2)
    return None


def read_vars(c, names):
    h, tags = c.var_register(names)
    if h is None:
        return None, []
    try:
        resp, rt = c.var_read(h)
        st = CodesysClient.var_status(rt)
        vals = [t["value"][4:] for t in _flatten(rt) if t["id"] == 0x1D]
        return st, vals
    finally:
        c.var_release(h)


def one_shot():
    c = connect()
    if c is None:
        return None, None, None
    try:
        c.identify(); c.create_session()
        pem, ch = c.get_public_key()
        st, _ = c.login(pem, ch, "test", "test")
        if st != 0:
            return None, None, None
        status, vals = read_vars(c, VARS)
        return c, status, vals
    except Exception:
        try:
            c.close()
        except Exception:
            pass
        return None, None, None


print(f"polling {VARS} for up to {LIMIT}s; press Run in the IDE now...",
      flush=True)
deadline = time.time() + LIMIT
last = None
while time.time() < deadline:
    c, status, vals = one_shot()
    if status is not None and status != last:
        print(f"[{time.strftime('%H:%M:%S')}] status = {status}"
              + ("  (still refused)" if status == NOT_FOUND else "  <-- CHANGED"),
              flush=True)
        last = status
    if status not in (None, NOT_FOUND):
        print("\n*** CmpIecVarAccess is now working ***", flush=True)
        for n, v in zip(VARS, vals):
            print(f"    {n:24} = {v.hex(' ')}  ({int.from_bytes(v, 'little')})",
                  flush=True)
        print("\n--- writing App2.PLC_PRG.iTest = 1234, then reading back ---",
              flush=True)
        resp, wt = c.var_write("App2.PLC_PRG.iTest", struct.pack("<h", 1234))
        print(f"    write status = {CodesysClient.var_status(wt)}", flush=True)
        time.sleep(1.5)
        st2, v2 = read_vars(c, ["App2.PLC_PRG.iTest"])
        print(f"    read back status={st2} value={[x.hex(' ') for x in v2]}",
              flush=True)
        c.close()
        sys.exit(0)
    if c:
        c.close()
    time.sleep(5)

print("\nstill refused after the timeout - CmpIecVarAccess stays disabled",
      flush=True)
sys.exit(1)

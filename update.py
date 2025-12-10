import hashlib
import base64
from datetime import date, timedelta

# Rule:
# k_{i+1} = SHA256(k_i) || 0x21
# where "|| 0x21" means append a single byte 0x21 at the end (ASCII '!').

def next_key(k: bytes) -> bytes:
    h = hashlib.sha256(k).digest()  # 32 bytes
    return h + b'\x21'              # append 0x21 to make 33 bytes

def to_hex(b: bytes) -> str:
    return b.hex()

def to_b64(b: bytes) -> str:
    return base64.b64encode(b).decode('ascii')

# Initial key on 2025-10-06 (ASCII, 33 bytes)
k = b"TinyRobotWafflesFlyOverCityAtDawn"
assert len(k) == 33

start = date(2025, 10, 6)
end   = date(2025, 10, 27)
d = start

# Print header
print(f"{'Date':<12} {'Len':<5} {'Key (HEX)':<66} {'Key (Base64)'}")

while d <= end:
    hex_str = to_hex(k)
    b64_str = to_b64(k)
    print(f"{d.isoformat():<12} {len(k):<5} {hex_str:<66} {b64_str}")
    k = next_key(k)
    d += timedelta(days=1)

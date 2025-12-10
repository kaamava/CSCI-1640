# Hybrid many-time-pad solver that also prints the reused OTP key.
# (A) Cribless bootstrap via space-vote + light language consistency -> partial key and partial plaintext
# (B) Human completes message 0 into a short crib
# (C) Crib-dragging to recover the full key -> decrypt all messages
# The script prints the OTP key in HEX and ASCII both before (possibly partial) and after (final) crib-dragging.

import string

hex_cts = [
"000c1d0d3b01054f003212120f020253250d176f0f0a07631b1118255430091e1d",
"0d0c1e591b4f010e1a7713030708450a2919593f131714260a0015385433041b02",
"151e0b0a3d02074f1b39044612050816661c182b560c01631e1b0b2a1d2a06",
"0d081759250a420c1539410b070700532019176f1903520d00171632542a0e00",
"1d490616220a42011b7712121308001d324c1a2e18450026081059351c2d12",
"00010f0d72180d1a18334104034c14062f181c6f130810221b061832072d0f10",
"181c0d123b031b4f3b0331460f1f4503231e1f2a15111e3a49071c22062115",
"10000a17264f2c0617381246150d1c5332041c3d134505221a5418611725151406",
"1908171b374f1b0a007728460205011d324c092e0f4513371d1117351d2b0f",
"030c4e0a3a001703107713030700090a6600103c02001c631d1b590f1d270e04",
"1a080659250a420e0632410209050b14661b1c231a45052a1d1c16340064091e03"
]
cts = [bytes.fromhex(h) for h in hex_cts]
n = len(cts)
L = max(map(len, cts))

def is_printable(b):
    # Basic printable ASCII check
    return 32 <= b <= 126

def is_alpha(b):
    # ASCII letter check
    return (65 <= b <= 90) or (97 <= b <= 122)

def key_hex_str(key):
    # HEX with '??' for unknown bytes
    out = []
    for kb in key:
        out.append('??' if kb is None else f"{kb:02x}")
    return ''.join(out)

def key_ascii_str(key):
    # ASCII view for key: printable -> char, else '.', unknown -> '*'
    out = []
    for kb in key:
        if kb is None:
            out.append('*')
        else:
            out.append(chr(kb) if is_printable(kb) else '.')
    return ''.join(out)

# ---------- (A) Cribless bootstrap: space voting + light column scoring ----------
alpha = [[0]*len(cts[i]) for i in range(n)]
for i in range(n):
    for j in range(n):
        if i == j:
            continue
        m = min(len(cts[i]), len(cts[j]))
        for k in range(m):
            if is_alpha(cts[i][k] ^ cts[j][k]):
                alpha[i][k] += 1

SPACE = 0x20
key = [None] * L

# Seed key bytes from strong space evidence using an adaptive per-column threshold (median+1)
for k in range(L):
    col_counts = [alpha[i][k] for i in range(n) if k < len(cts[i])]
    if not col_counts:
        continue
    med = sorted(col_counts)[len(col_counts)//2]
    for i in range(n):
        if k < len(cts[i]) and alpha[i][k] >= med + 1 and key[k] is None:
            key[k] = cts[i][k] ^ SPACE

# Column-level language score (cribless): reward printable, spaces, letters; penalize non-printable
def col_score(kbyte, col):
    s = 0.0
    tot = 0
    for i in range(n):
        if col < len(cts[i]):
            pb = cts[i][col] ^ kbyte
            tot += 1
            if not is_printable(pb):
                s -= 6
            elif pb == 32:
                s += 1.6
            elif is_alpha(pb):
                s += 1.2
            else:
                s += 0.2
    return s if tot else -1e9

# Candidate key bytes for a column: assume space or any ASCII letter under any ciphertext in that column
letters = list(map(ord, string.ascii_letters))
def candidates(col):
    C = set()
    for i in range(n):
        if col < len(cts[i]):
            C.add(cts[i][col] ^ SPACE)
            for Ltr in letters:
                C.add(cts[i][col] ^ Ltr)
    return C

# A few refinement passes: accept a candidate if it clearly beats the runner-up
for _ in range(6):
    progress = False
    for k in range(L):
        if key[k] is not None:
            continue
        cand = candidates(k)
        scored = []
        for kb in cand:
            # Quick prune: reject candidates causing too many non-printables
            tot = bad = 0
            for i in range(n):
                if k < len(cts[i]):
                    tot += 1
                    if not is_printable(cts[i][k] ^ kb):
                        bad += 1
            if tot and bad / tot > 0.35:
                continue
            scored.append((col_score(kb, k), kb))
        if not scored:
            continue
        scored.sort(reverse=True)
        if len(scored) == 1 or scored[0][0] - scored[1][0] >= 0.8:
            key[k] = scored[0][1]
            progress = True
    if not progress:
        break

def dec_line(ci, key):
    # Decrypt one ciphertext using current key; unknown key bytes render as '*'
    out = []
    for k, b in enumerate(ci):
        if key[k] is None:
            out.append('*')
        else:
            p = b ^ key[k]
            out.append(chr(p) if is_printable(p) else '?')
    return ''.join(out)

# Show the partially recovered message 0 and the partial OTP key
partial0 = dec_line(cts[0], key)
print("PARTIAL MESSAGE 0:\n", partial0)
print("\nPARTIAL OTP KEY (HEX):\n", key_hex_str(key))
print("PARTIAL OTP KEY (ASCII):\n", key_ascii_str(key))

# ---------- (B) Human supplies a short crib for message 0 (replace with your human guess) ----------
# Example: "*esting *est*ng can you read t***" -> "Testing testing can you read this"
human_crib = "Testing testing can you read this"

# ---------- (C) Crib-dragging: fix key bytes from the crib, then one more refinement ----------
for pos, ch in enumerate(human_crib.encode()):
    if pos < len(cts[0]):
        key[pos] = cts[0][pos] ^ ch

# Optional extra refinement passes to resolve any remaining columns
for _ in range(3):
    progress = False
    for k in range(L):
        if key[k] is not None:
            continue
        scored = []
        for kb in candidates(k):
            tot = bad = 0
            for i in range(n):
                if k < len(cts[i]):
                    tot += 1
                    if not is_printable(cts[i][k] ^ kb):
                        bad += 1
            if tot and bad / tot > 0.35:
                continue
            scored.append((col_score(kb, k), kb))
        if not scored:
            continue
        scored.sort(reverse=True)
        if len(scored) == 1 or scored[0][0] - scored[1][0] >= 0.6:
            key[k] = scored[0][1]
            progress = True
    if not progress:
        break

# Print the FINAL OTP key and the final plaintexts
print("\nFINAL OTP KEY (HEX):\n", key_hex_str(key))
print("FINAL OTP KEY (ASCII):\n", key_ascii_str(key))

print("\nFINAL PLAINTEXTS:")
for i, c in enumerate(cts, 1):
    print(f"{i:02d}: {dec_line(c, key)}")

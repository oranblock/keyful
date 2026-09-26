#!/usr/bin/env python3
"""
qvault5.py - card vault with a challenge that is never the same twice.

The card is not 140 random cells. It is 140 evaluation points of one
degree-12 polynomial over GF(2^20). ANY 13 cells reconstruct the master
secret, so the decoder invents a fresh random set every single time.

    C(140,13) = 1.2e17 possible challenges. You will never see one twice.

    card       140 cells x 20 bits, master secret = 260 bits
    challenge  15 cells asked (13 to reconstruct + 2 to catch typos)
    attacker   no cells -> 260 bits to guess. Nothing is stored about which.

    python qvault5.py card                # card.json + card.pdf
    python qvault5.py encode              # seals a typed message, SILENTLY
    python qvault5.py seal notes.txt      # seals a file  (gzipped if it helps)
    python qvault5.py seal ~/keys/        # seals a folder (tar.gz)
    python qvault5.py decode vault.qv5    # fresh random challenge, every time
    python qvault5.py cardinfo            # show this card's card+key fingerprints
    python qvault5.py verify              # check you can read the card, no vault
    python qvault5.py import              # rebuild card.json from paper
    python qvault5.py info vault.qv5      # display vault header information

flags:  --echo   show typed input (use this on a phone)
"""

import sys, os, io, json, gzip, base64, getpass, secrets, hashlib, datetime, tarfile, tempfile, re

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:
    sys.exit("\n  MISSING: cryptography\n"
             "  Termux:  pkg install python-cryptography\n"
             "  Else:    pip install cryptography\n")

MAGIC, VERSION = "QV5", 2
CHUNK = 1 << 20                              # 1 MiB streaming chunks
NOCOMP = {".gz",".zip",".7z",".xz",".bz2",".zst",".jpg",".jpeg",".png",".gif",
          ".mp4",".mkv",".mov",".mp3",".webp",".avif",".pdf"}
SLIPS, CELLS, CELL_LEN = 10, 14, 4          # 140 cells
K = 13                                       # cells needed to reconstruct
EXTRA = 2                                    # extra cells asked, for typo detection
B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
# only map chars that are NOT in B32, or valid input gets destroyed
FIX = str.maketrans({"0": "O", "1": "I", "8": "B", "9": "Q"})
assert not set("0189") & set(B32), "FIX must not rewrite valid alphabet chars"
RNG = secrets.SystemRandom()
CARD_FILE = "card.json"

# ---- GF(2^20), poly x^20 + x^3 + 1 -----------------------------------------
POLY, FBITS, FMASK = 0x100009, 20, (1 << 20) - 1

def gmul(a, b):
    r = 0
    while b:
        if b & 1: r ^= a
        b >>= 1
        a <<= 1
        if a >> FBITS & 1: a ^= POLY
    return r & FMASK

def gpow(a, e):
    r = 1
    while e:
        if e & 1: r = gmul(r, a)
        a = gmul(a, a); e >>= 1
    return r

def ginv(a):
    return gpow(a, (1 << FBITS) - 2)


# ---- polynomial card --------------------------------------------------------
def cell_x(s, c):
    return (s - 1) * CELLS + c          # 1..140, all distinct, all nonzero

def make_card():
    """Random degree-(K-1) polynomial. Cells are its values at x = 1..140."""
    coef = [secrets.randbelow(1 << FBITS) for _ in range(K)]
    card = {}
    for s in range(1, SLIPS + 1):
        for c in range(1, CELLS + 1):
            x, y = cell_x(s, c), 0
            for a in reversed(coef):    # Horner
                y = gmul(y, x) ^ a
            card[(s, c)] = enc_cell(y)
    return card, coef

def interpolate(pts):
    """pts: {x: y}. Recover all K coefficients of the degree-(K-1) polynomial."""
    xs = list(pts)
    coef = [0] * len(xs)
    for i in xs:                         # Lagrange basis, expanded
        num, den = [1] + [0] * (len(xs) - 1), 1
        deg = 0
        for j in xs:
            if i == j: continue
            new = [0] * len(xs)
            for d in range(deg + 1):     # multiply by (x + j)
                new[d] ^= gmul(num[d], j)
                if d + 1 < len(xs): new[d + 1] ^= num[d]
            num, deg = new, deg + 1
            den = gmul(den, i ^ j)
        scale = gmul(pts[i], ginv(den))
        for d in range(len(xs)):
            coef[d] ^= gmul(num[d], scale)
    return coef

def evaluate(coef, x):
    y = 0
    for a in reversed(coef):
        y = gmul(y, x) ^ a
    return y

def fit_poly(card):
    """Finds the best-fitting degree-(K-1) polynomial coef and inconsistent cells."""
    best_coef, best_bad = None, None
    attempts = [sorted(card)[:K]] + [RNG.sample(list(card.keys()), K) for _ in range(15)]
    for sample in attempts:
        pts = {cell_x(*k): dec_cell(card[k]) for k in sample}
        c = interpolate(pts)
        bad = [k for k in card if evaluate(c, cell_x(*k)) != dec_cell(card[k])]
        if best_bad is None or len(bad) < len(best_bad):
            best_coef, best_bad = c, bad
        if not bad:
            break
    return best_coef, best_bad

def key_fp(mk):
    """3-byte tag of the master key. Lets you tell 'wrong card' from 'typo'."""
    return hashlib.shake_256(b"QV5-MK" + mk).digest(3).hex().upper()

def master_key(coef):
    return hashlib.shake_256(b"QV5-MS" + b"".join(
        c.to_bytes(3, "big") for c in coef)).digest(32)


# ---- cell text --------------------------------------------------------------
def enc_cell(v):
    return "".join(B32[(v >> (5 * i)) & 31] for i in reversed(range(CELL_LEN)))

def dec_cell(s):
    v = 0
    for ch in s:
        v = (v << 5) | B32.index(ch)
    return v

def clean(v):
    return "".join(v.split()).upper().translate(FIX)

def card_fp(card):
    h = hashlib.shake_256(b"QV5-CARD")
    for k in sorted(card): h.update(card[k].encode())
    return h.digest(3).hex().upper()


# ---- card file --------------------------------------------------------------
def save_card(card):
    fd = os.open(CARD_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump({f"{s}.{c}": v for (s, c), v in card.items()}, f)

def load_card():
    if not os.path.exists(CARD_FILE):
        sys.exit(f"\n  no {CARD_FILE} - run `card` or `import`.\n"
                 f"  encode needs it. decode never does.\n")
    with open(CARD_FILE) as f:
        d = json.load(f)
    return {(int(k.split(".")[0]), int(k.split(".")[1])): v for k, v in d.items()}


# ---- vault ------------------------------------------------------------------
def kdf(mk, salt):
    return hashlib.shake_256(b"QV5-KDF" + salt + mk).digest(32)

def _aad(hdr_aad, i, last):
    return hashlib.sha256(hdr_aad).digest() + i.to_bytes(8, "big") + (b"F" if last else b"C")

def read_hdr(path):
    with open(path, "rb") as f:
        line = f.readline()
    return json.loads(line)


def seal_stream(src, meta, mk, path, fp):
    """src: file object. Chunked AES-256-GCM; index and final flag are authenticated."""
    salt, base = os.urandom(16), os.urandom(8)
    body = json.dumps(meta, sort_keys=True).encode()
    head = len(body).to_bytes(2, "big") + body

    chunks = []
    buf = head + src.read(CHUNK)
    i = 0
    while True:
        nxt = src.read(CHUNK)
        last = not nxt
        chunks.append((i, buf, last))
        if last: break
        buf = nxt; i += 1
    n = len(chunks)

    # No card or key fingerprint in the header: a vault must not say which card opens it.
    hdr = {"magic": MAGIC, "version": VERSION, "cipher": "AES-256-GCM",
           "kdf": "SHAKE256", "k": K,
           "chunks": n, "salt": base64.b64encode(salt).decode(),
           "base": base64.b64encode(base).decode()}
    aad0 = json.dumps(hdr, sort_keys=True).encode()
    key = kdf(mk, salt)
    with open(path, "wb") as f:
        f.write(aad0 + b"\n")
        for i, data, last in chunks:
            if n == 1 and len(data) < 4096:             # hide small payload sizes
                data = data + b"\x00" * ((-len(data)) % 256)
            ct = AESGCM(key).encrypt(base + i.to_bytes(4, "big"), data,
                                     _aad(aad0, i, last))
            f.write(len(ct).to_bytes(4, "big") + ct)
    return hdr, n


def open_stream(path, mk, sink):
    """Writes plaintext to sink. Returns meta dict."""
    with open(path, "rb") as f:
        raw = f.read()
    aad0, rest = raw.split(b"\n", 1)
    h = json.loads(aad0)
    key = kdf(mk, base64.b64decode(h["salt"]))

    if "chunks" not in h:                               # v1 vault: single blob, text
        body = AESGCM(key).decrypt(base64.b64decode(h["nonce"]), rest, aad0)
        n = int.from_bytes(body[:4], "big")
        sink.write(body[4:4 + n])
        return {"type": "text", "gz": False, "name": None}

    base, n, off, meta, first = base64.b64decode(h["base"]), h["chunks"], 0, None, True
    for i in range(n):
        ln = int.from_bytes(rest[off:off + 4], "big"); off += 4
        ct = rest[off:off + ln]; off += ln
        pt = AESGCM(key).decrypt(base + i.to_bytes(4, "big"), ct,
                                 _aad(aad0, i, i == n - 1))
        if first:
            ml = int.from_bytes(pt[:2], "big")
            meta = json.loads(pt[2:2 + ml]); pt = pt[2 + ml:]
            first = False
        sink.write(pt)
    return meta


def make_payload(src):
    """Returns (file-like, meta). Directory -> tar.gz. File -> gzip if it helps."""
    if src is None:
        return None, None
    if os.path.isdir(src):
        tmp = tempfile.TemporaryFile()
        with tarfile.open(fileobj=tmp, mode="w:gz") as t:
            t.add(src, arcname=os.path.basename(src.rstrip("/")))
        size = tmp.tell(); tmp.seek(0)
        return tmp, {"type": "dir", "name": os.path.basename(src.rstrip("/")) + ".tar.gz",
                     "gz": False, "size": size}
    with open(src, "rb") as f:
        raw = f.read()
    ext = os.path.splitext(src)[1].lower()
    if ext in NOCOMP:
        return io.BytesIO(raw), {"type": "file", "name": os.path.basename(src),
                                 "gz": False, "size": len(raw)}
    gz = gzip.compress(raw, 6)
    if len(gz) < len(raw) * 0.95:
        return io.BytesIO(gz), {"type": "file", "name": os.path.basename(src),
                                 "gz": True, "size": len(raw)}
    return io.BytesIO(raw), {"type": "file", "name": os.path.basename(src),
                             "gz": False, "size": len(raw)}


# ---- challenge --------------------------------------------------------------
def read_line(prompt, echo):
    if echo or not sys.stdin.isatty():
        return input(prompt)
    try:
        return getpass.getpass(prompt)
    except Exception:
        return input(prompt)

def fresh_challenge(n=K + EXTRA, avoid=None):
    pool = [(s, c) for s in range(1, SLIPS + 1) for c in range(1, CELLS + 1)
            if not (avoid and s in avoid)]
    if len(pool) < n:
        pool = [(s, c) for s in range(1, SLIPS + 1) for c in range(1, CELLS + 1)]
    return RNG.sample(pool, n)

def ask(coords, echo):
    """Ask K+EXTRA cells. Reconstruct from K, verify against the rest -> typo caught."""
    vals = {}
    print(f"  Read these {len(coords)} cells off the card:\n")
    for s, c in coords:
        while True:
            v = clean(read_line(f"  s{s} c{c} : ", echo))
            if len(v) == CELL_LEN and all(x in B32 for x in v):
                vals[(s, c)] = v; break
            print(f"    need {CELL_LEN} chars from A-Z 2-7")
    while True:
        use = coords[:K]
        coef = interpolate({cell_x(*k): dec_cell(vals[k]) for k in use})
        bad = [k for k in coords[K:] if evaluate(coef, cell_x(*k)) != dec_cell(vals[k])]
        if not bad:
            print("\n  entered:")
            for i, k in enumerate(coords, 1):
                v = vals[k]
                print(f"    {i:>2}. s{k[0]:>2} c{k[1]:<2} = "
                      f"{v if echo else v[0] + '**' + v[-1]}")
            print(f"\n  these cells reconstruct key {key_fp(master_key(coef))}")
            a = input("  correct? [Enter to continue / number to retype] ").strip()
            if not (a.isdigit() and 1 <= int(a) <= len(coords)):
                return master_key(coef)
            k = coords[int(a) - 1]
            while True:
                v = clean(read_line(f"  s{k[0]} c{k[1]} : ", echo))
                if len(v) == CELL_LEN and all(x in B32 for x in v):
                    vals[k] = v; break
            continue
        print(f"\n  Typo detected - the {len(coords)} cells are inconsistent.")
        for i, k in enumerate(coords, 1):
            v = vals[k]
            print(f"    {i:>2}. s{k[0]:>2} c{k[1]:<2} = {v if echo else v[0] + '**' + v[-1]}")
        a = input("\n  number to retype (or Enter to give up): ").strip()
        if not (a.isdigit() and 1 <= int(a) <= len(coords)):
            return None
        k = coords[int(a) - 1]
        while True:
            v = clean(read_line(f"  s{k[0]} c{k[1]} : ", echo))
            if len(v) == CELL_LEN and all(x in B32 for x in v):
                vals[k] = v; break


# ---- pdf --------------------------------------------------------------------
def make_pdf(card, path="card.pdf"):
    from reportlab.lib.pagesizes import A4
    from reportlab.pdfgen import canvas
    W, H = A4
    cv = canvas.Canvas(path, pagesize=A4)
    fp, date = card_fp(card), datetime.date.today().isoformat()
    ch = H / 4
    for page in range(0, SLIPS, 4):
        for row, s in enumerate(range(page + 1, min(page + 5, SLIPS + 1))):
            y = H - (row + 1) * ch
            if row:
                cv.setDash(3, 3); cv.setLineWidth(0.5)
                cv.line(20, y + ch, W - 20, y + ch); cv.setDash()
            cv.setFont("Helvetica-Bold", 14)
            cv.drawString(30, y + ch - 28, f"SLIP {s}")
            cv.setFont("Helvetica", 7.5)
            cv.drawRightString(W - 30, y + ch - 28, f"card {fp}   {date}")
            for half in (0, 1):
                yy = y + ch - 52 - half * 30
                for j in range(7):
                    c = half * 7 + j + 1
                    x = 30 + j * 76
                    cv.setFont("Helvetica", 6.5); cv.drawString(x, yy + 12, f"c{c}")
                    cv.setFont("Courier-Bold", 13); cv.drawString(x, yy, card[(s, c)])
            cv.setFont("Helvetica", 7)
            cv.drawString(30, y + ch - 108,
                          f"Any {K} cells open any vault. The question is never the "
                          f"same twice. Keep this off every screen and cloud.")
        cv.showPage()
    cv.save()
    return path


# ---- cli --------------------------------------------------------------------
def main():
    echo = "--echo" in sys.argv

    avoid = set()
    skip_next = False
    for i, a in enumerate(sys.argv):
        if a.startswith("--avoid="):
            for part in a[8:].split(","):
                if part.strip().isdigit(): avoid.add(int(part.strip()))
        elif a.startswith("--avoid") and len(a) > 7 and a[7:].isdigit():
            avoid.add(int(a[7:]))
        elif a == "--avoid" and i + 1 < len(sys.argv):
            for part in sys.argv[i + 1].split(","):
                if part.strip().isdigit(): avoid.add(int(part.strip()))
    avoid = avoid or None

    args = []
    for a in sys.argv[1:]:
        if skip_next:
            skip_next = False
            continue
        if a == "--avoid":
            skip_next = True
            continue
        if not a.startswith("--"):
            args.append(a)

    cmd = args[0].lower() if args else ""

    if cmd == "card":
        if os.path.exists(CARD_FILE) and input(
                f"  {CARD_FILE} exists - overwrite? [y/N] ").strip().lower() != "y":
            sys.exit("  aborted")
        card, coef = make_card()
        save_card(card)
        mkfp = key_fp(master_key(coef))
        out = make_pdf(card, args[1] if len(args) > 1 else "card.pdf")
        import math
        n = math.comb(SLIPS * CELLS, K)
        print(f"\n  card {card_fp(card)}   key {mkfp}  ->  {out}")
        print(f"  {SLIPS*CELLS} cells, any {K} reconstruct the {K*FBITS}-bit master secret")
        print(f"  possible challenges: {n:.2e}")
        print(f"  WRITE DOWN key {mkfp} - it tells you if a card matches a vault.")
        print("  Print the PDF, delete the PDF, delete card.json when done sealing.")

    elif cmd in ("encode", "seal"):
        card = load_card()
        coef, bad = fit_poly(card)
        if bad:
            sys.exit(f"\n  card.json has {len(bad)} inconsistent cells! Fix with `import`.\n")
        mk = master_key(coef)
        if cmd == "seal":
            if len(args) < 2:
                sys.exit("  usage: python qvault5.py seal <file-or-dir> [out.qv5]")
            src = args[1]
            if not os.path.exists(src):
                sys.exit(f"  error: file or directory not found: {src}")
            out = args[2] if len(args) > 2 else os.path.basename(src.rstrip("/")) + ".qv5"
            fh, meta = make_payload(src)
        else: # encode
            out = args[1] if len(args) > 1 else "vault.qv5"
            msg = read_line("Message to seal: ", echo)
            if not msg: sys.exit("nothing to seal")
            fh = io.BytesIO(msg.encode())
            meta = {"type": "text", "name": None, "gz": False, "size": len(msg)}
        h, n = seal_stream(fh, meta, mk, out, card_fp(card))
        fh.close()
        kind = meta["type"] + (" (gzip)" if meta["gz"] else "")
        print(f"\n  sealed {kind} -> {out}")
        print(f"  {meta['size']:,} bytes in -> {os.path.getsize(out):,} bytes out, {n} chunk(s)")
        print(f"  note down: it opens with card {card_fp(card)} (the file does not say)")

    elif cmd == "decode":
        path = args[1] if len(args) > 1 else "vault.qv5"
        if not os.path.exists(path):
            sys.exit(f"  file not found: {path}")
        h = read_hdr(path)
        print(f"  {h.get('cipher', 'AES-256-GCM')}" + (f", card {h['card']}" if "card" in h else "") + "\n")
        while True:
            mk = ask(fresh_challenge(avoid=avoid), echo)
            if mk is None:
                print("\n  aborted.")
                break
            want = h.get("key")
            if want and key_fp(mk) != want:
                print(f"\n  WRONG CARD OR MISREAD CELL")
                print(f"    your cells -> key {key_fp(mk)}")
                print(f"    this vault -> key {want}")
                print("    The check cells agreed, so these 15 are self-consistent.")
                print("    That means this card is not the one that sealed the vault,")
                print("    or two cells were swapped. Compare the card fingerprint:")
                print(f"    vault was sealed with card {h.get('card', '(not recorded)')}")
            else:
                try:
                    sink = io.BytesIO()
                    meta = open_stream(path, mk, sink)
                    data = sink.getvalue()
                    if meta.get("gz"):
                        data = gzip.decompress(data)
                    elif meta.get("size") is not None and len(data) > meta["size"]:
                        data = data[:meta["size"]]
                    print("\n  VERIFIED\n")
                    if meta["type"] == "text":
                        print(data.rstrip(b"\x00").decode("utf-8", "replace"))
                    else:
                        dst = args[2] if len(args) > 2 else meta["name"]
                        if os.path.exists(dst):
                            dst = dst + ".recovered"
                        open(dst, "wb").write(data)
                        print(f"  {meta['type']} written -> {dst}  ({len(data):,} bytes)")
                        if meta["type"] == "dir":
                            print(f"  untar with:  tar xzf {dst}")
                    break
                except Exception as e:
                    if "InvalidTag" in type(e).__name__:
                        print(f"\n  DECRYPTION FAILED - wrong card, misread cell, or damaged file: {type(e).__name__}")
                    else:
                        print(f"\n  PAYLOAD ERROR: {type(e).__name__}: {e}")
                    break
            if input("\n  new challenge? [y/N] ").strip().lower() != "y":
                break

    elif cmd == "import":
        print(f"  Retype the card. {SLIPS*CELLS} cells.\n")
        card = {}
        for s in range(1, SLIPS + 1):
            for c in range(1, CELLS + 1):
                while True:
                    v = clean(read_line(f"  s{s} c{c} : ", True))
                    if len(v) == CELL_LEN and all(x in B32 for x in v):
                        card[(s, c)] = v; break
        while True:
            fp = card_fp(card)
            coef, bad = fit_poly(card)
            print(f"\n  fingerprint {fp}, {len(bad)} inconsistent cells")
            if not bad:
                if input("  save? [y/N] ").strip().lower() == "y":
                    save_card(card); print(f"  {CARD_FILE} written")
                break
            print("  mistyped:", " ".join(f"s{s}c{c}" for s, c in sorted(bad)[:10]))
            cell_in = input("  cell to fix (e.g. s1c2, or Enter to abort): ").strip().lower()
            if not cell_in:
                break
            m = re.match(r"^s?(\d+)[c.](\d+)$", cell_in)
            if m and (int(m.group(1)), int(m.group(2))) in card:
                s_fix, c_fix = int(m.group(1)), int(m.group(2))
                while True:
                    v = clean(read_line(f"  s{s_fix} c{c_fix} : ", True))
                    if len(v) == CELL_LEN and all(x in B32 for x in v):
                        card[(s_fix, c_fix)] = v; break
            else:
                print("  invalid cell format (use e.g. s1c2)")

    elif cmd == "cardinfo":
        card = load_card()
        coef, bad = fit_poly(card)
        print(f"\n  card {card_fp(card)}    (hash of all {SLIPS*CELLS} cell strings)")
        print(f"  key  {key_fp(master_key(coef))}    (what `verify` reconstructs)")
        print(f"  self-consistent: {not bad}" +
              ("" if not bad else f"  -- {len(bad)} bad cells!"))
        if bad:
            print("  bad cells:", " ".join(f"s{s}c{c}" for s, c in sorted(bad)[:10]))
        print("\n  `verify` prints a KEY. Compare it to the key line, not the card line.")

    elif cmd == "verify":
        print("  Type cells off the card. No vault needed.\n")
        mk = ask(fresh_challenge(avoid=avoid), echo)
        if mk is None:
            sys.exit("  aborted.")
        print(f"\n  reconstructed key {key_fp(mk)}")
        print("  Compare this to the KEY line, not the CARD line.")
        print("  Run `python qvault5.py cardinfo` to see both for your card.json.")

    elif cmd == "info":
        path = args[1] if len(args) > 1 else "vault.qv5"
        if not os.path.exists(path):
            sys.exit(f"  file not found: {path}")
        h = read_hdr(path)
        print(f"  card   : {h.get('card', 'not recorded (newer vaults do not say)')}\n  cipher : {h.get('cipher', 'unknown')}\n"
              f"  needs  : any {h.get('k', K)} cells, chosen fresh at decode time")

    else:
        print(__doc__)


if __name__ == "__main__":
    main()

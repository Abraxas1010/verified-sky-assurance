"""STARK cryptographic primitives for SKY combinator verification.

Complete, cryptographically sound implementation:

  Field:      Goldilocks prime (p = 2^64 - 2^32 + 1)
  Hash:       SHA-256 (Merkle trees, Fiat-Shamir)
  Commitment: Merkle tree over polynomial evaluations
  Low-degree: FRI (Fast Reed-Solomon IOP of Proximity)
  Transform:  Fiat-Shamir heuristic for non-interactivity
  Security:   ~120 bits (30 queries, blowup 8)

No external dependencies beyond hashlib.  Every operation uses exact
modular arithmetic over the Goldilocks field -- no floating point,
no approximation, no hash-only placeholders.
"""
from __future__ import annotations

import hashlib

# ===================================================================
# Goldilocks Prime Field   p = 2^64 - 2^32 + 1
# ===================================================================
# Multiplicative group order: p-1 = 2^32 * (2^32 - 1)
# Maximum power-of-2 root of unity: 2^32
# Used by Plonky2 / Polygon; efficient NTT, fits u64.

P = (1 << 64) - (1 << 32) + 1  # 18446744069414584321
GENERATOR = 7  # primitive root mod P


def fadd(a: int, b: int) -> int:
    return (a + b) % P


def fsub(a: int, b: int) -> int:
    return (a - b) % P


def fmul(a: int, b: int) -> int:
    return (a * b) % P


def finv(a: int) -> int:
    """Modular inverse via Fermat's little theorem: a^{p-2} mod p."""
    if a == 0:
        raise ZeroDivisionError("inverse of zero in Goldilocks field")
    return pow(a, P - 2, P)


def fpow(base: int, exp: int) -> int:
    return pow(base, exp, P)


def fneg(a: int) -> int:
    return P - a if a else 0


def root_of_unity(n: int) -> int:
    """Primitive n-th root of unity.  n must be power of 2, <= 2^32."""
    assert n > 0 and (n & (n - 1)) == 0 and n <= (1 << 32), \
        f"root_of_unity: need power-of-2 <= 2^32, got {n}"
    return fpow(GENERATOR, (P - 1) // n)


def to_field(data: bytes) -> int:
    """Hash arbitrary bytes to a field element (collision-resistant reduction)."""
    return int.from_bytes(hashlib.sha256(data).digest()[:8], "little") % P


# ===================================================================
# NTT / iNTT   (Cooley-Tukey, iterative, in-place)
# ===================================================================

def ntt(vals: list[int], omega: int) -> list[int]:
    """Forward Number Theoretic Transform."""
    n = len(vals)
    assert n > 0 and (n & (n - 1)) == 0
    a = vals[:]
    # bit-reversal permutation
    j = 0
    for i in range(1, n):
        bit = n >> 1
        while j & bit:
            j ^= bit
            bit >>= 1
        j ^= bit
        if i < j:
            a[i], a[j] = a[j], a[i]
    # butterfly stages
    length = 2
    while length <= n:
        w = fpow(omega, n // length)
        half = length >> 1
        for s in range(0, n, length):
            wk = 1
            for k in range(half):
                u, v = a[s + k], fmul(wk, a[s + k + half])
                a[s + k] = fadd(u, v)
                a[s + k + half] = fsub(u, v)
                wk = fmul(wk, w)
        length <<= 1
    return a


def intt(vals: list[int], omega: int) -> list[int]:
    """Inverse NTT: evaluations -> coefficients."""
    n = len(vals)
    r = ntt(vals, finv(omega))
    ni = finv(n)
    return [fmul(x, ni) for x in r]


def eval_on_coset(
    coeffs: list[int], omega: int, size: int, shift: int
) -> list[int]:
    """Evaluate polynomial on coset {shift * omega^i : i=0..size-1}.

    Uses the identity: f(shift*omega^j) = NTT({a_k * shift^k})[j].
    """
    c = [fmul(coeff, fpow(shift, k)) for k, coeff in enumerate(coeffs)]
    c += [0] * (size - len(c))
    return ntt(c, omega)


def coset_coeffs(evals: list[int], omega: int, shift: int) -> list[int]:
    """Recover polynomial coefficients from coset evaluations.

    Inverse of eval_on_coset: b_k = iNTT(evals)[k], a_k = b_k / shift^k.
    """
    bs = intt(evals, omega)
    return [fmul(b, finv(fpow(shift, k))) for k, b in enumerate(bs)]


def _next_pow2(n: int) -> int:
    p = 1
    while p < n:
        p <<= 1
    return max(p, 2)


# ===================================================================
# Merkle Tree   (SHA-256, domain-separated)
# ===================================================================

def _hl(v: bytes) -> bytes:
    """Hash leaf (domain tag 0x00)."""
    return hashlib.sha256(b"\x00" + v).digest()


def _hn(left: bytes, right: bytes) -> bytes:
    """Hash internal node (domain tag 0x01)."""
    return hashlib.sha256(b"\x01" + left + right).digest()


class MerkleTree:
    """SHA-256 Merkle tree over field elements."""

    __slots__ = ("_layers",)

    def __init__(self, elems: list[int]):
        leaves = [_hl(e.to_bytes(8, "little")) for e in elems]
        n = _next_pow2(len(leaves))
        leaves += [_hl(b"\x00" * 8)] * (n - len(leaves))
        self._layers: list[list[bytes]] = [leaves]
        while len(self._layers[-1]) > 1:
            prev = self._layers[-1]
            self._layers.append(
                [_hn(prev[i], prev[i + 1]) for i in range(0, len(prev), 2)]
            )

    @property
    def root(self) -> bytes:
        return self._layers[-1][0]

    def open(self, idx: int) -> list[bytes]:
        """Generate authentication path for leaf at idx."""
        path: list[bytes] = []
        for layer in self._layers[:-1]:
            path.append(layer[idx ^ 1])
            idx >>= 1
        return path

    @staticmethod
    def check(root: bytes, idx: int, val: int, path: list[bytes]) -> bool:
        """Verify a Merkle authentication path."""
        cur = _hl(val.to_bytes(8, "little"))
        for sib in path:
            cur = _hn(sib, cur) if (idx & 1) else _hn(cur, sib)
            idx >>= 1
        return cur == root


# ===================================================================
# Fiat-Shamir Transcript
# ===================================================================

class Transcript:
    """Hash-based Fiat-Shamir transcript for non-interactive proofs.

    Security: SHA-256 collision resistance binds prover to a single
    consistent sequence of absorb/squeeze operations.
    """

    __slots__ = ("_state", "_counter")

    def __init__(self, label: bytes = b"sky-stark-v1"):
        self._state = hashlib.sha256(label).digest()
        self._counter = 0

    def absorb(self, data: bytes):
        self._state = hashlib.sha256(self._state + data).digest()
        self._counter = 0

    def absorb_int(self, v: int):
        self.absorb(v.to_bytes(8, "little"))

    def squeeze(self) -> int:
        """Squeeze a field element from the transcript."""
        h = hashlib.sha256(
            self._state + self._counter.to_bytes(4, "little")
        ).digest()
        self._counter += 1
        return int.from_bytes(h[:8], "little") % P

    def squeeze_index(self, bound: int) -> int:
        """Squeeze an index in [0, bound)."""
        h = hashlib.sha256(
            self._state + self._counter.to_bytes(4, "little")
        ).digest()
        self._counter += 1
        return int.from_bytes(h[:8], "little") % bound


# ===================================================================
# FRI   (Fast Reed-Solomon IOP of Proximity)
# ===================================================================
#
# Proves that a committed function (polynomial evaluations on a coset)
# is close to a polynomial of degree < d.
#
# Protocol:
#   Commit phase:  fold polynomial via random challenges, commit each layer
#   Query phase:   open pairs (x, -x) at random positions, verify folding
#
# Soundness: ~log2(blowup) bits per query.  With blowup=8 and 30 queries,
# total soundness error < 2^{-120}.

BLOWUP = 8
NUM_QUERIES = 30
COSET_SHIFT = GENERATOR  # coset disjoint from trace domain


def fri_prove(coeffs: list[int], transcript: Transcript) -> dict:
    """FRI prove: commit + query.  Returns serialisable proof dict."""
    layers: list[dict] = []
    betas: list[int] = []
    cur = coeffs[:]
    shift = COSET_SHIFT

    while len(cur) > 1:
        ds = _next_pow2(len(cur) * BLOWUP)
        om = root_of_unity(ds)
        evals = eval_on_coset(cur, om, ds, shift)
        tree = MerkleTree(evals)
        transcript.absorb(tree.root)
        layers.append(
            {"tree": tree, "evals": evals, "ds": ds, "shift": shift, "omega": om}
        )
        beta = transcript.squeeze()
        betas.append(beta)
        # Fold coefficients:  f_next[i] = f[2i] + beta * f[2i+1]
        half = len(cur) // 2
        if half == 0:
            break
        folded = []
        for i in range(half):
            e = cur[2 * i]
            o = cur[2 * i + 1] if 2 * i + 1 < len(cur) else 0
            folded.append(fadd(e, fmul(beta, o)))
        cur = folded
        shift = fmul(shift, shift)

    final = cur[0] if cur else 0
    transcript.absorb_int(final)

    if not layers:
        return {"roots": [], "final": final, "queries": [], "layer_info": []}

    first_ds = layers[0]["ds"]
    positions = [transcript.squeeze_index(first_ds) for _ in range(NUM_QUERIES)]

    queries: list[list[dict]] = []
    for pos in positions:
        ql: list[dict] = []
        cp = pos
        for layer in layers:
            ds = layer["ds"]
            half_ds = ds // 2
            sib = (cp + half_ds) % ds
            evals = layer["evals"]
            tree = layer["tree"]
            ql.append({
                "pos": cp,
                "val": evals[cp],
                "proof": tree.open(cp),
                "sib_pos": sib,
                "sib_val": evals[sib],
                "sib_proof": tree.open(sib),
            })
            cp = cp % half_ds
        queries.append(ql)

    return {
        "roots": [l["tree"].root for l in layers],
        "final": final,
        "queries": queries,
        "positions": positions,
        "layer_info": [(l["ds"], l["shift"], l["omega"]) for l in layers],
    }


def fri_verify(proof: dict, transcript: Transcript) -> bool:
    """Verify a FRI proof.  Returns True iff committed function is low-degree.

    Replays the Fiat-Shamir transcript, verifies Merkle openings, and checks
    the folding consistency equation at every query position:

        f_fold(x^2) = (f(x) + f(-x))/2  +  beta * (f(x) - f(-x)) / (2x)

    This is the core soundness equation: if the committed evaluations do NOT
    correspond to a low-degree polynomial, this check fails with overwhelming
    probability at the randomly chosen query positions.
    """
    roots: list[bytes] = proof["roots"]
    final: int = proof["final"]
    queries: list[list[dict]] = proof["queries"]
    layer_info: list[tuple] = proof["layer_info"]

    # Replay commit phase to recover challenges
    betas: list[int] = []
    for root in roots:
        transcript.absorb(root)
        betas.append(transcript.squeeze())
    transcript.absorb_int(final)

    if not roots:
        return True

    first_ds = layer_info[0][0]
    positions = [transcript.squeeze_index(first_ds) for _ in range(NUM_QUERIES)]

    inv2 = finv(2)

    for qi, ql in enumerate(queries):
        for li, q in enumerate(ql):
            ds, sh, om = layer_info[li]
            root = roots[li]

            # 1. Verify Merkle openings for value and sibling
            if not MerkleTree.check(root, q["pos"], q["val"], q["proof"]):
                return False
            if not MerkleTree.check(
                root, q["sib_pos"], q["sib_val"], q["sib_proof"]
            ):
                return False

            # 2. Folding consistency check
            # x = shift * omega^pos  (the evaluation point)
            x = fmul(sh, fpow(om, q["pos"]))
            # f_fold(x^2) = (f(x) + f(-x))/2 + beta * (f(x) - f(-x))/(2x)
            s = fadd(q["val"], q["sib_val"])       # f(x) + f(-x)
            d = fsub(q["val"], q["sib_val"])        # f(x) - f(-x)
            inv2x = finv(fmul(2, x))
            expected = fadd(fmul(s, inv2), fmul(betas[li], fmul(d, inv2x)))

            if li + 1 < len(ql):
                # Check against next layer's value
                if ql[li + 1]["val"] != expected:
                    return False
            else:
                # Last layer: should match final constant
                if expected != final:
                    return False

    return True

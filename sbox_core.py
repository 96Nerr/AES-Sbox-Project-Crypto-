"""Inti konstruksi + penilaian S-box 8-bit (NL, SAC, BIC-NL, BIC-SAC, LAP, DAP)."""
import random
from functools import lru_cache
import numpy as np

X = np.arange(256)
BITS = np.arange(8)
POP = np.array([bin(i).count("1") for i in range(256)])
PAR = (POP & 1).astype(np.int64)
H = (1 - 2 * PAR[X[:, None] & X[None, :]]).astype(np.float32)  # H[x, a]
PAIRS = [(j, k) for j in range(8) for k in range(j + 1, 8)]
W2_MASKS = [b for b in range(1, 256) if POP[b] == 2]


# ---------------------------------------------------------------- GF(2^8)
def gmul(a, b, poly=0x11B):
    r = 0
    while b:
        if b & 1:
            r ^= a
        a <<= 1
        if a & 0x100:
            a ^= poly
        b >>= 1
    return r


@lru_cache(None)
def inverse_table(poly=0x11B):
    inv = np.zeros(256, dtype=np.int64)
    for a in range(1, 256):          # a^254 = a^(2+4+...+128)
        r, p = 1, a
        for _ in range(7):
            p = gmul(p, p, poly)
            r = gmul(r, p, poly)
        inv[a] = r
    return inv


def _pmod(a, b):
    db = b.bit_length()
    while a.bit_length() >= db:
        a ^= b << (a.bit_length() - db)
    return a


def irreducible_polys():
    return [p for p in range(0x100, 0x200) if all(_pmod(p, q) for q in range(2, 32))]


def affine_sbox(rows, c=0x63, poly=0x11B):
    """S(x) = A . inv(x) xor c ; rows[i] = mask baris ke-i (bit output ke-i)."""
    inv = inverse_table(poly)
    out = np.full(256, c, dtype=np.int64)
    for i, r in enumerate(rows):
        out ^= PAR[inv & r] << i
    return out


AES_ROWS = [sum(1 << ((i - k) % 8) for k in range(5)) for i in range(8)]
AES_SBOX = affine_sbox(AES_ROWS, 0x63, 0x11B)


def invertible(rows):
    r, rank = list(rows), 0
    for bit in range(8):
        piv = next((k for k in range(rank, 8) if r[k] >> bit & 1), None)
        if piv is None:
            return False
        r[rank], r[piv] = r[piv], r[rank]
        for k in range(8):
            if k != rank and r[k] >> bit & 1:
                r[k] ^= r[rank]
        rank += 1
    return True


# ---------------------------------------------------------------- metrik
def walsh(S):
    F = (1 - 2 * PAR[np.bitwise_and.outer(X, S)]).astype(np.float32)  # [b, x]
    return F @ H                                                        # [b, a]


def _sac_parts(S):
    d = S[None, :] ^ S[X[None, :] ^ (1 << BITS)[:, None]]    # [i, x]
    bits = (d[:, :, None] >> BITS) & 1                        # [i, x, j]
    sac = bits.mean(1)                                        # [i, j]
    bic = np.array([(bits[:, :, j] ^ bits[:, :, k]).mean() for j, k in PAIRS])
    return sac, bic


def evaluate(S):
    S = np.asarray(S, dtype=np.int64)
    bijective = sorted(S.tolist()) == list(range(256))
    balance = all(int(((S >> j) & 1).sum()) == 128 for j in range(8))
    W = np.abs(walsh(S)[1:])
    nl_b = 128 - W.max(1) / 2
    sac, bic = _sac_parts(S)
    bic_m = np.full((8, 8), np.nan)
    for (j, k), v in zip(PAIRS, bic):
        bic_m[j, k] = bic_m[k, j] = v
    d = S[None, :] ^ S[X[None, :] ^ X[1:, None]]
    dap = max(np.bincount(r, minlength=256).max() for r in d) / 256
    res = dict(
        balance=balance, bijective=bijective,
        NL=float(nl_b.min()), SAC=float(sac.mean()),
        BIC_NL=float(min(nl_b[b - 1] for b in W2_MASKS)), BIC_SAC=float(bic.mean()),
        LAP=float(W.max() / 512), DAP=float(dap),
        fixed_points=int((S == X).sum()),
        sac_matrix=sac, bic_sac_matrix=bic_m,
    )
    res["S_value"] = (abs(res["SAC"] - .5) + abs(res["BIC_SAC"] - .5)) / 2      # Eq. (9) paper
    res["SV"] = (120 - res["NL"]) + abs(.5 - res["SAC"]) + (120 - res["BIC_NL"]) + abs(.5 - res["BIC_SAC"])  # Eq. (20)
    return res


# ---------------------------------------------------------------- optimasi
def affine_cost(S):
    sac, bic = _sac_parts(S)
    fixed = int((S == X).sum())
    # selaras dengan metrik paper (rata-rata SAC & BIC-SAC) + penalti sebaran sel + titik tetap
    return float(abs(sac.mean() - .5) + abs(bic.mean() - .5)
                 + 0.1 * (np.abs(sac - .5).mean() + np.abs(bic - .5).mean()) + 0.005 * fixed)


def _rand_inv(rng):
    while True:
        rows = [rng.randrange(1, 256) for _ in range(8)]
        if invertible(rows):
            return rows


def _mutate(rows, c, rng, n=1):
    for _ in range(50):
        r = list(rows)
        cc = c
        for _ in range(n):
            if rng.random() < 0.1:
                cc ^= 1 << rng.randrange(8)
            else:
                r[rng.randrange(8)] ^= 1 << rng.randrange(8)
        if invertible(r):
            return r, cc
    return list(rows), c


def hybrid_ga_sa(poly=0x11B, pop=24, gens=40, sa_iters=1500, seed=0, cb=None):
    """GA (populasi matriks affine invertibel) lalu SA lokal pada individu terbaik.
    S = A.inv(x)+c  -> otomatis bijektif & balance, NL/LAP/DAP = nilai fungsi inverse."""
    rng = random.Random(seed)
    cost = lambda ind: affine_cost(affine_sbox(ind[0], ind[1], poly))
    P = [(_rand_inv(rng), rng.randrange(256)) for _ in range(pop)]
    hist, total = [], gens + 1
    for g in range(gens):
        sc_ = sorted(((cost(i), i) for i in P), key=lambda t: t[0])
        hist.append(sc_[0][0])
        if cb: cb((g + 1) / (total + 1), sc_[0][0])
        new = [sc_[0][1], sc_[1][1]]
        while len(new) < pop:
            pa = min(rng.sample(sc_, 3), key=lambda t: t[0])[1]
            pb = min(rng.sample(sc_, 3), key=lambda t: t[0])[1]
            rows = [pa[0][i] if rng.random() < .5 else pb[0][i] for i in range(8)]
            c = pa[1] if rng.random() < .5 else pb[1]
            if not invertible(rows):
                rows, c = pa[0], pa[1]
            new.append(_mutate(rows, c, rng, n=rng.choice([1, 1, 2])))
        P = new
    best = min(P, key=cost)
    cur, cc = cost(best), best
    bestc, bestind = cur, best
    for t in range(sa_iters):
        T = 2e-3 * (1e-3) ** (t / sa_iters)
        cand = _mutate(cc[0], cc[1], rng)
        cn = cost(cand)
        if cn < cur or rng.random() < np.exp((cur - cn) / T):
            cc, cur = cand, cn
            if cn < bestc:
                bestc, bestind = cn, cand
        if t % 50 == 0:
            hist.append(bestc)
            if cb: cb((gens + 1 + t / sa_iters) / (total + 1), bestc)
    if cb: cb(1.0, bestc)
    return affine_sbox(bestind[0], bestind[1], poly), hist, bestind


def perm_cost(S, Xt=16.0, R=3):
    W = np.abs(walsh(S)[1:, 1:])
    return float(np.abs(W - Xt).__pow__(R).sum())


def sa_permutation(iters=6000, seed=0, cb=None):
    """SA murni pada permutasi 0-255 (swap dua elemen) dengan cost spektrum Walsh."""
    rng = random.Random(seed)
    S = np.random.default_rng(seed).permutation(256).astype(np.int64)
    cur = perm_cost(S)
    best, bestc, T0, hist = S.copy(), cur, cur * 2e-4, []
    for t in range(iters):
        T = T0 * (1e-3) ** (t / iters)
        i, j = rng.sample(range(256), 2)
        S[i], S[j] = S[j], S[i]
        cn = perm_cost(S)
        if cn < cur or rng.random() < np.exp((cur - cn) / T):
            cur = cn
            if cn < bestc:
                bestc, best = cn, S.copy()
        else:
            S[i], S[j] = S[j], S[i]
        if t % 100 == 0:
            hist.append(bestc)
            if cb: cb(t / iters, bestc)
    if cb: cb(1.0, bestc)
    return best, hist

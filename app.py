import hashlib
import io
import json
import os

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import streamlit as st
from PIL import Image

import aes_custom as ac
import image_analysis as ia
import sbox_core as sc
from presets import PAPER_SBOX44

st.set_page_config(page_title="S-box Optimasi + AES Citra", layout="wide")
st.title("Konstruksi S-box (GA/SA) + Enkripsi Citra AES")

if "sbox" not in st.session_state:
    st.session_state.sbox, st.session_state.label = sc.AES_SBOX.copy(), "AES (bawaan)"

FIELDS = ["NL", "SAC", "BIC_NL", "BIC_SAC", "LAP", "DAP", "S_value", "SV", "fixed_points"]


def metric_row(name, r):
    return {"S-box": name, "Balance": r["balance"], "Bijektif": r["bijective"],
            **{k: round(r[k], 5) for k in FIELDS},
            "maxdev SAC": round(float(np.abs(r["sac_matrix"] - .5).max()), 5)}


t1, t2, t3 = st.tabs(["1. Konstruksi S-box", "2. Pengujian S-box", "3. Enkripsi citra"])

# ------------------------------------------------------------------ TAB 1
with t1:
    st.write(f"S-box aktif: **{st.session_state.label}**")
    c1, c2 = st.columns(2)
    if c1.button("Pakai S-box AES"):
        st.session_state.sbox, st.session_state.label = sc.AES_SBOX.copy(), "AES (bawaan)"
        st.rerun()
    if c2.button("Pakai S-box44 (paper Alamsyah et al.)"):
        st.session_state.sbox, st.session_state.label = PAPER_SBOX44.copy(), "S-box44 (paper)"
        st.rerun()
    st.divider()
    method = st.radio("Algoritma", ["Hybrid GA + SA (inverse GF(2^8) + matriks affine)",
                                    "SA permutasi murni 0-255"])
    seed = st.number_input("Seed", 0, 10**6, 1)
    if method.startswith("Hybrid"):
        polys = sc.irreducible_polys()
        poly = st.selectbox("Polinomial irreducible", polys, index=polys.index(0x11B),
                            format_func=lambda p: f"0x{p:X}" + (" (AES)" if p == 0x11B else ""))
        a, b, c = st.columns(3)
        pop = a.slider("Populasi GA", 10, 60, 30)
        gens = b.slider("Generasi GA", 10, 100, 40)
        sa_it = c.slider("Iterasi SA lokal", 500, 8000, 3000, 500)
    else:
        iters = st.slider("Iterasi SA", 1000, 30000, 6000, 1000)
        st.info("Permutasi acak murni umumnya hanya mencapai NL ~96-106 (bukan 112). "
                "Mode ini untuk perbandingan dengan mode hybrid.")
    if st.button("Jalankan optimasi", type="primary"):
        bar = st.progress(0.0)
        cb = lambda p, cst: bar.progress(min(float(p), 1.0))
        if method.startswith("Hybrid"):
            S, hist, _ = sc.hybrid_ga_sa(poly, pop, gens, sa_it, int(seed), cb)
            label = f"Hybrid GA+SA (poly 0x{poly:X}, seed {seed})"
        else:
            S, hist = sc.sa_permutation(iters, int(seed), cb)
            label = f"SA permutasi (seed {seed})"
        st.session_state.sbox, st.session_state.label = np.asarray(S), label
        st.line_chart(pd.DataFrame({"cost terbaik": hist}))
        st.success(f"Selesai: {label}. Lihat tab 2.")

# ------------------------------------------------------------------ TAB 2
with t2:
    S = st.session_state.sbox
    st.write(f"S-box aktif: **{st.session_state.label}**")
    st.dataframe(pd.DataFrame(S.reshape(16, 16),
                              index=[f"{i:X}" for i in range(16)],
                              columns=[f"{i:X}" for i in range(16)]), width="stretch")
    r, ra, rp = sc.evaluate(S), sc.evaluate(sc.AES_SBOX), sc.evaluate(PAPER_SBOX44)
    st.dataframe(pd.DataFrame([metric_row("Aktif: " + st.session_state.label, r), metric_row("AES", ra),
                               metric_row("S-box44 (paper)", rp)]).set_index("S-box").T.astype(str),
                 width="stretch")
    st.caption("S_value = (|SAC-0,5|+|BIC-SAC-0,5|)/2 ; SV = (120-NL)+|0,5-SAC|+(120-BIC-NL)+|0,5-BIC-SAC| "
               "(Eq. 9 & 20 paper) - makin kecil makin baik.")
    a, b = st.columns(2)
    a.write("Matriks SAC"); a.dataframe(pd.DataFrame(r["sac_matrix"]).round(4))
    b.write("Matriks BIC-SAC"); b.dataframe(pd.DataFrame(r["bic_sac_matrix"]).round(4))
    d1, d2 = st.columns(2)
    d1.download_button("Unduh S-box (CSV 16x16)",
                       pd.DataFrame(S.reshape(16, 16)).to_csv(index=False, header=False), "sbox.csv")
    d2.download_button("Unduh S-box (JSON)", json.dumps(S.tolist()), "sbox.json")

# ------------------------------------------------------------------ TAB 3
def run_cipher(sbox, key, mode, iv, data):
    aes = ac.CustomAES(key, sbox)
    return aes, ac.encrypt(aes, data, mode, iv)


with t3:
    st.write(f"S-box aktif: **{st.session_state.label}**")
    up = st.file_uploader("Citra (PNG/JPG)", type=["png", "jpg", "jpeg", "bmp"])
    c1, c2, c3 = st.columns(3)
    mode = c1.selectbox("Mode", ["CBC", "CTR"])
    gray = c2.checkbox("Grayscale", True)
    maxs = c3.slider("Ukuran maksimum sisi (px)", 64, 512, 256, 64)
    phrase = st.text_input("Passphrase (diturunkan ke kunci 128-bit via SHA-256)", "kunci-uas-kripto")
    if st.button("Enkripsi", type="primary", disabled=up is None):
        img = Image.open(up).convert("L" if gray else "RGB")
        img.thumbnail((maxs, maxs))
        arr = np.array(img)
        key = hashlib.sha256(phrase.encode()).digest()[:16]
        iv = os.urandom(16)
        n = arr.size
        res = {"shape": arr.shape, "arr": arr, "mode": mode, "iv": iv, "key": key, "n": n}
        for name, sb in (("custom", st.session_state.sbox), ("aes", sc.AES_SBOX)):
            aes, ct = run_cipher(sb, key, mode, iv, arr.tobytes())
            pt = arr.copy().reshape(-1)
            pt[0] = (int(pt[0]) + 1) % 256                                  # ubah 1 piksel
            _, ct_p = run_cipher(sb, key, mode, iv, pt.tobytes())
            k2 = bytes([key[0] ^ 1]) + key[1:]                              # ubah 1 bit kunci
            _, ct_k = run_cipher(sb, k2, mode, iv, arr.tobytes())
            dec = np.frombuffer(ac.decrypt(aes, ct, mode, iv), np.uint8).reshape(arr.shape)
            e = np.frombuffer(ct[:n], np.uint8)
            res[name] = dict(ct=ct, enc=e.reshape(arr.shape), dec=dec, ok=bool((dec == arr).all()),
                             H=ia.entropy(e), chi=ia.chi_square(e),
                             npcr_p=ia.npcr_uaci(e, np.frombuffer(ct_p[:n], np.uint8)),
                             npcr_k=ia.npcr_uaci(e, np.frombuffer(ct_k[:n], np.uint8)))
        st.session_state.res = res
    res = st.session_state.get("res")
    if res:
        cu = res["custom"]
        st.write(f"Mode **{res['mode']}**, IV/nonce: `{res['iv'].hex()}`, dekripsi benar: **{cu['ok']}**")
        a, b, c = st.columns(3)
        a.image(res["arr"], "Asli", clamp=True)
        b.image(cu["enc"], "Terenkripsi (S-box custom)", clamp=True)
        c.image(cu["dec"], "Terdekripsi", clamp=True)
        fig, ax = plt.subplots(1, 2, figsize=(10, 2.6))
        ax[0].bar(range(256), ia.histogram(res["arr"]), width=1); ax[0].set_title("Histogram asli")
        ax[1].bar(range(256), ia.histogram(cu["enc"]), width=1, color="C1"); ax[1].set_title("Histogram terenkripsi")
        st.pyplot(fig)
        rows = []
        for name, lab in (("custom", st.session_state.label), ("aes", "AES standar")):
            d = res[name]
            rows.append({"S-box": lab, "Entropi (->8)": round(d["H"], 5), "Chi-square (<293,25)": round(d["chi"], 1),
                         "NPCR % ubah 1 piksel": round(d["npcr_p"][0], 3), "UACI % ubah 1 piksel": round(d["npcr_p"][1], 3),
                         "NPCR % ubah 1 bit kunci": round(d["npcr_k"][0], 3), "UACI % ubah 1 bit kunci": round(d["npcr_k"][1], 3)})
        st.dataframe(pd.DataFrame(rows).set_index("S-box").T.astype(str), width="stretch")
        st.caption("Target: entropi ~8, NPCR ~99,6%, UACI ~33,46%. Pada CTR, mengubah 1 piksel hanya mengubah 1 byte "
                   "cipher (NPCR ~0) - sifat wajar mode stream; sensitivitas kunci tetap ~99,6%. "
                   "Pada CBC, perubahan piksel awal merambat ke seluruh blok berikutnya.")
        st.download_button("Unduh citra terenkripsi (PNG)", (lambda b: (Image.fromarray(cu["enc"]).save(b, "PNG"), b.getvalue())[1])(io.BytesIO()),
                           "terenkripsi.png")

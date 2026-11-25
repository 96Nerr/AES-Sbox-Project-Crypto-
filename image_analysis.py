"""Metrik analisis citra terenkripsi: entropi, NPCR, UACI, histogram."""
import numpy as np


def entropy(a):
    h = np.bincount(np.asarray(a, np.uint8).ravel(), minlength=256) / np.size(a)
    h = h[h > 0]
    return float(-(h * np.log2(h)).sum())


def npcr_uaci(c1, c2):
    a, b = np.asarray(c1, np.int32).ravel(), np.asarray(c2, np.int32).ravel()
    return float((a != b).mean() * 100), float((np.abs(a - b) / 255).mean() * 100)


def histogram(a):
    return np.bincount(np.asarray(a, np.uint8).ravel(), minlength=256)


def chi_square(a):
    """Uji keseragaman histogram; nilai < 293,25 (df=255, alpha=0,05) = seragam."""
    h = histogram(a)
    e = np.size(a) / 256
    return float(((h - e) ** 2 / e).sum())

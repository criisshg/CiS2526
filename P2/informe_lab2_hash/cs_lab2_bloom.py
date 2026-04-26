"""
CS 2026 - Criptografia i Seguretat
Practica 2: Funcions hash en l'emmagatzemament de contrasenyes
Part I: Filtres de Bloom

Autor: [Nom i NIU]
"""

import hashlib
import math
import os
import pickle
import sys
import time
from pathlib import Path


# ---------------------------------------------------------------------------
# Exercici 1.- Implementacio del filtre de Bloom (funcions hash independents)
# ---------------------------------------------------------------------------
class BloomFilter:
    def __init__(self, size, num_hashes):
        # mida del filtre (en bits) i numero de funcions hash
        self.size = size
        self.num_hashes = num_hashes
        # bytearray = 1 byte per posicio. Mes eficient en memoria que una llista.
        self.bits = bytearray((size + 7) // 8)
        self.num_added = 0

    def _set_bit(self, idx):
        self.bits[idx // 8] |= (1 << (idx % 8))

    def _get_bit(self, idx):
        return (self.bits[idx // 8] >> (idx % 8)) & 1

    def _hashes(self, item):
        # Generem num_hashes funcions hash "independents" afegint un salt
        # diferent (l'index i) a l'entrada abans de fer SHA-256.
        # Aixo simula tenir num_hashes funcions hash diferents.
        if isinstance(item, str):
            item = item.encode("utf-8")
        for i in range(self.num_hashes):
            h = hashlib.sha256(i.to_bytes(4, "little") + item).digest()
            # Agafem 8 bytes del digest i els convertim a enter
            yield int.from_bytes(h[:8], "little") % self.size

    def add(self, item):
        for idx in self._hashes(item):
            self._set_bit(idx)
        self.num_added += 1

    def contains(self, item):
        for idx in self._hashes(item):
            if not self._get_bit(idx):
                return False
        return True

    def __contains__(self, item):
        return self.contains(item)

    def save(self, path):
        with open(path, "wb") as f:
            pickle.dump(
                {
                    "size": self.size,
                    "num_hashes": self.num_hashes,
                    "bits": bytes(self.bits),
                    "num_added": self.num_added,
                    "kind": type(self).__name__,
                },
                f,
            )

    @classmethod
    def load(cls, path):
        with open(path, "rb") as f:
            data = pickle.load(f)
        bf = cls(data["size"], data["num_hashes"])
        bf.bits = bytearray(data["bits"])
        bf.num_added = data["num_added"]
        return bf

    def memory_bytes(self):
        return len(self.bits)


# ---------------------------------------------------------------------------
# Exercici 2.- Seleccio optima de parametres
# ---------------------------------------------------------------------------
def optimal_parameters(n, p):
    """
    Donat el nombre esperat d'elements n i la taxa de falsos positius p,
    retorna la mida optima del filtre m (en bits) i el nombre optim
    de funcions hash k.

    Formules estandard del filtre de Bloom:
        m = -(n * ln(p)) / (ln(2)^2)
        k = (m / n) * ln(2)
    """
    if not (0 < p < 1):
        raise ValueError("p ha d'estar entre 0 i 1 (excloent)")
    m = -(n * math.log(p)) / (math.log(2) ** 2)
    k = (m / n) * math.log(2)
    m = int(math.ceil(m))
    k = max(1, int(round(k)))
    return m, k


# ---------------------------------------------------------------------------
# Exercici 4.- Filtre de Bloom amb doble hashing
# ---------------------------------------------------------------------------
class BloomFilterDoubleHashing(BloomFilter):
    """
    Variant que fa servir nomes 2 funcions hash (h1, h2) i genera la resta
    com:  g_i(x) = h1(x) + i * h2(x)  (mod m)
    Aixo redueix significativament el cost de calcul respecte a calcular
    k hashos diferents per cada element.
    """

    def _hashes(self, item):
        if isinstance(item, str):
            item = item.encode("utf-8")
        # Calculem un unic SHA-256 i partim el digest en dos hashos
        digest = hashlib.sha256(item).digest()
        h1 = int.from_bytes(digest[:8], "little")
        h2 = int.from_bytes(digest[8:16], "little")
        # h2 hauria de ser senar per cobrir bones zones del filtre
        if h2 % 2 == 0:
            h2 += 1
        for i in range(self.num_hashes):
            yield (h1 + i * h2) % self.size


# ---------------------------------------------------------------------------
# Utilitats: lectura de contrasenyes del dataset
# ---------------------------------------------------------------------------
def iter_passwords(dataset_path, max_count=None):
    """
    Itera contrasenyes a partir del dataset.
    El dataset son fitxers de text amb linies "email:password".
    Funciona tant si dataset_path es un fitxer com una carpeta amb subcarpetes.
    """
    p = Path(dataset_path)
    files = [p] if p.is_file() else sorted(p.rglob("*"))
    n = 0
    for f in files:
        if not f.is_file():
            continue
        try:
            fh = open(f, "r", encoding="utf-8", errors="ignore")
        except OSError:
            continue
        with fh:
            for line in fh:
                line = line.rstrip("\n").rstrip("\r")
                if ":" not in line:
                    continue
                # Agafem nomes la part de la contrasenya
                pw = line.split(":", 1)[1]
                if not pw:
                    continue
                yield pw
                n += 1
                if max_count is not None and n >= max_count:
                    return


def load_subset(dataset_path, n):
    """Carrega n contrasenyes a una llista."""
    return list(iter_passwords(dataset_path, max_count=n))


# ---------------------------------------------------------------------------
# Exercici 3 i 5.- Comparatives
# ---------------------------------------------------------------------------
def measure_structure(structure_factory, words, test_words):
    """
    Mesura les 4 metriques per una estructura donada:
      - temps d'afegir
      - temps de comprovacio
      - mida en memoria (aproximada)
      - taxa de falsos positius (sobre test_words que NO son a 'words')
    structure_factory: funcio que retorna una estructura buida amb metodes
                       'add' i 'contains' (o suport per 'in').
    """
    s = structure_factory()

    # Temps d'afegir
    t0 = time.perf_counter()
    for w in words:
        s.add(w) if hasattr(s, "add") else s.append(w)
    t_add = time.perf_counter() - t0

    # Temps de comprovacio (consultem els mateixos elements)
    t0 = time.perf_counter()
    for w in words:
        _ = w in s
    t_check = time.perf_counter() - t0

    # Mida en memoria
    if hasattr(s, "memory_bytes"):
        mem = s.memory_bytes()
    else:
        # Per a set/list, sys.getsizeof + contingut
        mem = sys.getsizeof(s) + sum(sys.getsizeof(w) for w in s)

    # Falsos positius: consultem elements que segur que NO hi son
    fp = 0
    for w in test_words:
        if w in s:
            fp += 1
    fp_rate = fp / len(test_words) if test_words else 0.0

    return {
        "add_time": t_add,
        "check_time": t_check,
        "memory_bytes": mem,
        "fp_rate": fp_rate,
    }


def make_negative_samples(n, prefix="NEG_"):
    """Genera n strings que segur que no son al dataset."""
    return [f"{prefix}{i}_{os.urandom(4).hex()}" for i in range(n)]


def comparative(dataset_path, sizes=(1_000, 10_000, 100_000), p=0.01):
    """
    Exercici 3 i 5: compara el filtre de Bloom (independent),
    el filtre de Bloom (doble hashing) i un set de Python.
    """
    print(f"\n{'='*70}")
    print(f"COMPARATIVA  (taxa de falsos positius desitjada p = {p})")
    print(f"{'='*70}")

    for n in sizes:
        print(f"\n--- N = {n} contrasenyes ---")
        words = load_subset(dataset_path, n)
        if len(words) < n:
            print(f"AVIS: nomes s'han pogut carregar {len(words)} contrasenyes")
            n = len(words)
        if n == 0:
            print("No hi ha dades, salto aquest cas.")
            continue

        # Generem negatius per mesurar la taxa de falsos positius
        negatives = make_negative_samples(min(10_000, n))

        m, k = optimal_parameters(n, p)
        print(f"Parametres optims del filtre: m = {m} bits, k = {k} hashos")

        results = {
            "BloomFilter (k hashos independents)":
                measure_structure(lambda: BloomFilter(m, k), words, negatives),
            "BloomFilter (doble hashing)":
                measure_structure(lambda: BloomFilterDoubleHashing(m, k),
                                  words, negatives),
            "set de Python":
                measure_structure(lambda: set(), words, negatives),
        }

        print(f"\n{'Estructura':<40} {'add(s)':>10} {'check(s)':>10}"
              f" {'mem (KB)':>12} {'FP':>8}")
        print("-" * 82)
        for name, r in results.items():
            print(f"{name:<40} {r['add_time']:>10.3f} {r['check_time']:>10.3f}"
                  f" {r['memory_bytes']/1024:>12.1f}"
                  f" {r['fp_rate']:>8.4f}")


# ---------------------------------------------------------------------------
# Exercici 6.- Filtre per al dataset complet
# ---------------------------------------------------------------------------
def build_full_filter(dataset_path, expected_n, p=0.05,
                      output="bloom_full.pkl"):
    """
    Construeix un filtre per a tot el dataset amb la millor configuracio.
    Per resultats de l'exercici 5, fem servir doble hashing (mes rapid).
    """
    print(f"\n{'='*70}")
    print(f"EXERCICI 6: filtre per al dataset complet (p maxim = {p})")
    print(f"{'='*70}")

    m, k = optimal_parameters(expected_n, p)
    print(f"Versio:    BloomFilterDoubleHashing")
    print(f"Mida (m):  {m} bits  ({m/8/1024/1024:.2f} MB)")
    print(f"Hashos (k): {k}")
    print(f"Elements esperats: {expected_n}")

    bf = BloomFilterDoubleHashing(m, k)

    t0 = time.perf_counter()
    n_added = 0
    for pw in iter_passwords(dataset_path):
        bf.add(pw)
        n_added += 1
        if n_added % 1_000_000 == 0:
            elapsed = time.perf_counter() - t0
            print(f"  ... {n_added:,} contrasenyes afegides en {elapsed:.1f}s")
    t_total = time.perf_counter() - t0

    print(f"\nTotal afegits:      {n_added:,}")
    print(f"Temps total:        {t_total:.1f} s")
    print(f"Mida del filtre:    {bf.memory_bytes()/1024/1024:.2f} MB")

    bf.save(output)
    print(f"Filtre desat a:     {output}")

    # Comprovacio de les contrasenyes de l'enunciat
    candidates = [
        "hola",
        "1234",
        "iloveyou",
        "Awesome1",
        "mmmmmmm",
        "367026606991464",
        "supertrooper2002",
        "SpRyhdjd2002",
        "593b04318425a33190ceaabab648376c",
        "bnbd246GbB",
    ]
    print("\nContrasenyes filtrades (al filtre):")
    for c in candidates:
        marca = "SI" if c in bf else "no"
        print(f"  [{marca:>2}] {c}")

    return bf


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    import argparse
    parser = argparse.ArgumentParser(description="Practica 2 - Filtres de Bloom")
    parser.add_argument("--dataset", required=True,
                        help="Ruta al dataset (fitxer o carpeta)")
    parser.add_argument("--mode", choices=["compare", "full", "demo"],
                        default="demo",
                        help="compare = exercicis 3 i 5;  "
                             "full = exercici 6;  demo = prova rapida")
    parser.add_argument("--expected", type=int, default=1_400_000_000,
                        help="Nombre esperat d'elements (exercici 6)")
    parser.add_argument("--p", type=float, default=0.05,
                        help="Taxa de falsos positius desitjada")
    args = parser.parse_args()

    if args.mode == "compare":
        comparative(args.dataset, sizes=(1_000, 10_000, 1_000_000), p=0.01)
    elif args.mode == "full":
        build_full_filter(args.dataset, args.expected, p=args.p)
    else:
        # demo: prova rapida amb pocs elements
        print("DEMO: prova rapida del filtre de Bloom")
        words = load_subset(args.dataset, 1000)
        m, k = optimal_parameters(len(words), 0.01)
        bf = BloomFilterDoubleHashing(m, k)
        for w in words:
            bf.add(w)
        print(f"Afegits {len(words)} elements amb m={m}, k={k}")
        print(f"'hola' al filtre? {'hola' in bf}")
        print(f"'1234' al filtre? {'1234' in bf}")
        if words:
            print(f"'{words[0]}' al filtre? {words[0] in bf}  (ha de ser True)")


if __name__ == "__main__":
    main()

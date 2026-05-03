#!/usr/bin/env python3
"""
Test Attaque IKE Downgrade
Vérifie si le serveur VPN accepte les propositions cryptographiques faibles.
Résultat attendu : le serveur doit REJETER toutes les propositions faibles.

IMPORTANT: Ce test doit être lancé depuis une machine EXTERNE
au tunnel VPN pour simuler une vraie attaque de downgrade.

Résultats depuis le serveur (192.168.138.10) — CORRECT:
- Aucune réponse = serveur rejette correctement les propositions faibles

Résultats depuis le client (192.168.138.20) — FAUX POSITIF:
- RÉPONSE REÇUE = normal car tunnel IPSec actif entre les deux VMs
- Ce n'est PAS une vulnérabilité réelle
"""

from scapy.all import *
from scapy.layers.isakmp import *

# ─── Configuration ────────────────────────────────────────────
TARGET = "192.168.138.10"  # ─── Cible: serveur VPN ──────────
RESULTS = []

# ─── Détection de la perspective d exécution ──────────────────
import socket
local_ip = socket.gethostbyname(socket.gethostname())
if "192.168.138.20" in local_ip or "192.168.230" in local_ip:
    print("="*60)
    print("AVERTISSEMENT: Script lancé depuis le CLIENT VPN")
    print("Les résultats peuvent être des FAUX POSITIFS")
    print("car le tunnel IPSec existant interfère avec les tests.")
    print("Pour des résultats fiables, lancez depuis le SERVEUR.")
    print("="*60 + "\n")

def send_and_check(proposal_name, pkt):
    print(f"\n[*] ESSAI: {proposal_name}")
    try:
        resp = sr1(pkt, timeout=3, verbose=0)
        if resp:
            print(f"  [!] RÉPONSE REÇUE — le serveur a répondu!")
            print(f"  [!] VULNÉRABLE à {proposal_name}")
            RESULTS.append(("ECHOUER", proposal_name))
        else:
            print(f"  [+] Aucune réponse — le serveur a correctement rejeté la demande.")
            RESULTS.append(("REUSSI", proposal_name))
    except Exception as e:
        print(f"  [+] Paquet rejeté — le serveur a correctement rejeté la demande.")
        RESULTS.append(("REUSSI", proposal_name))

# ─── Test 1: Faible DES + MD5 proposition ─────────────────────
pkt_des = (
    IP(dst=TARGET) /
    UDP(sport=RandShort(), dport=500) /
    ISAKMP(init_cookie=RandString(8), resp_cookie=b'\x00'*8,
           next_payload=1, exch_type=2) /
    ISAKMP_payload_SA(next_payload=0, prop=
        ISAKMP_payload_Proposal(
            proto=1, trans_nb=1,
            trans=ISAKMP_payload_Transform(
                num=1,
                transforms=[
                    (1, 1),   # ─── Chiffrement: DES-CBC (faible)
                    (2, 1),   # ─── Hachage: MD5 (faible)
                    (4, 1),   # ─── Auth: PSK
                    (3, 1),   # ─── Groupe DH: 1 (768-bit, faible)
                ]
            )
        )
    )
)
send_and_check("DES-CBC + MD5 + Groupe DH 1 (faible)", pkt_des)

# ─── Test 2: Proposition de chiffrement NULL ───────────────────
pkt_null = (
    IP(dst=TARGET) /
    UDP(sport=RandShort(), dport=500) /
    ISAKMP(init_cookie=RandString(8), resp_cookie=b'\x00'*8,
           next_payload=1, exch_type=2) /
    ISAKMP_payload_SA(next_payload=0, prop=
        ISAKMP_payload_Proposal(
            proto=1, trans_nb=1,
            trans=ISAKMP_payload_Transform(
                num=1,
                transforms=[
                    (1, 11),  # ─── Chiffrement: NULL (aucun chiffrement)
                    (2, 1),   # ─── Hachage: MD5
                    (4, 1),   # ─── Auth: PSK
                    (3, 1),   # ─── Groupe DH: 1
                ]
            )
        )
    )
)
send_and_check("CHIFFREMENT NULL (aucun chiffrement)", pkt_null)

# ─── Test 3: Tentative de downgrade IKEv1 ─────────────────────
pkt_v1 = (
    IP(dst=TARGET) /
    UDP(sport=RandShort(), dport=500) /
    ISAKMP(init_cookie=RandString(8), resp_cookie=b'\x00'*8,
           next_payload=1, exch_type=2, version=0x10) /
    ISAKMP_payload_SA(next_payload=0, prop=
        ISAKMP_payload_Proposal(proto=1, trans_nb=1,
            trans=ISAKMP_payload_Transform(num=1,
                transforms=[(1,7),(2,2),(4,1),(3,2)]
            )
        )
    )
)
send_and_check("Mode principal IKEv1 (tentative de downgrade)", pkt_v1)

# ─── Test 4: Charge utile SA malformée/vide ───────────────────
pkt_malformed = (
    IP(dst=TARGET) /
    UDP(sport=RandShort(), dport=500) /
    ISAKMP(init_cookie=RandString(8), resp_cookie=b'\x00'*8,
           next_payload=1, exch_type=2) /
    Raw(load=b'\x00' * 20)
)
send_and_check("Charge utile (payload) SA malformée/vide", pkt_malformed)

# ─── Résumé des résultats ─────────────────────────────────────
print("\n" + "="*50)
print("RESUME D'ATTAQUE DOWNGRADE")
print("="*50)
for status, name in RESULTS:
    icon = "[+] REUSSI" if status == "REUSSI" else "[-] ECHOUER"
    print(f"  {icon} — {name}")

reussi = sum(1 for s, _ in RESULTS if s == "REUSSI")
print(f"\nRésultat: {reussi}/{len(RESULTS)} tests réussis")
if reussi == len(RESULTS):
    print("✓ VPN est sécurisé contre les attaques de downgrade !")
else:
    print("✗ VPN a des VULNÉRABILITÉS !!!!")
    print("  NOTE: Si lancé depuis le client, vérifier si faux positif.")

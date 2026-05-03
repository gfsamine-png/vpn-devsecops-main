#!/bin/bash
# ─── Script de restauration après snapshot ────────────────────

echo "Synchronisation de l'heure..."
sudo timedatectl set-ntp true
sudo chronyc makestep

echo "Redémarrage des interfaces réseau..."
sudo ip link set ens34 down
sleep 2
sudo ip link set ens34 up
sleep 3

echo "Application des règles iptables..."
cd ~/vpn-devsecops/terraform
terraform taint null_resource.server_firewall
terraform apply -auto-approve

echo "Redémarrage des services VPN..."
sudo ipsec restart
sleep 5
sudo ipsec up vpn-site
sudo systemctl restart openvpn-server@server

echo "Vérification..."
sudo ipsec status
sudo ip addr show tun0

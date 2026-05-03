terraform {
  required_providers {
    null = {
      source  = "hashicorp/null"
      version = "~> 3.0"
    }
  }
}

# ─── RÈGLES FIREWALL SERVEUR VPN ─────────────────────────────────────────────
resource "null_resource" "server_firewall" {
  connection {
    type        = "ssh"
    host        = var.server_ip
    user        = var.ssh_user
    private_key = file(pathexpand(var.ssh_key_path))
  }
  provisioner "remote-exec" {
    inline = [
      <<-SCRIPT
        sudo bash -c '
          cat > /tmp/fw.sh << "FWEOF"
#!/bin/bash

# ─── Synchronisation de l heure ───────────────────────────────
timedatectl set-ntp true
chronyc makestep 2>/dev/null || true

# ─── Réinitialisation complète des règles iptables ────────────
iptables -F
iptables -X
iptables -P INPUT ACCEPT
iptables -P FORWARD ACCEPT
iptables -P OUTPUT ACCEPT

# ─── Règles de base ───────────────────────────────────────────
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# ─── Protection brute force SSH ───────────────────────────────
iptables -A INPUT -p tcp --dport 22 -m state --state NEW \
    -m recent --set --name SSH_BRUTE
iptables -A INPUT -p tcp --dport 22 -m state --state NEW \
    -m recent --update --seconds 60 --hitcount 4 \
    --name SSH_BRUTE -j DROP
iptables -A INPUT -p tcp --dport 22 -j ACCEPT

# ─── Protection brute force IKE (port 500) ────────────────────
iptables -A INPUT -p udp --dport 500 -m state --state NEW \
    -m recent --set --name IKE_BRUTE
iptables -A INPUT -p udp --dport 500 -m state --state NEW \
    -m recent --update --seconds 60 --hitcount 10 \
    --name IKE_BRUTE -j DROP
iptables -A INPUT -p udp --dport 500 -j ACCEPT

# ─── Protection brute force NAT-T (port 4500) ─────────────────
iptables -A INPUT -p udp --dport 4500 -m state --state NEW \
    -m recent --set --name NATT_BRUTE
iptables -A INPUT -p udp --dport 4500 -m state --state NEW \
    -m recent --update --seconds 60 --hitcount 10 \
    --name NATT_BRUTE -j DROP
iptables -A INPUT -p udp --dport 4500 -j ACCEPT

# ─── Protection brute force OpenVPN (port 1194) ───────────────
iptables -A INPUT -p udp --dport 1194 -m state --state NEW \
    -m recent --set --name OVPN_BRUTE
iptables -A INPUT -p udp --dport 1194 -m state --state NEW \
    -m recent --update --seconds 60 --hitcount 10 \
    --name OVPN_BRUTE -j DROP
iptables -A INPUT -p udp --dport 1194 -j ACCEPT

# ─── Règles ESP et tunnel VPN ─────────────────────────────────
iptables -A INPUT -p esp -j ACCEPT
iptables -A INPUT -i tun0 -j ACCEPT
iptables -A FORWARD -i tun0 -j ACCEPT
iptables -A FORWARD -o tun0 -j ACCEPT

# ─── Autorisation explicite du client VPN ─────────────────────
iptables -A INPUT -s ${var.client_ip} -j ACCEPT
iptables -A INPUT -s ${var.vpn_subnet} -j ACCEPT

# ─── Journalisation des paquets bloqués ───────────────────────
iptables -A INPUT -j LOG --log-prefix "FW-DROP: " --log-level 4

# ─── Politique par défaut DROP ────────────────────────────────
iptables -P INPUT DROP
iptables -P FORWARD DROP

# ─── Activation du forwarding IP ──────────────────────────────
sysctl -w net.ipv4.ip_forward=1
echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/99-vpn.conf

# ─── Relancer l interface ens34 ───────────────────────────────
ip link set ens34 down
sleep 2
ip link set ens34 up
sleep 3

FWEOF
          chmod +x /tmp/fw.sh
          /tmp/fw.sh
          DEBIAN_FRONTEND=noninteractive apt install -y \
            iptables-persistent netfilter-persistent
          netfilter-persistent save
        '
      SCRIPT
    ]
  }
}

# ─── RÈGLES FIREWALL CLIENT VPN ──────────────────────────────────────────────
resource "null_resource" "client_firewall" {
  connection {
    type        = "ssh"
    host        = var.client_ip
    user        = var.ssh_user
    private_key = file(pathexpand(var.ssh_key_path))
  }
  provisioner "remote-exec" {
    inline = [
      <<-SCRIPT
        sudo bash -c '
          cat > /tmp/fw.sh << "FWEOF"
#!/bin/bash

# ─── Synchronisation de l heure ───────────────────────────────
timedatectl set-ntp true
chronyc makestep 2>/dev/null || true

# ─── Réinitialisation complète des règles iptables ────────────
iptables -F
iptables -X
iptables -P INPUT ACCEPT
iptables -P FORWARD ACCEPT
iptables -P OUTPUT ACCEPT

# ─── Règles de base ───────────────────────────────────────────
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# ─── Protection brute force SSH ───────────────────────────────
iptables -A INPUT -p tcp --dport 22 -m state --state NEW \
    -m recent --set --name SSH_BRUTE
iptables -A INPUT -p tcp --dport 22 -m state --state NEW \
    -m recent --update --seconds 60 --hitcount 4 \
    --name SSH_BRUTE -j DROP
iptables -A INPUT -p tcp --dport 22 -j ACCEPT

# ─── Protection brute force IKE (port 500) ────────────────────
iptables -A INPUT -p udp --dport 500 -m state --state NEW \
    -m recent --set --name IKE_BRUTE
iptables -A INPUT -p udp --dport 500 -m state --state NEW \
    -m recent --update --seconds 60 --hitcount 10 \
    --name IKE_BRUTE -j DROP
iptables -A INPUT -p udp --dport 500 -j ACCEPT

# ─── Protection brute force NAT-T (port 4500) ─────────────────
iptables -A INPUT -p udp --dport 4500 -m state --state NEW \
    -m recent --set --name NATT_BRUTE
iptables -A INPUT -p udp --dport 4500 -m state --state NEW \
    -m recent --update --seconds 60 --hitcount 10 \
    --name NATT_BRUTE -j DROP
iptables -A INPUT -p udp --dport 4500 -j ACCEPT

# ─── Protection brute force OpenVPN (port 1194) ───────────────
iptables -A INPUT -p udp --dport 1194 -m state --state NEW \
    -m recent --set --name OVPN_BRUTE
iptables -A INPUT -p udp --dport 1194 -m state --state NEW \
    -m recent --update --seconds 60 --hitcount 10 \
    --name OVPN_BRUTE -j DROP
iptables -A INPUT -p udp --dport 1194 -j ACCEPT

# ─── Règles ESP et tunnel VPN ─────────────────────────────────
iptables -A INPUT -p esp -j ACCEPT
iptables -A INPUT -i tun0 -j ACCEPT
iptables -A FORWARD -i tun0 -j ACCEPT
iptables -A FORWARD -o tun0 -j ACCEPT

# ─── Autorisation explicite du serveur VPN ────────────────────
iptables -A INPUT -s ${var.server_ip} -j ACCEPT
iptables -A INPUT -s ${var.vpn_subnet} -j ACCEPT

# ─── Journalisation des paquets bloqués ───────────────────────
iptables -A INPUT -j LOG --log-prefix "FW-DROP: " --log-level 4

# ─── Politique par défaut DROP ────────────────────────────────
iptables -P INPUT DROP
iptables -P FORWARD DROP

# ─── Relancer l interface ens34 ───────────────────────────────
ip link set ens34 down
sleep 2
ip link set ens34 up
sleep 3

FWEOF
          chmod +x /tmp/fw.sh
          /tmp/fw.sh
          DEBIAN_FRONTEND=noninteractive apt install -y \
            iptables-persistent netfilter-persistent
          netfilter-persistent save
        '
      SCRIPT
    ]
  }

  depends_on = [null_resource.server_firewall]
}

variable "server_ip" {
  default = "192.168.138.10"
}

variable "client_ip" {
  default = "192.168.230.137"
}

variable "ssh_user" {
  default = "ubuntu"
}

variable "ssh_key_path" {
  default = "~/.ssh/ed25519"
}

# ─── Sous-réseau VPN autorisé ─────────────────────────────────
variable "vpn_subnet" {
  default = "192.168.230.0/24"
}

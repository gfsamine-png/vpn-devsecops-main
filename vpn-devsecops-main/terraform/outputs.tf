output "server_firewall_status" {
  value = "Firewall rules applied to vpn_server (${var.server_ip})"
}

output "client_firewall_status" {
  value = "Firewall rules applied to client (${var.client_ip})"
}

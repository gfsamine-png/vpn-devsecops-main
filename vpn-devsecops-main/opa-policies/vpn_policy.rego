package vpn.security

algorithmes_autorises := ["AES-256-GCM", "AES-128-GCM"]
ike_versions_autorisees := ["ikev2"]

cipher_fort if {
    input.cipher == algorithmes_autorises[_]
}

ikev2_obligatoire if {
    input.ike_version == ike_versions_autorisees[_]
}

rule CredentialCloudGCPServiceAccount : Credential Cloud GCP {
    meta:
        name        = "GCP Service Account JSON"
        author      = "Peter Adkins"
        version     = "0.4.0"
        accuracy    = 100
        description = "Potential GCP service account JSON found."

    strings:
        $atom_0   = "client_x509_cert_url" wide ascii private
        $atom_1   = "client_x509_cert_url" base64 base64wide private

        $ascii_0  = "\"client_x509_cert_url\"" wide ascii private
        $ascii_1  = "\"private_key\"" wide ascii private
        $ascii_2  = "\"client_email\"" wide ascii

        $base64_0 = "\"client_x509_cert_url\"" base64 base64wide private
        $base64_1  = "\"private_key\"" base64 base64wide private
        $base64_2  = "\"client_email\"" base64 base64wide

    condition:
        any of ($atom_*) and (
            all of ($ascii_*)
        ) or (
            all of ($base64_*)
        )
}

rule CredentialGenericHTTPBasic : Credential Generic HTTP {

    meta:
        name        = "HTTP Basic Authentication"
        author      = "Peter Adkins"
        version     = "0.2.0"
        accuracy    = 70
        description = "Potential HTTP basic authentication credentials found."

    strings:
        $atom_0 = "http://" ascii wide private
        $atom_1 = "https://" ascii wide private

        $ascii_1 = /\bhttps?:\/\/[a-zA-Z0-9@\-_.%]{1,256}:[\x21-\x7E]{1,256}@[a-zA-Z0-9\-.]+(\/|\b)/ ascii wide

    condition:
        (any of ($atom_*)) and (any of ($ascii_*))
}

rule CredentialSaaSSlackUserToken : Credential SaaS Slack {
    meta:
        name        = "Slack User OAuth token"
        author      = "Peter Adkins"
        version     = "0.2.0"
        accuracy    = 100
        description = "Potential Slack User OAuth token found."

    strings:
        $atom_0  = "xoxp-" ascii wide
        $ascii_0 = /xoxp-[0-9]{4,24}-[0-9]{4,24}-[0-9]{4,24}-[0-9a-fA-F]{32}/ ascii wide

    condition:
        $atom_0 and $ascii_0
}

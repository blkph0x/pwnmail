#!/bin/bash

LOG_FILE="/var/log/email_server_setup.log"
POSTFIX_MAIN="/etc/postfix/main.cf"
VMAILBOX_FILE="/etc/postfix/vmailbox"
VMAILBOX_DIR="/var/mail/vmail"
DOVECOT_PASSWD_FILE="/etc/dovecot/passwd"
SNI_MAP_FILE="/etc/postfix/sni_map"
OPENDKIM_DIR="/etc/opendkim"
OPENDKIM_KEYS="$OPENDKIM_DIR/keys"

log() { echo "$(date): $1" | tee -a $LOG_FILE; }

check_and_create() {
    path=$1
    permissions=$2
    owner=$3

    if [[ ! -e $path ]]; then
        if [[ $path == */ ]]; then
            mkdir -p "$path"
        else
            touch "$path"
        fi
        chmod "$permissions" "$path"
        chown "$owner" "$path"
        log "Created $path with permissions $permissions and owner $owner."
    else
        chmod "$permissions" "$path"
        chown "$owner" "$path"
        log "Verified $path with permissions $permissions and owner $owner."
    fi
}

install_dependencies() {
    apt update && apt install -y postfix dovecot-core dovecot-imapd dovecot-pop3d certbot opendkim opendkim-tools
    log "Dependencies installed."
}

validate_files_and_folders() {
    check_and_create "$LOG_FILE" "644" "root:root"
    check_and_create "$VMAILBOX_FILE" "600" "postfix:postfix"
    check_and_create "$DOVECOT_PASSWD_FILE" "600" "vmail:vmail"
    check_and_create "$VMAILBOX_DIR/" "700" "vmail:vmail"
    check_and_create "$SNI_MAP_FILE" "600" "postfix:postfix"
    check_and_create "$OPENDKIM_DIR/" "755" "opendkim:opendkim"
    check_and_create "$OPENDKIM_KEYS/" "750" "opendkim:opendkim"
}

configure_postfix() {
    postconf -e "mydestination = localhost"
    postconf -e "virtual_alias_maps = hash:$VMAILBOX_FILE"
    postconf -e "virtual_mailbox_maps = hash:$VMAILBOX_FILE"
    postconf -e "virtual_mailbox_base = $VMAILBOX_DIR"
    postconf -e "home_mailbox = Maildir/"
    postconf -e "smtpd_sasl_auth_enable = yes"
    postconf -e "smtpd_tls_cert_file=/etc/letsencrypt/live/$1/fullchain.pem"
    postconf -e "smtpd_tls_key_file=/etc/letsencrypt/live/$1/privkey.pem"
    postconf -e "smtpd_tls_security_level = may"
    postconf -e "smtpd_tls_auth_only = yes"
    postconf -e "smtpd_milters = inet:localhost:8891"
    postconf -e "non_smtpd_milters = inet:localhost:8891"
    postconf -e "milter_default_action = accept"
    postconf -e "smtp_tls_security_level = may"
    postconf -e "smtp_tls_loglevel = 1"
    postconf -e "smtpd_recipient_restrictions = permit_sasl_authenticated, permit_mynetworks, reject_unauth_destination"
    postconf -e "smtpd_relay_restrictions = permit_mynetworks, permit_sasl_authenticated, defer_unauth_destination"
    postconf -e "smtpd_tls_protocols = !SSLv2, !SSLv3"
    postconf -e "smtp_tls_protocols = !SSLv2, !SSLv3"
    systemctl restart postfix
    log "Postfix configured for domain $1."
}

configure_dovecot() {
    cat <<EOF > /etc/dovecot/dovecot.conf
protocols = imap pop3 lmtp
disable_plaintext_auth = yes
mail_location = maildir:$VMAILBOX_DIR/%d/%n/Maildir
auth_mechanisms = plain login
passdb {
  driver = passwd-file
  args = /etc/dovecot/passwd
}
userdb {
  driver = static
  args = uid=vmail gid=vmail home=$VMAILBOX_DIR/%d/%n
}
ssl = required
ssl_cert = </etc/letsencrypt/live/$1/fullchain.pem
ssl_key = </etc/letsencrypt/live/$1/privkey.pem
EOF

    systemctl restart dovecot
    log "Dovecot configured for IMAP, POP3, and SMTP."
}

configure_opendkim() {
    mkdir -p $OPENDKIM_KEYS/$1
    opendkim-genkey -D $OPENDKIM_KEYS/$1/ -d $1 -s mail
    chown -R opendkim:opendkim $OPENDKIM_KEYS && chmod 600 $OPENDKIM_KEYS/$1/mail.private
    cat <<EOF > /etc/opendkim.conf
AutoRestart             Yes
Syslog                  Yes
Canonicalization        relaxed/simple
KeyTable                $OPENDKIM_DIR/KeyTable
SigningTable            $OPENDKIM_DIR/SigningTable
Socket                  inet:8891@localhost
PidFile                 /run/opendkim/opendkim.pid
EOF
    echo "$1 mail._domainkey.$1 $OPENDKIM_KEYS/$1/mail.private" >> $OPENDKIM_DIR/KeyTable
    echo "*@$1 mail._domainkey.$1" >> $OPENDKIM_DIR/SigningTable
    systemctl restart opendkim
    log "OpenDKIM configured for domain $1."
}

generate_dns_instructions() {
    echo "DNS Records for domain: $1
-----------------------------------
1. SPF Record:
   Type: TXT
   Name: @
   Value: \"v=spf1 mx ~all\"

2. DKIM Record:
   Type: TXT
   Name: mail._domainkey
   Value: $(cat $OPENDKIM_KEYS/$1/mail.txt | grep -oP '(?<=p=).*')

3. DMARC Record:
   Type: TXT
   Name: _dmarc
   Value: \"v=DMARC1; p=quarantine; rua=mailto:dmarc@$1;\""
}

add_domain() {
    mkdir -p "$VMAILBOX_DIR/$1"
    certbot certonly --standalone -d $1 --non-interactive --agree-tos --email admin@$1
    echo "$1 /etc/letsencrypt/live/$1/fullchain.pem /etc/letsencrypt/live/$1/privkey.pem" >> $SNI_MAP_FILE
    postmap $SNI_MAP_FILE
    configure_postfix $1
    configure_opendkim $1
    log "Domain $1 added with SSL and DKIM."
    generate_dns_instructions $1
}

add_email() {
    read -p "Email username (e.g., admin): " username
    read -sp "Password: " password; echo
    domain=$1
    email="$username@$domain"
    hashed_password=$(doveadm pw -s SHA512-CRYPT -p "$password")
    echo "$email $VMAILBOX_DIR/$domain/$username/Maildir/" >> $VMAILBOX_FILE
    echo "$email:$hashed_password" >> $DOVECOT_PASSWD_FILE
    mkdir -p "$VMAILBOX_DIR/$domain/$username/Maildir/{cur,new,tmp}"
    chmod -R 700 "$VMAILBOX_DIR/$domain/$username"
    chown -R vmail:vmail "$VMAILBOX_DIR/$domain/$username"
    postmap $VMAILBOX_FILE
    systemctl reload postfix
    log "Added email: $email to domain: $domain"
}

main() {
    [[ $EUID -ne 0 ]] && { echo "Run as root."; exit 1; }
    install_dependencies
    validate_files_and_folders
    read -p "Initial domain to configure: " domain
    add_domain $domain
    add_email $domain
    log "Email server setup complete for $domain."
}

main

# clear-authz

A simple tool to clear pending ACME v1 authorizations based upon a Certbot private ACME account key (in `private_key.json` format) and Certbot logs (from `/var/log/letsencrypt`).

## A better alternative

You may want to check out https://tools.letsdebug.net/clear-authz instead. It runs in your browser and supports both ACME v1 and ACME v2.

## Installation

Please download the Linux amd64 binary from the releases page. Otherwise, you are on your own to build it from source:

    go get -u github.com/alexzorin/clear-authz

## Usage

    sudo ./clear-authz < /var/log/letsencrypt/letsencrypt.log*

### With a custom directory server (ACME v1 only)

    sudo CLEAR_AUTHZ_SERVER=acme-staging.api.letsencrypt.org ./clear-authz < /var/log/letsencrypt/letsencrypt.log*

### With a custom ACME account key
Typically the account key will be automatically located from `/etc/letsencrypt/accounts` for the nominated directory server, but you can specify the path to the `account_key.json` as the first argument.

    sudo ./clear-authz /path/to/account_key.json < ...

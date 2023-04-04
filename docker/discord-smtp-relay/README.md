# Discord SMTP Relay

Original Repo: [hamiltlr/discord-smtp-relay](https://github.com/hamiltlr/discord-smtp-relay)

This project is a very simple relay from SMTP to a Discord webhook. This allows applications that only support SMTP email notifications to be routed to Discord without an actual email server as a middle-man.

This project supports a few options for authentication:
 - No authenticaion, no TLS
 - PLAIN or LOGON authentication, without TLS
 - PLAIN or LOGON authentication with TLS

It currently only allows one username/password combination, which are set by environment variables (see below). If you don't need authentication or TLS, simply don't set those variables (SMTP_USERNAME/PASSWORD or TLS_CERT/KEY respectively).

This is designed for use internally only, specifically within a Docker network.

# Environment variables
| Variable    | Description          | Example                                          |
|-------------|----------------------|--------------------------------------------------|
| WEBHOOK_URL | Discord webhook URL. | `https://discord.com/api/webhooks/xxxxxx/yyyyyy` |
| SMTP_USERNAME | Accepted username for SMTP | `testuser` |
| SMTP_PASSWORD | Accepted password for SMTP | `testpass` |
| TLS_CERT_CHAIN | File path to full TLS certificate chain | `fullchain.pem` |
| TLS_KEY | File path to private key for certificate | `privkey.pem` |

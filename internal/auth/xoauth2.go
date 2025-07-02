package auth

import (
	"errors"
	"net/smtp"
)

type xoauth2Auth struct {
	accessToken, host string
}

func XOAuth2Auth(accessToken, host string) smtp.Auth {
	return &xoauth2Auth{accessToken, host}
}

func (a *xoauth2Auth) Start(server *smtp.ServerInfo) (string, []byte, error) {
	// Must have TLS, or else localhost server.
	// Note: If TLS is not true, then we can't trust ANYTHING in ServerInfo.
	// In particular, it doesn't matter if the server advertises XOAUTH2 auth.
	// That might just be the attacker saying
	// "it's ok, you can trust me with your token."
	if !server.TLS && !isLocalhost(server.Name) {
		return "", nil, errors.New("unencrypted connection")
	}
	if server.Name != a.host {
		return "", nil, errors.New("wrong host name")
	}
	return "XOAUTH2", []byte(""), nil
}

func (a *xoauth2Auth) Next(fromServer []byte, more bool) ([]byte, error) {
	if more {
		// The server expects the access token.
		return []byte(a.accessToken), nil
	}
	return nil, nil
}

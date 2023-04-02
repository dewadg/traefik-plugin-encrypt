package traefik_plugin_encrypt

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
)

type Config struct {
	ExchangeURL string
	HeaderName  string
}

func CreateConfig() *Config {
	return &Config{
		ExchangeURL: "http://localhost:8000",
		HeaderName:  "x-traefik-session",
	}
}

type Plugin struct {
	next        http.Handler
	name        string
	exchangeURL string
	headerName  string
}

func New(ctx context.Context, next http.Handler, cfg *Config, name string) (http.Handler, error) {
	return &Plugin{
		next:        next,
		name:        name,
		exchangeURL: cfg.ExchangeURL,
		headerName:  cfg.HeaderName,
	}, nil
}

type encryptedPayload struct {
	Payload string `json:"payload"`
}

func (p *Plugin) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	sessionID := r.Header.Get(p.headerName)
	if sessionID == "" {
		http.Error(w, "missing "+p.headerName+" header", http.StatusBadRequest)
		return
	}

	var reqBody encryptedPayload
	if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
		logError(err, "invalid payload")
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	secret, err := getSecret(r.Context(), p.exchangeURL, sessionID)
	if err != nil {
		logError(err, "error fetching secret")
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	decryptedPayload, err := decrypt(secret, reqBody.Payload)
	if err != nil {
		logError(err, "error decrypting payload")
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	ww := &responseWriter{
		ResponseWriter: w,
		secret:         secret,
		headerName:     p.headerName,
		sessionID:      sessionID,
	}

	r.ContentLength = int64(len(decryptedPayload))
	r.Body = io.NopCloser(bytes.NewReader(decryptedPayload))

	p.next.ServeHTTP(ww, r)
}

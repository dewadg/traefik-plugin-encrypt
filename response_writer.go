package traefik_plugin_encrypt

import (
	"encoding/json"
	"net/http"
)

type responseWriter struct {
	http.ResponseWriter
	secret     []byte
	headerName string
	sessionID  string
}

func (w *responseWriter) Header() http.Header {
	header := w.ResponseWriter.Header()
	header.Set(w.headerName, w.sessionID)
	return header
}

func (w *responseWriter) Write(bytes []byte) (int, error) {
	ciphertext, err := encrypt(w.secret, bytes)
	if err != nil {
		logError(err, "error encrypting payload")
		return 0, err
	}

	bytes, err = json.Marshal(encryptedPayload{
		Payload: ciphertext,
	})
	if err != nil {
		logError(err, "error marshaling payload")
		return 0, err
	}

	return w.ResponseWriter.Write(bytes)
}

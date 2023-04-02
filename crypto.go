package traefik_plugin_encrypt

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
)

type getSecretResponse struct {
	Secret string `json:"secret"`
}

func getSecret(ctx context.Context, exchangeURL string, sessionID string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, exchangeURL+"/exchange/"+sessionID, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var reqBody getSecretResponse
	if err = json.NewDecoder(resp.Body).Decode(&reqBody); err != nil {
		return nil, err
	}

	encodedSecret := []byte(reqBody.Secret)
	decodedSecret := make([]byte, hex.DecodedLen(len(encodedSecret)))
	_, err = hex.Decode(decodedSecret, encodedSecret)
	if err != nil {
		return nil, err
	}

	return decodedSecret, nil
}

func decrypt(key []byte, payload string) ([]byte, error) {
	splitPayload := strings.Split(payload, ".")
	if len(splitPayload) < 2 {
		return nil, errors.New("invalid payload")
	}

	nonceBytes := []byte(splitPayload[0])
	nonce := make([]byte, hex.DecodedLen(len(nonceBytes)))
	_, err := hex.Decode(nonce, nonceBytes)
	if err != nil {
		return nil, errors.New("invalid nonce")
	}

	ciphertextBytes := []byte(splitPayload[1])
	ciphertext := make([]byte, hex.DecodedLen(len(ciphertextBytes)))
	_, err = hex.Decode(ciphertext, ciphertextBytes)
	if err != nil {
		return nil, errors.New("invalid ciphertext")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	sealer, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	plaintext, err := sealer.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

func encrypt(key []byte, payload []byte) (string, error) {
	nonce := make([]byte, 12)
	_, err := rand.Read(nonce)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	sealer, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	encodedNonce := hex.EncodeToString(nonce)
	encodedCipher := hex.EncodeToString(sealer.Seal(nil, nonce, payload, nil))

	return encodedNonce + "." + encodedCipher, nil
}

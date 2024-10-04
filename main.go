package main

import (
	"encoding/json"
	"github.com/joho/godotenv"
	"io"
	"log"
	"net/http"
	"net/url"
)

var inviteLink string
var secret string

func main() {
	envFile, _ := godotenv.Read(".env")
	inviteLink = envFile["INVITE_LINK"]
	secret = envFile["RECAPTCHA_V3_SITE_KEY"]

	http.Handle("/validate", http.HandlerFunc(validateRecaptcha))
	http.HandleFunc("/test", func(w http.ResponseWriter, r *http.Request) {
		_, err := w.Write([]byte("Hello, world!"))
		if err != nil {
			return
		}

	})
	err := http.ListenAndServe(":8123", nil)
	if err != nil {
		log.Printf("Error starting server: %v", err)
		return
	}

}

type clientToken struct {
	ClientToken string `json:"token"`
}

type verifyPayload struct {
	Secret      string `json:"secret"`
	ClientToken string `json:"response"`
}

type verifyResponse struct {
	Success     bool   `json:"success"`
	ChallengeTs string `json:"challenge_ts"`
	Hostname    string `json:"hostname"`
}

type response struct {
	InviteLink string `json:"invite_link"`
}

func validateRecaptcha(w http.ResponseWriter, r *http.Request) {

	if r.Header.Get("Content-Type") != "application/json" {
		log.Printf("Invalid Content-Type: %v", r.Header.Get("Content-Type"))
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	tokenFromClient := clientToken{}
	requestBody, err := io.ReadAll(r.Body)
	if err != nil {
		log.Printf("Error reading request body: %v", err)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	err = json.Unmarshal(requestBody, &tokenFromClient)
	if err != nil {
		log.Printf("Error decoding request: %v", err)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	verificationPayload := verifyPayload{Secret: secret, ClientToken: tokenFromClient.ClientToken}

	resp, err := http.PostForm("https://www.google.com/recaptcha/api/siteverify", url.Values{
		"secret":   {verificationPayload.Secret},
		"response": {verificationPayload.ClientToken},
	})
	if err != nil {
		log.Printf("Error verifying recaptcha: %v", err)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	jsonResp := verifyResponse{}

	err = json.NewDecoder(resp.Body).Decode(&jsonResp)

	if err != nil {
		log.Printf("Error decoding response: %v", err)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	if jsonResp.Success == false {
		log.Printf("Recaptcha verification failed")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	err = json.NewEncoder(w).Encode(response{InviteLink: inviteLink})
	if err != nil {
		log.Printf("Error encoding response: %v", err)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
}

package http

import (
	"encoding/json"
	"log"
	"net/http"
	"pki/cert"
	"pki/config"

	"github.com/gorilla/mux"
)

type certifcateResponse struct {
	Pem []byte `json:"pem"`
}

func respondWithError(w http.ResponseWriter, code int, msg string, r *http.Request) {
	respondWithJson(w, code, map[string]string{"error": msg}, r)
}

func respondWithJson(w http.ResponseWriter, code int, payload interface{}, r *http.Request) {
	response, _ := json.Marshal(payload)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	w.Write(response)
	log.Printf("- %s - %s %s - %d", r.RemoteAddr, r.Method, r.URL, code)
}

func getCertificate(w http.ResponseWriter, r *http.Request) {
	csr := cert.CertificateRequest{}
	err := json.NewDecoder(r.Body).Decode(&csr)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "CSR invalide", r)
		return
	}
	if csr == (cert.CertificateRequest{}) {
		respondWithError(w, http.StatusBadRequest, "CSR invalide", r)
		return
	}
	pem, err := cert.GetCertificate(csr)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, err.Error(), r)
		return
	}
	respondWithJson(w, http.StatusOK, certifcateResponse{pem}, r)
}

func getPrivateKey(w http.ResponseWriter, r *http.Request) {
	pkey := cert.GetPrivateKey()

	respondWithJson(w, http.StatusOK, pkey, r)
}

func healthz(w http.ResponseWriter, r *http.Request) {
	respondWithJson(w, http.StatusOK, "ok", r)
}

func HttpServer() {
	router := mux.NewRouter()
	router.HandleFunc("/certificate", getCertificate).Methods("POST")
	router.HandleFunc("/pkey", getPrivateKey).Methods("GET")
	router.HandleFunc("/healthz", healthz).Methods("GET")

	log.Fatal(http.ListenAndServe(config.Config.Server.Listen_address+":"+config.Config.Server.Port, router))
}

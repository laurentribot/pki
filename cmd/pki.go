package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"log"
	"net/http"
	"pki/config"

	"crypto/ecdsa"
	"encoding/base64"
	"fmt"
	"github.com/gorilla/mux"
	"github.com/spf13/pflag"
	"io/ioutil"
	"math/big"
	"time"
)

type PrivateKey struct {
	Pem string `json:"pem"`
}

type CertificateRequest struct {
	Csr string
	Ac  string
}

type Authorities struct {
	Certificate x509.Certificate
	Privatekey  rsa.PrivateKey
}

var authorities map[string]Authorities

func respondWithError(w http.ResponseWriter, code int, msg string) {
	respondWithJson(w, code, map[string]string{"error": msg})
}

func respondWithJson(w http.ResponseWriter, code int, payload interface{}) {
	response, _ := json.Marshal(payload)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	w.Write(response)
}

// get pkey + certificate (optional AC)
// get crl for AC

// LS0tLS1CRUdJTiBDRVJUSUZJQ0FURSBSRVFVRVNULS0tLS0KTUlJQ3dUQ0NBYWtDQVFBd1dqRUxNQWtHQTFVRUJoTUNSbEl4RGpBTUJnTlZCQWdNQlZCQlVrbFRNUTR3REFZRApWUVFIREFWUVFWSkpVekVOTUFzR0ExVUVDZ3dFZEdWemRERU5NQXNHQTFVRUN3d0VkR1Z6ZERFTk1Bc0dBMVVFCkF3d0VkR1Z6ZERDQ0FTSXdEUVlKS29aSWh2Y05BUUVCQlFBRGdnRVBBRENDQVFvQ2dnRUJBTFNoazU0eisxMmsKd3pJbm9YdWpGK1U3alJJVFVTQ04wb1NNV1hsTmlMVzZQcEZBM3dQaGFkSjNnY3Q1TEg5bXdQVkYyNHJ4Vm50WAp0UG03ZWJYMGt5dnFJYUR4ekNMT0J0ZkFKSWthTHozRUxseU9XUHVGRjZqZ1grcE5kOVZvdzVTRnlkODlpcFg2CkxuY25WdEw1KzAvcTdPb0ZveTJBMEhQd2lMOEl3bUNUa3BhaEJvcVNSZ3NBSmpDSDkrbVltTHRZQkQ1ZWF5bW8KV09BazBNdE0rQ2E4bkJDRWdqMWtMekovYUdUa0VEUmRjb1ZsSTE1TkZTRWowVUZ1SS9xT0ZIUCszblVGN0NXSQpZcGd3TlNIQzljWm9sR1RIVDZpc3ZOeFBiOHl5aVRlM0JraDdZdTlWbThRLzdRKzBQb3Bic3I4RjN0U0ZwYndPCkVHcmNxQS8yWXBFQ0F3RUFBYUFpTUNBR0NTcUdTSWIzRFFFSkRqRVRNQkV3RHdZRFZSMFJCQWd3Qm9JRWRHVnoKZERBTkJna3Foa2lHOXcwQkFRc0ZBQU9DQVFFQU1nT0VDeWpFVytQVkpWUXdxMEVqL1Naa0pzTHd6UGYwUG9UUwpwS1A4MmJoMTU4MzVuUU50bUZ2bEwxVGk2WkpLc0owN0tPSmI3cmYxclQwTks0UG5rVGlPSGdqdURPQ2k3dkdTClFCZGc2UEZHSyt3K3A4ZzJTaEJEYmxFSU9UanhIemkwM3NZQjl3MnBwVDFtNXF2cVQ4SkNHZ0txN0FVN3VodXEKZkpQaU9memtlSUw1VlZXMVJFenJNN3FBYW5xNDkyOU5CaW5tV0hqaFdmZkdON0FCMDdjTzliU0VyaGFWVGErLwpMaGRPeDc1MVloUVZCZ0RlUWdFMTNFOXlDYmJFN2dFMTF1MDVLbmVVUk5ubHEzQklGKzEwUTdtYVRwQ2dKaGhuCm1NVDRLd0IxNG1XTnU3RGw0QWNxTStENk45S3Juc1R0U0cwNlhGYWRySGNGZWFqcmlRPT0KLS0tLS1FTkQgQ0VSVElGSUNBVEUgUkVRVUVTVC0tLS0tCg

func publicKey(priv interface{}) interface{} {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey
	case *ecdsa.PrivateKey:
		return &k.PublicKey
	default:
		return nil
	}
}

func getCertificate(w http.ResponseWriter, r *http.Request) {
	csr := CertificateRequest{}
	err := json.NewDecoder(r.Body).Decode(&csr)
	if err != nil {
		panic(err)
	}
	data, _ := base64.StdEncoding.DecodeString(csr.Csr)
	block, _ := pem.Decode([]byte(data))
	cetificateRequest, _ := x509.ParseCertificateRequest(block.Bytes)

	notBefore := time.Now()
	notAfter := notBefore.Add(365 * 24 * time.Hour)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, _ := rand.Int(rand.Reader, serialNumberLimit)

	cert := x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      cetificateRequest.Subject,
		NotBefore:    notBefore,
		NotAfter:     notAfter,

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	parent := authorities["ac1"]
	derBytes, err := x509.CreateCertificate(rand.Reader, &cert, &parent.Certificate, cetificateRequest.PublicKey, &parent.Privatekey)
	if err != nil {
		fmt.Println(err)
	}
	cert_pem := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	respondWithJson(w, http.StatusOK, cert_pem)
}

func getPrivateKey(w http.ResponseWriter, r *http.Request) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}
	block, _ = x509.EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte("toto"), x509.PEMCipherAES256)
	pemdata := pem.EncodeToMemory(block)
	pkey := PrivateKey{Pem: string(pemdata)}

	respondWithJson(w, http.StatusOK, pkey)
}

func loadAuthorities() {
	authorities = make(map[string]Authorities)
	for _, ac := range config.Config.Authorities {
		cf, _ := ioutil.ReadFile(ac.Certificatefile)
		cpb, _ := pem.Decode(cf)
		cert, _ := x509.ParseCertificate(cpb.Bytes)
		kf, _ := ioutil.ReadFile(ac.Privatekeyfile)
		kpb, _ := pem.Decode(kf)
		key, e := x509.ParsePKCS1PrivateKey(kpb.Bytes)
		if e != nil {
			fmt.Println(e)
		}
		authorities[ac.Name] = Authorities{Certificate: *cert, Privatekey: *key}
	}
}

func main() {
	configFile := pflag.StringP("config", "c", "", "")
	pflag.Parse()
	router := mux.NewRouter()
	router.HandleFunc("/certificate", getCertificate).Methods("POST")
	router.HandleFunc("/pkey", getPrivateKey).Methods("GET")
	config.ReadPkiConfig(*configFile)
	loadAuthorities()
	log.Fatal(http.ListenAndServe(config.Config.Server.Listen_address+":"+config.Config.Server.Port, router))
}

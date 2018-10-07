package cert

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"pki/ca"
	"time"
)

type CertificateRequest struct {
	Csr string
	ac  string
}

type PrivateKey struct {
	pem string `json:"pem"`
}

type subjectPublicKeyInfo struct {
	Algorithm        pkix.AlgorithmIdentifier
	SubjectPublicKey asn1.BitString
}

func computeSKI(pub interface{}) ([]byte, error) {
	encodedPub, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}

	var subPKI subjectPublicKeyInfo
	_, err = asn1.Unmarshal(encodedPub, &subPKI)
	if err != nil {
		return nil, err
	}

	pubHash := sha1.Sum(subPKI.SubjectPublicKey.Bytes)
	return pubHash[:], nil
}

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

func GetCertificate(csr CertificateRequest) []byte {
	data, _ := base64.StdEncoding.DecodeString(csr.Csr)
	block, _ := pem.Decode([]byte(data))
	cetificateRequest, _ := x509.ParseCertificateRequest(block.Bytes)

	notBefore := time.Now()
	notAfter := notBefore.Add(10 * 365 * 24 * time.Hour)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, _ := rand.Int(rand.Reader, serialNumberLimit)

	ski, _ := computeSKI(cetificateRequest.PublicKey)
	cert := x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      cetificateRequest.Subject,
		NotBefore:    notBefore,
		NotAfter:     notAfter,

		DNSNames: cetificateRequest.DNSNames,

		SubjectKeyId:          ski,
		CRLDistributionPoints: nil,

		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		//BasicConstraintsValid: true,
	}

	parent := ca.Authorities["ac1"]
	derBytes, err := x509.CreateCertificate(rand.Reader, &cert, &parent.Certificate, cetificateRequest.PublicKey, &parent.Privatekey)
	if err != nil {
		fmt.Println(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
}

func GetPrivateKey() PrivateKey {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}
	block, _ = x509.EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte("toto"), x509.PEMCipherAES256)
	pemdata := pem.EncodeToMemory(block)

	return PrivateKey{pem: string(pemdata)}
}

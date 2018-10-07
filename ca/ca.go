package ca

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"pki/config"
)

type authoritiesType struct {
	Certificate x509.Certificate
	Privatekey  rsa.PrivateKey
}

var Authorities map[string]authoritiesType

func LoadAuthorities() {
	Authorities = make(map[string]authoritiesType)
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
		Authorities[ac.Name] = authoritiesType{Certificate: *cert, Privatekey: *key}
	}
}

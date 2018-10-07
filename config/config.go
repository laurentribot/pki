package config

import (
	"fmt"
	"os"

	"github.com/spf13/viper"
)

type configType struct {
	Server struct {
		Listen_address     string
		Port               string
		Tls                bool
		Tlsca              string
		Tlscertificatefile string
		Tlsprivatekeyfile  string
	}
	Authorities []struct {
		Name            string
		Certificatefile string
		Privatekeyfile  string
	}
}

var Config configType

func ReadPkiConfig(filename string) {
	viper.SetConfigType("yaml")

	viper.SetDefault("server.listen_address", "0.0.0.0")
	viper.SetDefault("server.port", "8080")
	viper.SetDefault("server.tls", false)
	viper.SetDefault("authorities", nil)

	if filename != "" {
		if _, err := os.Stat(filename); !os.IsNotExist(err) {
			f, _ := os.Open(filename)
			err := viper.ReadConfig(f)
			if err != nil {
				panic(fmt.Errorf("Fatal error config file: %s \n", err))
				f.Close()
			}
			f.Close()
		}
	}

	viper.Unmarshal(&Config)
}

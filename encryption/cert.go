package encryption

import "crypto/tls"

func LoadTLSConfig(certFile, keyFile string) (*tls.Config, error) {
	serverCert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}

	config := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.NoClientCert,
		NextProtos: []string{
			"h2", "http/1.1", // enable HTTP/2
		},
	}
	return config, nil
}

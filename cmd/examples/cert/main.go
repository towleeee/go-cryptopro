package main

import (
	"fmt"
	"github.com/towleeee/go-cryptopro/cert"
)

func main() {
	fmt.Println("cert start")
	data := []byte("hello, world!")
	_, err := cert.CertCreateCertificateContext(data)
	if err != nil {
		fmt.Println(err)
	}
}

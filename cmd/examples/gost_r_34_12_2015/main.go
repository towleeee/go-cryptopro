package main

import (
	"bytes"
	"fmt"

	gcipher "github.com/towleeee/go-cryptopro/gost_r_34_12_2015"
)

func main() {
	var (
		openData = []byte("hello")
		mainData = []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
		key      = []byte("qwertyuiopasdfghjklzxcvbnm123456")
		nonce    = []byte("1234567890123456")
	)

	fmt.Println(mainData)

	cphr, err := gcipher.New(key)
	if err != nil {
		panic(err)
	}

	enc := cphr.Seal(nil, nonce, mainData, openData)
	fmt.Println(enc)

	dec, err := cphr.Open(nil, nonce, enc, openData)
	fmt.Println(dec, err)

	fmt.Println(bytes.Equal(mainData, dec))
}

package main

import "github.com/towleeee/go-cryptopro/store"

func main() {
	s, err := store.CertOpenSystemStore("MY")
	if err != nil {
		panic(err)
	}

	err = store.CertCloseStore(s, store.CERT_CLOSE_STORE_CHECK_FLAG)
	if err != nil {
		panic(err)
	}
}

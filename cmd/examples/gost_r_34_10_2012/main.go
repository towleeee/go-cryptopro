package main

import (
	"fmt"

	gkeys "github.com/towleeee/go-cryptopro/gost_r_34_10_2012"
)

func main() {
	gkeys.Debug = false
	// cfg := gkeys.NewConfig(gkeys.K256, "username", "password")
	cfg := gkeys.SimpleConfig(gkeys.K256, "username", "password", gkeys.AT_SIGNATURE)
	fmt.Printf("{cfg: %+v}", cfg)
	err := gkeys.GenPrivKey(cfg)
	if err != nil {
		fmt.Println("Warning: key already exist?")
	}

	priv, err := gkeys.NewPrivKey(cfg)
	if err != nil {
		panic(err)
	}

	pub := priv.PubKey(gkeys.AT_SIGNATURE)
	pbytes := pub.Bytes()

	msg := []byte("hello, world!")
	sign, err := priv.Sign(msg, gkeys.AT_SIGNATURE)
	if err != nil {
		panic(err)
	}

	fmt.Printf(
		"Type: %s;\nPubKey [%dB]: %x;\nSign [%dB]: %x;\nSuccess: %t;\n",
		pub.Type(),
		len(pbytes),
		pbytes,
		len(sign),
		sign,
		pub.VerifySignature(msg, sign),
	)
}

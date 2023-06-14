package gost_r_34_10_2012

/*
#cgo LDFLAGS: -Wl,--allow-multiple-definition
#cgo linux,amd64 CFLAGS: -I/opt/cprocsp/include/cpcsp -DUNIX -DLINUX -DSIZEOF_VOID_P=8
#cgo linux,386 CFLAGS: -I/opt/cprocsp/include/cpcsp -DUNIX -DLINUX -DSIZEOF_VOID_P=4
#cgo linux,amd64 LDFLAGS: -L/opt/cprocsp/lib/amd64/ -lcapi10 -lcapi20 -lrdrsup -lssp
#cgo linux,386 LDFLAGS: -L/opt/cprocsp/lib/ia32/ -lcapi10 -lcapi20 -lrdrsup -lssp
*/
import "C"
import (
	"encoding/hex"
	"fmt"
	"unsafe"

	ghash "github.com/towleeee/go-cryptopro/gost_r_34_11_2012"
)

/*
 * INTERFACES
 */

type Address []byte

type PrivKey interface {
	Bytes() []byte
	String() string
	Sign(msg []byte) ([]byte, error)
	PubKey() PubKey
	Equals(PrivKey) bool
	Type() string
}

type PubKey interface {
	Address() Address
	Bytes() []byte
	String() string
	VerifySignature(msg []byte, sig []byte) bool
	Equals(PubKey) bool
	Type() string
}

type BatchVerifier interface {
	Add(key PubKey, message, signature []byte) error
	Verify() (bool, []bool)
}

/*
 * CONFIG
 */

type Config struct {
	prov      ProvType
	container string
	password  string
}

func NewConfig(prov ProvType, container, password string) *Config {
	switch prov {
	case K256, K512:
		return (&Config{
			prov:      prov,
			container: container,
			password:  password,
		}).wrap()
	default:
		return nil
	}
}

// SimpleConfig - NewConfig with soft wrapping
func SimpleConfig(prov ProvType, container, password string) *Config {
	switch prov {
	case K256, K512:
		return (&Config{
			prov:      prov,
			container: container,
			password:  password,
		}).softWrap()
	default:
		return nil
	}
}

// softWrap без хэша
func (cfg *Config) softWrap() *Config {
	dst := make([]byte, hex.EncodedLen(32))
	_ = hex.Encode(dst, []byte(cfg.container))
	dstP := make([]byte, hex.EncodedLen(32))
	_ = hex.Encode(dstP, []byte(cfg.password))
	c := &Config{
		prov:      cfg.prov,
		container: string(dst),
		password:  string(dstP),
	}
	fmt.Println(fmt.Sprintf("%+v", c))
	return c
}

func (cfg *Config) wrap() *Config {
	return &Config{
		prov: cfg.prov,
		container: hex.EncodeToString(ghash.SumHMAC(
			ghash.H256,
			[]byte(cfg.container),
			[]byte{byte(cfg.prov)},
		)),
		password: hex.EncodeToString(ghash.SumHMAC(
			ghash.H256,
			[]byte(cfg.password),
			[]byte(cfg.container),
		)),
	}
}

func toGOstring(cstr *C.uchar) string {
	return C.GoString((*C.char)(unsafe.Pointer(cstr)))
}

func toCstring(gostr string) *C.uchar {
	return (*C.uchar)(&append([]byte(gostr), 0)[0])
}

func toCbytes(data []byte) *C.uchar {
	if len(data) > 0 {
		return (*C.uchar)(&data[0])
	}
	return nil
}

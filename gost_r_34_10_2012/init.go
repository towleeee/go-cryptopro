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
	"bytes"
	"encoding/hex"
	"fmt"
	"unsafe"

	ghash "github.com/towleeee/go-cryptopro/gost_r_34_11_2012"
)

/*
 * INTERFACES
 */
const keyHashSize = ghash.Size256

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

// salt добить до 32
func salt(data string) string {
	buf := bytes.NewBufferString(data)
	h := ghash.Sum(ghash.ProvType(K256), buf.Bytes())
	if len(data) < keyHashSize {
		fmt.Println(fmt.Sprintf("{data: %s, len: %d}",
			buf.String(),
			buf.Len(),
		))
		buf.Write([]byte(":"))
		buf.Write(h[:keyHashSize-buf.Len()])
		fmt.Println(fmt.Sprintf("{buf: %s, len: %d, hmac_len: %d}",
			buf.String(),
			buf.Len(),
			len(h),
		),
		)
	}
	dst := make([]byte, hex.EncodedLen(keyHashSize))
	_ = hex.Encode(dst, buf.Bytes())
	return string(dst)
}

// softWrap без хэша
func (cfg *Config) softWrap() *Config {
	c := &Config{
		prov:      cfg.prov,
		container: salt(cfg.container),
		password:  salt(cfg.password),
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

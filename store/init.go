package store

/*
#cgo CFLAGS: -DUNIX -DLINUX -DHAVE_LIMITS_H -DSIZEOF_VOID_P=8 -I/opt/cprocsp/include/ -I/opt/cprocsp/include/cpcsp -I/opt/cprocsp/include/pki
#cgo LDFLAGS: -L/opt/cprocsp/lib/amd64 -lcapi20 -lcapi10
*/
import "C"
import (
	"errors"
	"fmt"
	"unsafe"
)

var CRYPT_E_STREAM_MSG_NOT_READY = errors.New("CRYPT_E_STREAM_MSG_NOT_READY")
var CRYPT_E_NOT_FOUND = errors.New("CRYPT_E_NOT_FOUND")

var winAPIErrors = map[int]error{
	0x80091010: CRYPT_E_STREAM_MSG_NOT_READY,
	0x80092004: CRYPT_E_NOT_FOUND,
}

func GetLastError() error {
	codeError := int(C.GetLastError())
	err := winAPIErrors[codeError]
	if err == nil {
		err = fmt.Errorf("0x%x", codeError)
	}
	return err
}

type CryptMsg struct {
	hCryptMsg *C.HCRYPTMSG
}

type CertStore struct {
	HCertStore *C.HCERTSTORE
}

func CertOpenSystemStore(storeName string) (*CertStore, error) {
	store := C.CertOpenSystemStore(0, C.CString(storeName))
	if store == nil {
		return nil, fmt.Errorf("can`t open store %s got error 0x%x", storeName, GetLastError())
	}
	return &CertStore{HCertStore: &store}, nil
}

func CertMsgOpenStore(msg *CryptMsg) (*CertStore, error) {
	store := C.CertOpenStore(C.CERT_STORE_PROV_MSG, X509_ASN_ENCODING|PKCS_7_ASN_ENCODING, 0, 0,
		unsafe.Pointer(*msg.hCryptMsg))
	if store == nil {
		return nil, fmt.Errorf("can't open store for message got error 0x%x", GetLastError())
	}
	return &CertStore{HCertStore: &store}, nil
}

func CertMemOpenStore() (*CertStore, error) {
	store := C.CertOpenStore(C.CERT_STORE_PROV_MEMORY, X509_ASN_ENCODING|PKCS_7_ASN_ENCODING, 0,
		C.CERT_STORE_CREATE_NEW_FLAG, nil)
	if store == nil {
		return nil, fmt.Errorf("can't open store for message got error 0x%x", GetLastError())
	}
	return &CertStore{HCertStore: &store}, nil
}

func CertCloseStore(store *CertStore, flags uint32) error {
	if store == nil {
		return errors.New("store not exist")
	}

	status := C.CertCloseStore(*store.HCertStore, C.uint(flags))
	if status == 0 {
		return fmt.Errorf("can't close store got error 0x%x", GetLastError())
	}
	return nil
}

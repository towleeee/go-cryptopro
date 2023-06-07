package cert

/*
#cgo LDFLAGS: -Wl,--allow-multiple-definition
#cgo linux,amd64 CFLAGS: -DLINUX -DUNIX -DSIZEOF_VOID_P=8 -I/opt/cprocsp/include/ -I/opt/cprocsp/include/cpcsp -I/opt/cprocsp/include/pki
#cgo linux,amd64 LDFLAGS: -L/opt/cprocsp/lib/amd64 -lcapi20 -lcapi10
*/
import "C"

// #cgo CFLAGS: -DLINUX -DHAVE_LIMITS_H -DSIZEOF_VOID_P=8 -I/opt/cprocsp/include/ -I/opt/cprocsp/include/cpcsp -I/opt/cprocsp/include/pki
// #cgo LDFLAGS: -L/opt/cprocsp/lib/amd64 -lcapi20 -lcapi10

//#cgo LDFLAGS: -Wl,--allow-multiple-definition
//#cgo linux,amd64 CFLAGS: -I/opt/cprocsp/include/cpcsp -DUNIX -DLINUX -DSIZEOF_VOID_P=8
//#cgo linux,386 CFLAGS: -I/opt/cprocsp/include/cpcsp -DUNIX -DLINUX -DSIZEOF_VOID_P=4

//#cgo linux,amd64 LDFLAGS: -L/opt/cprocsp/lib/amd64/ -lcapi10 -lcapi20 -lrdrsup -lssp
//#cgo linux,386 LDFLAGS: -L/opt/cprocsp/lib/ia32/ -lcapi10 -lcapi20 -lrdrsup -lssp
//#cgo windows CFLAGS: -I/opt/cprocsp/include/cpcsp
//#cgo windows LDFLAGS: -lcrypt32 -lpthread

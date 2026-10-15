// Command dumphello prints the stdcode-encoded ClientHello bytes the client
// sends, for wire-level interop debugging against the Rust exit.
package main

import (
	"fmt"

	"github.com/geph-official/geph5-go/internal/exithandshake"
)

func main() {
	_, myPub, err := exithandshake.NewEphemeralKey()
	if err != nil {
		panic(err)
	}
	hello := exithandshake.ClientHello{
		Credentials: nil,
		CryptHello: exithandshake.ClientCryptHello{
			Kind:      exithandshake.KindX25519,
			X25519Pub: myPub,
		},
	}
	b, err := hello.MarshalStdcode()
	if err != nil {
		panic(err)
	}
	fmt.Printf("HELLO_LEN=%d\n", len(b))
	fmt.Printf("HELLO_HEX=%x\n", b)
}

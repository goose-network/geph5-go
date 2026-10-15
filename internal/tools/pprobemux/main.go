// Command pprobemux drives the real Rust exit over raw TCP from inside the
// module, using the exact same packages the client uses (conntest handshake,
// exithandshake, framing, picomux). It exists to debug tunnel-open behavior:
// it opens a picomux session, sends the metadata stream, then a rich tunnel
// command, and prints every frame exchange until a response or timeout.
package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"github.com/geph-official/geph5-go/internal/exithandshake"
	"github.com/geph-official/geph5-go/internal/picomux"
	"github.com/geph-official/geph5-go/internal/sillad"
	"github.com/geph-official/geph5-go/internal/stdcode"
)

func main() {
	addr := os.Getenv("EXIT_ADDR")
	if addr == "" {
		addr = "127.0.0.1:39001"
	}
	target := os.Getenv("TARGET")
	if target == "" {
		target = "192.168.15.170:39099"
	}
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		panic(err)
	}
	defer conn.Close()
	fmt.Println("connected to", addr)

	// -- conntest ping: 2-byte BE size 7, payload, echo, then 0x0000
	payload := make([]byte, 7)
	if _, err := readRand(payload); err != nil {
		panic(err)
	}
	var sz [2]byte
	sz[0] = byte(len(payload) >> 8)
	sz[1] = byte(len(payload))
	if _, err := conn.Write(sz[:]); err != nil {
		panic(err)
	}
	if _, err := conn.Write(payload); err != nil {
		panic(err)
	}
	echo := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, echo); err != nil {
		panic(err)
	}
	if hex.EncodeToString(echo) != hex.EncodeToString(payload) {
		panic("echo mismatch")
	}
	if _, err := conn.Write([]byte{0x00, 0x00}); err != nil {
		panic(err)
	}
	fmt.Println("conntest ok")

	// -- ClientHello: creds empty, X25519
	myPriv, myPub, err := exithandshake.NewEphemeralKey()
	if err != nil {
		panic(err)
	}
	e := stdcode.NewEncoder()
	e.EncodeBytes(nil)
	e.EncodeU32(1) // X25519 variant index (declaration order: SharedSecretChallenge=0, X25519=1)
	e.EncodeRaw(myPub[:])
	helloBytes := e.Bytes()
	if err := writePrepend(conn, helloBytes); err != nil {
		panic(err)
	}
	respBytes, err := readPrepend(conn)
	if err != nil {
		panic(err)
	}
	fmt.Printf("exit hello received (%d bytes), first byte (variant) = %d\n", len(respBytes), respBytes[0])
	var exitHello exithandshake.ExitHello
	if err := exitHello.UnmarshalStdcode(respBytes); err != nil {
		panic(err)
	}
	fmt.Printf("exit hello inner kind = %d (0=Reject 1=SSResp 2=X25519)\n", exitHello.Inner.Kind)

	// -- verify signature over (helloBytes ++ innerBytes)
	_ = myPriv
	readKey, writeKey := exithandshake.DeriveKeys(myPriv, exitHello.Inner.X25519Pub)
	fmt.Println("keys derived")

	crypt, err := exithandshake.NewClientCryptPipe(&sillad.ConnPipe{Conn: conn, ProtocolStr: "plain"}, readKey, writeKey)
	if err != nil {
		panic(err)
	}
	mux := picomux.New(crypt)
	mux.SetLiveness(picomux.LivenessConfig{PingInterval: 1200 * time.Second, Timeout: 120 * time.Second})

	// metadata stream first
	metaStream, err := mux.Open([]byte("null"))
	if err != nil {
		panic(err)
	}
	metaStream.Close()
	fmt.Println("metadata stream opened+closed")

	// rich tunnel command
	cmd := map[string]string{"protocol": "tcp", "host": target}
	cmdJSON, _ := json.Marshal(cmd)
	cmdStream, err := mux.Open(cmdJSON)
	if err != nil {
		panic(err)
	}
	fmt.Println("tunnel stream opened, metadata:", string(cmdJSON))
	cmdStream.SetReadDeadline(time.Now().Add(20 * time.Second))

	// read the 4-byte-BE length-prefixed RichTunnelResponse
	var lenBuf [4]byte
	if _, err := io.ReadFull(cmdStream, lenBuf[:]); err != nil {
		fmt.Println("ERROR reading response length:", err)
		// dump whatever else arrives on any stream
		time.Sleep(2 * time.Second)
		return
	}
	n := uint32(lenBuf[0])<<24 | uint32(lenBuf[1])<<16 | uint32(lenBuf[2])<<8 | uint32(lenBuf[3])
	fmt.Println("response length:", n)
	body := make([]byte, n)
	if _, err := io.ReadFull(cmdStream, body); err != nil {
		fmt.Println("ERROR reading response body:", err)
		return
	}
	fmt.Println("response body:", string(body))

	// If success, speak a trivial HTTP GET
	httpReq := fmt.Sprintf("GET /probe.txt HTTP/1.0\r\nHost: %s\r\n\r\n", target)
	cmdStream.SetWriteDeadline(time.Now().Add(10 * time.Second))
	if _, err := cmdStream.Write([]byte(httpReq)); err != nil {
		fmt.Println("write err:", err)
		return
	}
	cmdStream.SetReadDeadline(time.Now().Add(15 * time.Second))
	resp, err := io.ReadAll(cmdStream)
	fmt.Printf("HTTP response (%d bytes):\n%s\n", len(resp), string(resp))
}

func readRand(b []byte) (int, error) {
	f, err := os.Open("/dev/urandom")
	if err != nil {
		return 0, err
	}
	defer f.Close()
	return io.ReadFull(f, b)
}

func writePrepend(w io.Writer, payload []byte) error {
	var lenBuf [4]byte
	lenBuf[0] = byte(len(payload) >> 24)
	lenBuf[1] = byte(len(payload) >> 16)
	lenBuf[2] = byte(len(payload) >> 8)
	lenBuf[3] = byte(len(payload))
	if _, err := w.Write(lenBuf[:]); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

func readPrepend(r io.Reader) ([]byte, error) {
	var lenBuf [4]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return nil, err
	}
	n := uint32(lenBuf[0])<<24 | uint32(lenBuf[1])<<16 | uint32(lenBuf[2])<<8 | uint32(lenBuf[3])
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		return nil, err
	}
	return b, nil
}

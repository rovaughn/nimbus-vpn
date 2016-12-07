package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"github.com/BurntSushi/toml"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/songgao/water"
	"golang.org/x/crypto/nacl/box"
	"log"
	"net"
	"os"
	"os/exec"
)

type Strings []string

func (ss Strings) String() string {
	return fmt.Sprintf("%#v", ss)
}

func (ss *Strings) Set(value string) error {
	*ss = append(*ss, value)
	return nil
}

func DecodeKey(s string) (*[32]byte, error) {
	out := new([32]byte)

	if _, err := hex.Decode(out[:], []byte(s)); err != nil {
		return nil, err
	}

	return out, nil
}

type PublicKey [32]byte

func (pk *PublicKey) UnmarshalText(text []byte) error {
	_, err := hex.Decode((*[32]byte)(pk)[:], text)
	return err
}

func (pk *PublicKey) String() string {
	return string((*[32]byte)(pk)[:])
}

type SecretKey [32]byte

func (sk *SecretKey) UnmarshalText(text []byte) error {
	_, err := hex.Decode((*[32]byte)(sk)[:], text)
	return err
}

type Message []byte

func CreateMessage(out []byte, payload []byte, sharedKey *[32]byte) Message {
	var nonce [24]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		panic(err)
	}
	out = append(out, nonce[:]...)
	out = box.SealAfterPrecomputation(out, payload, &nonce, sharedKey)
	return Message(out)
}

func (m Message) Open(out []byte, sharedKey *[32]byte) ([]byte, bool) {
	var nonce [24]byte
	copy(nonce[:], []byte(m))
	return box.OpenAfterPrecomputation(out, []byte(m)[24:], &nonce, sharedKey)
}

func (m Message) Nonce() []byte {
	return []byte(m)[:24]
}

func CopyMessage(in []byte) Message {
	new := make([]byte, len(in))
	copy(new, in)
	return Message(new)
}

func main() {
	if len(os.Args) == 2 && os.Args[1] == "keypair" {
		publicKey, secretKey, err := box.GenerateKey(rand.Reader)
		if err != nil {
			panic(err)
		}

		fmt.Printf("PublicKey = \"%s\"\n", hex.EncodeToString(publicKey[:]))
		fmt.Printf("SecretKey = \"%s\"\n", hex.EncodeToString(secretKey[:]))
		return
	}

	type Identity struct {
		Name      string
		PublicKey PublicKey
		SecretKey SecretKey
		Route     string
		Peers     []string
	}

	type Contact struct {
		Name      string
		PublicKey PublicKey
		Address   string
		Remote    string
	}

	type Remote struct {
		Address string
	}

	type Listener struct {
		Address string
	}

	type Tunnel struct {
		Address   string
		Identity  string
		Contact   string
		Translate string
	}

	var config struct {
		Identity []Identity
		Contact  []Contact
		Remote   []Remote
		Listener []Listener
		Tunnel   []Tunnel
	}

	if _, err := toml.DecodeFile(os.Args[1], &config); err != nil {
		panic(err)
	}

	type RemoteConn struct {
		Address    *net.UDPAddr
		Conn       *net.UDPConn
		UseWriteTo bool
		SentNonce  map[string]bool
	}

	identityByName := make(map[string]*Identity)
	identityByPublicKey := make(map[string]*Identity)
	contactByName := make(map[string]*Contact)
	contactByPublicKey := make(map[string]*Contact)
	remoteConns := make([]RemoteConn, 0, len(config.Remote))
	routeMessage := make(chan Message)
	subscribeMessages := make(chan chan<- Message)
	newRemote := make(chan RemoteConn)

	for i := range config.Remote {
		addr, err := net.ResolveUDPAddr("udp", config.Remote[i].Address)
		if err != nil {
			panic(err)
		}

		conn, err := net.DialUDP("udp", nil, addr)
		if err != nil {
			panic(err)
		}

		remoteConns = append(remoteConns, RemoteConn{
			Address:    addr,
			Conn:       conn,
			UseWriteTo: false,
			SentNonce:  make(map[string]bool),
		})
	}

	for i := range config.Identity {
		identity := &config.Identity[i]
		identityByName[identity.Name] = identity
		identityByPublicKey[identity.PublicKey.String()] = identity
	}

	for i := range config.Contact {
		contact := &config.Contact[i]
		contactByName[contact.Name] = contact
		contactByPublicKey[contact.PublicKey.String()] = contact
	}

	go func() {
		subscriptions := make([]chan<- Message, 0)

		for {
			select {
			case subscription := <-subscribeMessages:
				subscriptions = append(subscriptions, subscription)
			case newRemote := <-newRemote:
				exists := false
				for _, remote := range remoteConns {
					if remote.Address.String() == newRemote.Address.String() {
						exists = true
						break
					}
				}
				if !exists {
					remoteConns = append(remoteConns, newRemote)
				}
			case message := <-routeMessage:
				nonceStr := string(message.Nonce())

				for _, remoteConn := range remoteConns {
					if remoteConn.SentNonce[nonceStr] {
						continue
					}

					remoteConn.SentNonce[nonceStr] = true

					log.Printf("Sending message %x to %s", nonceStr, remoteConn.Address)
					if remoteConn.UseWriteTo {
						if _, err := remoteConn.Conn.WriteToUDP([]byte(message), remoteConn.Address); err != nil {
							log.Println("Sending message:", err)
						}
					} else {
						if _, err := remoteConn.Conn.Write([]byte(message)); err != nil {
							log.Println("Sending message:", err)
						}
					}
				}

				for _, subscription := range subscriptions {
					subscription <- message
				}
			}
		}
	}()

	// A tunnel is an interface between normal IP and our system.  A packet sent
	// to tunnel.Address will be addressed from tunnel.Identity to
	// tunnel.Contact.  If tunnel.Translate set, then the destination IP is
	// replaced by it.
	for i := range config.Tunnel {
		go func(tunnel *Tunnel) {
			tun, err := water.NewTUN("")
			if err != nil {
				panic(err)
			}
			defer tun.Close()

			//identity := identityByName[tunnel.Identity]

			if _, err := exec.Command("ip", "link", "set", "dev", tun.Name(), "up").Output(); err != nil {
				panic(err)
			}

			if _, err := exec.Command("ip", "route", "add", tunnel.Address, "dev", tun.Name()).Output(); err != nil {
				panic(err)
			}

			translateIP := net.ParseIP(tunnel.Translate)
			untranslatedIP := net.ParseIP(tunnel.Address)

			//identityPublicKey := identityByName[tunnel.Identity].PublicKey
			identitySecretKey := identityByName[tunnel.Identity].SecretKey
			contactPublicKey := contactByName[tunnel.Contact].PublicKey

			var sharedKey [32]byte
			box.Precompute(&sharedKey, (*[32]byte)(&contactPublicKey), (*[32]byte)(&identitySecretKey))

			log.Printf("Tunnel %s (%s) is ready", tun.Name(), tunnel.Address)

			go func() {
				in := make([]byte, 2048)
				out := make([]byte, 2048)

				var ip4 layers.IPv4
				var udp layers.UDP
				var payload gopacket.Payload
				//var tcp layers.TCP

				parser := gopacket.NewDecodingLayerParser(layers.LayerTypeIPv4, &ip4, &udp, &payload)
				decoded := []gopacket.LayerType{}
				buf := gopacket.NewSerializeBuffer()
				opts := gopacket.SerializeOptions{}

				for {
					n, err := tun.Read(in)
					if err != nil {
						panic(err)
					}

					if translateIP != nil {
						if err := parser.DecodeLayers(in[:n], &decoded); err != nil {
							log.Println("Decoding packet into tun:", err)
							continue
						}

						log.Printf("Incoming packet %s -> %s", ip4.SrcIP, ip4.DstIP)

						ip4.DstIP = translateIP

						if err := gopacket.SerializeLayers(buf, opts, &ip4, &udp, &payload); err != nil {
							log.Println("Serializing packet:", err)
							continue
						}

						routeMessage <- CreateMessage(out[:0], buf.Bytes(), &sharedKey)
					} else {
						routeMessage <- CreateMessage(out[:0], in[:n], &sharedKey)
					}
				}
			}()

			go func() {
				subscription := make(chan Message)
				subscribeMessages <- subscription
				out := make([]byte, 2048)

				var ip4 layers.IPv4
				var udp layers.UDP
				var payload gopacket.Payload
				//var tcp layers.TCP

				parser := gopacket.NewDecodingLayerParser(layers.LayerTypeIPv4, &ip4, &udp, &payload)
				decoded := []gopacket.LayerType{}
				buf := gopacket.NewSerializeBuffer()
				opts := gopacket.SerializeOptions{}

				for message := range subscription {
					out, ok := message.Open(out[:0], &sharedKey)
					if !ok {
						continue
					}

					log.Printf("Message %x leaving tunnel %s", message.Nonce(), tunnel.Address)

					if translateIP != nil {
						if err := parser.DecodeLayers(out, &decoded); err != nil {
							log.Println("Decoding packet out of tun:", err)
							continue
						}

						log.Printf("Packet is %s -> %s", ip4.SrcIP, ip4.DstIP)

						if !ip4.SrcIP.Equal(translateIP) {
							log.Println("Expected packet to have address %s not %s", translateIP, ip4.SrcIP)
							continue
						}

						ip4.SrcIP = untranslatedIP

						log.Printf("Packet is now %s:%d -> %s:%d", ip4.SrcIP, udp.SrcPort, ip4.DstIP, udp.DstPort)

						if err := gopacket.SerializeLayers(buf, opts, &ip4, &udp, &payload); err != nil {
							log.Println("Serializing packet:", err)
							continue
						}

						if _, err := tun.Write(buf.Bytes()); err != nil {
							panic(err)
						}
					} else {
						if _, err := tun.Write(out); err != nil {
							panic(err)
						}
					}
				}
			}()

			select {}
		}(&config.Tunnel[i])
	}

	// A listener is an open port that allows messages to enter our system.
	for i := range config.Listener {
		go func(listener *Listener) {
			addr, err := net.ResolveUDPAddr("udp", listener.Address)
			if err != nil {
				panic(err)
			}

			conn, err := net.ListenUDP("udp", addr)
			if err != nil {
				panic(err)
			}
			defer conn.Close()

			in := make([]byte, 2048)

			log.Printf("Listener %s is ready", listener.Address)

			for {
				n, remoteAddr, err := conn.ReadFromUDP(in)
				if err != nil {
					panic(err)
				}

				newRemote <- RemoteConn{
					Address:    remoteAddr,
					Conn:       conn,
					UseWriteTo: true,
					SentNonce:  make(map[string]bool),
				}
				routeMessage <- CopyMessage(in[:n])
			}
		}(&config.Listener[i])
	}

	select {}
}

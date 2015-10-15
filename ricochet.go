// ricochet.go - Ricochet protocol implementation.
//
// To the extent possible under law, Yawning Angel waived all copyright
// and related or neighboring rights to ricochet (library), using the Creative
// Commons "CC0" public domain dedication. See LICENSE or
// <http://creativecommons.org/publicdomain/zero/1.0/> for full details.

// Package ricochet implements the Ricochet chat protocol.
package ricochet

//
// Annoyances with the current spec:
//  * There is no "correct" behavior specified for when more than 1 connection
//    exists from a given peer.  Yes, it's a race condition, yes behavior
//    should be specified.
//  * `channel_identifier` is specified as a int32 when opening, but
//    packetization only allows for a uint16.
//  * Unparsable/invalid packets only tear down the channel, when the full
//    connection should be torn down (version/extensions are negotiated, so
//    there's no excuse for spitting out something broken).
//  * KeepAlive responses should be rate limited.
//  * KeepAlive requests/respones should have a tag that is echoed.
//  * After sending an Auth HS response, closing the channel is optional.
//    This should be a MUST, done by the server.
//  * There is one and only one sensible place over the course of a connection
//    to exchange a EnableFeatures/FeatureEnabled pair (as the first set of
//    messages).  This should be specified as such.
//  * "using PKCS #1 v2.0 (as per OpenSSL RSA_sign)" is insufficient
//     information to actually verify proof signatures.
//  * Signing the HMAC output directly, despite using a NID denoting SHA256 is
//    unusual.
//  * The whole channel thing is over-engineering and over-complication.
//    * All the channels are singletons, and all but chat are only ever client
//      initiated.
//    * Authentication and contact authorization shouldn't require their own
//      channel, since both are required to do anything else.
//    * The RequestContact OpenChannel's implicit response method shouldn't
//      exist.
//
// Nice to haves:
//  * There is no way to get the full public key of the server, without
//    querying the HS descriptor via the Tor control port.
//

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/proxy"

	"github.com/yawning/bulb"
	"github.com/yawning/bulb/utils/pkcs1"
	"github.com/yawning/ricochet/packet"
)

const (
	PublicKeyBits = 1024

	ricochetPort = 9878

	protocolVersion      = 0x01
	protocolVersionError = 0xff

	packetHdrSize = 2 + 2

	unknownHostname = "<unknown>"
	onionSuffix     = ".onion"

	chatChannelType = "im.ricochet.chat"

	handshakeTimeout      = 30 * time.Second
	authenticationTimeout = 30 * time.Second
)

var handshakePrefix = []byte{0x49, 0x4d}

type EndpointConfig struct {
	TorControlPort *bulb.Conn
	PrivateKey     *rsa.PrivateKey
	KnownContacts  []string
}

type Endpoint struct {
	sync.Mutex

	hostname string

	privateKey *rsa.PrivateKey
	ctrl       *bulb.Conn
	isoBase    *proxy.Auth
	ln         net.Listener

	contacts *contactMgr
}

type ricochetConn struct {
	sync.Mutex

	endpoint *Endpoint
	conn     net.Conn
	hostname string

	chanMap   map[uint16]ricochetChan
	authTimer *time.Timer

	isServer   bool
	nextChanID uint16
}

type ricochetChan interface {
	onOpenChannel() error
	onChannelResult(*packet.ChannelResult) error
	onPacket([]byte) error
	onClose() error
}

func (c *ricochetConn) nextPacket() (uint16, []byte, error) {
	// Read a packet from the network connection.
	//  uint16_t size (Including header)
	//  uint16_t channel
	//  uint16_t data
	var pktHdr [4]byte
	if _, err := io.ReadFull(c.conn, pktHdr[:]); err != nil {
		return 0, nil, fmt.Errorf("failed to read pkt header: %v", err)
	}
	pktSize := binary.BigEndian.Uint16(pktHdr[0:])
	pktChan := binary.BigEndian.Uint16(pktHdr[2:])
	if pktSize <= packetHdrSize {
		return pktChan, nil, io.EOF
	}
	pktSize -= packetHdrSize
	pktData := make([]byte, pktSize)
	if _, err := io.ReadFull(c.conn, pktData); err != nil {
		return 0, nil, fmt.Errorf("failed to read pkt data: %v", err)
	}
	return pktChan, pktData, nil
}

func (c *ricochetConn) sendPacket(pktChan uint16, pktData []byte) error {
	c.Lock()
	defer c.Unlock()

	pktLen := packetHdrSize + len(pktData)
	if pktLen > math.MaxUint16 {
		return fmt.Errorf("pkt > max size: %v", pktLen)
	}

	var pktHdr [4]byte
	binary.BigEndian.PutUint16(pktHdr[0:], uint16(pktLen))
	binary.BigEndian.PutUint16(pktHdr[2:], pktChan)
	if _, err := c.conn.Write(pktHdr[:]); err != nil {
		return err
	}
	_, err := c.conn.Write(pktData)
	return err
}

func (c *ricochetConn) allocateNextChanID() (uint16, error) {
	c.Lock()
	defer c.Unlock()

	chanID := c.nextChanID
	if ((int)(chanID) + 2) > math.MaxUint16 {
		// Could happen, unlikely to happen since it means that over 32k
		// channels were opened
		//
		// TODO: Handle this in a better manner.
		return 0, fmt.Errorf("bug: next channel ID will wrap")
	}
	c.nextChanID += 2 // Channel IDs are all odd or even.
	return chanID, nil
}

func NewEndpoint(cfg *EndpointConfig) (e *Endpoint, err error) {
	e = new(Endpoint)
	e.hostname, _ = pkcs1.OnionAddr(&cfg.PrivateKey.PublicKey)
	e.privateKey = cfg.PrivateKey
	e.ctrl = cfg.TorControlPort
	e.isoBase, err = getIsolationAuth()
	if err != nil {
		return nil, err
	}

	e.ln, err = e.ctrl.Listener(ricochetPort, e.privateKey)
	if err != nil {
		return nil, err
	}

	log.Printf("server: online as '%v'", e.hostname)

	e.contacts = newContactMgr(e, cfg.KnownContacts)
	go e.hsAcceptWorker()

	return e, nil
}

func (e *Endpoint) hsAcceptWorker() {
	// Accept incoming connections from the HS listener, and dispatch go
	// routines to handle handshaking.
	for {
		conn, err := e.ln.Accept()
		if err != nil {
			if e, ok := err.(net.Error); ok && !e.Temporary() {
				break
			}
			continue
		}
		go e.serverHandshake(conn)
	}
}

func (e *Endpoint) SendMsg(hostname, message string) error {
	return nil
}

func (e *Endpoint) dialClient(hostname string) (*ricochetConn, error) {
	dialHostname := hostname
	if !strings.HasSuffix(hostname, onionSuffix) {
		dialHostname = hostname + onionSuffix
	}
	dialHostname = fmt.Sprintf("%s:%d", dialHostname, ricochetPort)
	log.Printf("client: new server connection: '%v'", hostname)

	// Obtain a Tor backed proxy.Dialer with appropriate isolation set.
	auth := &proxy.Auth{User: e.isoBase.User, Password: hostname}
	d, err := e.ctrl.Dialer(auth)
	if err != nil {
		log.Printf("client: Failed to get outgoing Dialer: %v", err)
		return nil, err
	}

	rConn := new(ricochetConn)
	rConn.endpoint = e
	rConn.hostname = hostname
	rConn.isServer = false
	rConn.nextChanID = 1
	go rConn.clientHandshake(d, dialHostname)

	return rConn, nil
}

func (c *ricochetConn) clientHandshake(d proxy.Dialer, dialHostname string) {
	var err error
	defer func() {
		if c.conn != nil {
			c.conn.Close()
		}
		c.endpoint.contacts.onOutgoingConnectionClosed(c)
	}()

	// Open the connection to the remote HS.
	c.conn, err = d.Dial("tcp", dialHostname)
	if err != nil {
		log.Printf("client: Failed to connect to '%v' : %v", dialHostname, err)
		return
	}

	// Arm the handshake timeout.
	if err := c.conn.SetDeadline(time.Now().Add(handshakeTimeout)); err != nil {
		log.Printf("client: Failed to arm handshake timeout: %v", err)
		return
	}

	// Send prefix | nVersions | version.
	hsPrefix := append(handshakePrefix, 1)       // Sending one version...
	hsPrefix = append(hsPrefix, protocolVersion) // ... this one.
	if _, err := c.conn.Write(hsPrefix); err != nil {
		log.Printf("client: Failed to send prefix | nVersions | version: %v", err)
		return
	}

	// Read the negotiated version.
	var respVer [1]byte
	if _, err := io.ReadFull(c.conn, respVer[:]); err != nil {
		log.Printf("client: Failed to read negotiated version: %v", err)
		return
	}
	if respVer[0] != protocolVersion {
		log.Printf("client: Server speaks no compatible versions, closing")
		return
	}

	// Disarm the handshake timeout.
	if err := c.conn.SetDeadline(time.Time{}); err != nil {
		log.Printf("client: Failed to disarm handshake timeout: %v", err)
		return
	}

	c.chanMap = make(map[uint16]ricochetChan)
	c.chanMap[controlChanID] = newControlChan(c, controlChanID)

	fuck := func() { _ = c.conn.Close() }
	c.authTimer = time.AfterFunc(authenticationTimeout, fuck)

	// Send the OpenChannel(AuthHS) request before doing anything else.  The
	// rest of the process is driven by receiving responses from the server,
	// or 'fuck()'.
	if err := newClientAuthHSChan(c); err != nil {
		log.Printf("client: Failed to start authentication: %v", err)
		return
	}

	c.incomingPacketWorker()
}

func (e *Endpoint) serverHandshake(conn net.Conn) {
	defer conn.Close()

	log.Printf("server: new client connection")

	// Arm the handshake timeout.
	if err := conn.SetDeadline(time.Now().Add(handshakeTimeout)); err != nil {
		log.Printf("server: Failed to arm handshake timeout: %v", err)
		return
	}

	// Read in the protocol versions supported by the client.
	var hsPrefix [3]byte
	if _, err := io.ReadFull(conn, hsPrefix[:]); err != nil {
		log.Printf("server: Failed to read in prefix | nVersions: %v", err)
		return
	}
	if !bytes.Equal(hsPrefix[0:2], handshakePrefix) {
		log.Printf("server: Invalid handshake prefix")
		return
	}
	versions := make([]byte, hsPrefix[2])
	if _, err := io.ReadFull(conn, versions); err != nil {
		log.Printf("server: Failed to read in versions: %v", err)
		return
	}

	// Determine if the client speaks a supported version.
	respVer := []byte{protocolVersionError}
	for _, v := range versions {
		if v == protocolVersion {
			respVer[0] = protocolVersion
			break
		}
	}
	if _, err := conn.Write(respVer); err != nil {
		log.Printf("server: Failed to send protocol version: %v", err)
		return
	}
	if respVer[0] == protocolVersionError {
		log.Printf("server: Client speaks no compatible versions, closing")
		return
	}

	// Disarm the handshake timeout.
	if err := conn.SetDeadline(time.Time{}); err != nil {
		log.Printf("server: Failed to disarm handshake timeout: %v", err)
		return
	}

	rConn := new(ricochetConn)
	rConn.endpoint = e
	rConn.conn = conn
	rConn.hostname = unknownHostname
	rConn.isServer = true
	rConn.nextChanID = 2
	rConn.chanMap = make(map[uint16]ricochetChan)
	rConn.chanMap[controlChanID] = newControlChan(rConn, controlChanID)

	fuck := func() { _ = conn.Close() }
	rConn.authTimer = time.AfterFunc(authenticationTimeout, fuck)

	rConn.incomingPacketWorker()

	// XXX: Remove connection from the global state.
}

func (c *ricochetConn) incomingPacketWorker() {
	for {
		chanID, rawPkt, err := c.nextPacket()
		if err == io.EOF {
			if err = c.demuxChanClose(chanID); err == nil {
				continue
			}
		}
		if err != nil {
			log.Printf("worker: early pkt processing: %v", err)
			return
		}

		ch := c.chanMap[chanID]
		if ch == nil {
			log.Printf("worker: received pkt for invalid channel: %v", err)
			return
		}
		if err = ch.onPacket(rawPkt); err != nil {
			log.Printf("worker: channel pkt processing: %v", err)
			return
		}
	}
}

func (c *ricochetConn) demuxChanClose(chanID uint16) error {
	ch := c.chanMap[chanID]
	if ch == nil {
		return fmt.Errorf("close for invalid channel: %v", chanID)
	}
	return ch.onClose()
}

func getIsolationAuth() (*proxy.Auth, error) {
	const isoUsername = "ricochet-client:"

	var isoSeed [256]byte
	if _, err := rand.Read(isoSeed[:]); err != nil {
		return nil, fmt.Errorf("failed to generate isolation cookie: %v", err)
	}
	isoHash := sha256.Sum256(isoSeed[:])
	isoCookie := base64.StdEncoding.EncodeToString(isoHash[:])
	return &proxy.Auth{User: isoUsername + isoCookie}, nil
}

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
//    exists to/from a given peer.  Yes, it's a race condition, yes behavior
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
//    information to actually verify proof signatures.
//  * Signing the HMAC output directly, despite using a NID denoting SHA256 is
//    unusual.
//  * The reference implementation closes the connection when previously
//    rejected clients try to authenticate.  This behavior leads to ambiguious
//    state on the client where the client can't tell if it's a transient
//    networking error or a rejection.
//  * The spec should explicitly state which party closes the contact request
//    channel, after an accept/reject/error response is sent (the server?).
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
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"

	"golang.org/x/net/proxy"

	"github.com/yawning/bulb"
	"github.com/yawning/bulb/utils/pkcs1"
)

const (
	PublicKeyBits = 1024

	ricochetPort = 9878

	unknownHostname = "<unknown>"
	onionSuffix     = ".onion"

	chatChannelType = "im.ricochet.chat"
)

type EndpointConfig struct {
	TorControlPort *bulb.Conn
	PrivateKey     *rsa.PrivateKey

	KnownContacts       []string
	BlacklistedContacts []string
}

type Endpoint struct {
	sync.Mutex

	hostname string

	privateKey *rsa.PrivateKey
	ctrl       *bulb.Conn
	isoBase    *proxy.Auth
	ln         net.Listener

	blacklist map[string]bool
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
	e.blacklist = make(map[string]bool)
	for _, id := range cfg.BlacklistedContacts {
		e.blacklist[id] = true
	}

	e.ln, err = e.ctrl.Listener(ricochetPort, e.privateKey)
	if err != nil {
		return nil, err
	}

	log.Printf("server: online as '%v'", e.hostname)

	go e.hsAcceptWorker()

	return e, nil
}

func (e *Endpoint) AddContact(hostname, requestData *ContactRequest) error {
	return nil
}

func (e *Endpoint) SendMsg(hostname, message string) error {
	return nil
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
		go e.acceptServer(conn)
	}
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
	rConn.chanMap = make(map[uint16]ricochetChan)
	go rConn.clientHandshake(d, dialHostname)

	return rConn, nil
}

func (e *Endpoint) acceptServer(conn net.Conn) {
	rConn := new(ricochetConn)
	rConn.endpoint = e
	rConn.conn = conn
	rConn.hostname = unknownHostname
	rConn.isServer = true
	rConn.nextChanID = 2
	rConn.chanMap = make(map[uint16]ricochetChan)
	rConn.serverHandshake()
}

func (e *Endpoint) isBlacklisted(hostname string) bool {
	e.Lock()
	defer e.Unlock()

	return e.blacklist[hostname]
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

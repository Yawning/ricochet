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
//  * There is no mention anywhere of MessageMaxCharacters, but the reference
//    implementation will reject "oversized" messages.
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
	"errors"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/proxy"

	"github.com/eapache/channels"
	"github.com/yawning/bulb"
	"github.com/yawning/bulb/utils/pkcs1"
)

const (
	PublicKeyBits = 1024

	ricochetPort         = 9878
	ricochetHostnameSize = 16

	unknownHostname = "<unknown>"
	onionSuffix     = ".onion"
	ricochetPrefix  = "ricochet:"

	contactRetryDelay = 60 * time.Second
)

var (
	ErrAlreadyExists = errors.New("contact already exists")
	ErrNoSuchContact = errors.New("no such contact")

	ricochetHostnameMap map[rune]bool
)

type EndpointConfig struct {
	TorControlPort *bulb.Conn
	PrivateKey     *rsa.PrivateKey

	KnownContacts       []string
	BlacklistedContacts []string
	PendingContacts     map[string]*ContactRequest
}

type Endpoint struct {
	sync.Mutex

	IncomingMsgChan chan *IncomingMessage

	hostname string

	privateKey *rsa.PrivateKey
	ctrl       *bulb.Conn
	isoBase    *proxy.Auth
	ln         net.Listener

	blacklist       map[string]bool
	contacts        map[string]*ricochetContact
	pendingContacts map[string]*ricochetContact

	outgoingQueue        *channels.InfiniteChannel
	incomingMsgQueue     *channels.InfiniteChannel
	incomingContactQueue *channels.InfiniteChannel
}

type IncomingMessage struct {
	From string
	Body string
}

type ricochetContact struct {
	conn        *ricochetConn
	requestData *ContactRequest
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
	e.outgoingQueue = channels.NewInfiniteChannel()
	e.incomingMsgQueue = channels.NewInfiniteChannel()
	e.incomingContactQueue = channels.NewInfiniteChannel()
	e.pendingContacts = make(map[string]*ricochetContact)

	e.IncomingMsgChan = make(chan *IncomingMessage)

	e.blacklist = make(map[string]bool)
	for _, id := range cfg.BlacklistedContacts {
		if err := e.BlacklistContact(id, true); err != nil {
			return nil, err
		}
	}
	e.contacts = make(map[string]*ricochetContact)
	for _, id := range cfg.KnownContacts {
		if err := e.AddContact(id, nil); err != nil {
			return nil, err
		}
	}
	for id, requestData := range cfg.PendingContacts {
		if err := e.AddContact(id, requestData); err != nil {
			return nil, err
		}
	}

	e.ln, err = e.ctrl.Listener(ricochetPort, e.privateKey)
	if err != nil {
		return nil, err
	}

	log.Printf("server: online as '%v'", e.hostname)

	go e.hsAcceptWorker()
	go e.hsConnectWorker()
	go e.incomingMsgWorker()

	return e, nil
}

func (e *Endpoint) AddContact(hostname string, requestData *ContactRequest) error {
	hostname, err := normalizeHostname(hostname)
	if err != nil {
		return err
	}

	e.Lock()
	defer e.Unlock()
	if contact := e.contacts[hostname]; contact != nil {
		return ErrAlreadyExists
	}
	if contact := e.pendingContacts[hostname]; contact != nil {
		// Treat adds when the peer has sent us a ContactRequest
		// as accepting said request.
		delete(e.pendingContacts, hostname)
		contact.requestData = requestData
		e.contacts[hostname] = contact
		if contact.conn == nil {
			e.outgoingQueue.In() <- hostname
		} else {
			// XXX: Accept the contact request, and mark peer online.
		}
		return nil
	}

	// Add to our map of known peers, and schedule a connect.
	contact := new(ricochetContact)
	contact.requestData = requestData
	e.contacts[hostname] = contact
	e.outgoingQueue.In() <- hostname
	return nil
}

func (e *Endpoint) BlacklistContact(hostname string, set bool) error {
	hostname, err := normalizeHostname(hostname)
	if err != nil {
		return err
	}

	e.Lock()
	defer e.Unlock()
	if set {
		e.blacklist[hostname] = true
		e.removeAndCloseConnLocked(hostname)
	} else {
		delete(e.blacklist, hostname)
	}
	return nil
}

func (e *Endpoint) RemoveContact(hostname string) error {
	hostname, err := normalizeHostname(hostname)
	if err != nil {
		return err
	}

	e.Lock()
	defer e.Unlock()

	e.removeAndCloseConnLocked(hostname)
	return nil
}

func (e *Endpoint) SendMsg(hostname, message string) error {
	hostname, err := normalizeHostname(hostname)
	if err != nil {
		return err
	}
	if len(message) > MessageMaxCharacters {
		return ErrMessageSize
	}

	// XXX: Send the message.

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

func (e *Endpoint) hsConnectWorker() {
	connectCh := e.outgoingQueue.Out()
	for {
		var err error

		// Grab the hostname out of the queue of outgoing peers to contact.
		v, ok := <-connectCh
		if !ok {
			break
		}
		hostname := v.(string)

		e.Lock()
		contact := e.contacts[hostname]
		if contact == nil || contact.conn != nil {
			// No longer exists, or there is a connection already.
			e.Unlock()
			continue
		}
		contact.conn, err = e.dialClient(hostname)
		e.Unlock()
		if err != nil {
			// Failed to prepare to dial the client, retry after a delay.
			// delay.
			reAddContact := func() {
				e.outgoingQueue.In() <- hostname
			}
			time.AfterFunc(contactRetryDelay, reAddContact)
			continue
		}
	}
}

func (e *Endpoint) incomingMsgWorker() {
	// Abuse a go routine to save the caller from having to include a type
	// assertion.  Sort of silly, but who cares.
	msgCh := e.incomingMsgQueue.Out()
	for {
		msg, ok := <-msgCh
		if !ok {
			break
		}
		e.IncomingMsgChan <- msg.(*IncomingMessage)
	}
}

func (e *Endpoint) dialClient(hostname string) (*ricochetConn, error) {
	dialHostname := hostname + onionSuffix
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

func (e *Endpoint) isKnown(hostname string) bool {
	e.Lock()
	defer e.Unlock()

	return e.contacts[hostname] != nil
}

func (e *Endpoint) isBlacklisted(hostname string) bool {
	e.Lock()
	defer e.Unlock()

	return e.blacklist[hostname]
}

func (e *Endpoint) requestData(hostname string) *ContactRequest {
	e.Lock()
	defer e.Unlock()

	if contact := e.contacts[hostname]; contact != nil {
		return contact.requestData
	}
	return nil
}

func (e *Endpoint) onConnectionEstablished(conn *ricochetConn) {
	e.Lock()
	defer e.Unlock()

	// If we still care about the peer...
	if contact := e.contacts[conn.hostname]; contact != nil {
		contact.updateConn(conn)

		// XXX: Notify caller that peer is online.
	} else {
		// User must have removed it while the connection was in
		// progress.  Close the connection.
		conn.closeConn()
	}
}

func (e *Endpoint) onConnectionClosed(conn *ricochetConn) {
	// Inbound connection from unknown peer, do nothing.
	if conn.hostname == unknownHostname {
		return
	}

	e.Lock()
	defer e.Unlock()

	// If we still care about the peer...
	if contact := e.contacts[conn.hostname]; contact != nil {
		// And this was the active connection to the peer...
		if contact.conn == conn {
			// The contact no longer has a connection.
			contact.conn = nil

			// XXX: Notify caller that the peer is offline.

			// Schedule a reconnect.
			e.outgoingQueue.In() <- conn.hostname
		}
	} else if contact := e.pendingContacts[conn.hostname]; contact != nil {
		// If this was a contact request from a peer pending approval...
		if contact.conn == conn {
			// Remove the connection, but do not remove the data structure.
			contact.conn = nil
		}
	}
}

func (e *Endpoint) onRemoteReject(hostname string) {
	e.Lock()
	defer e.Unlock()

	// If we still care about the peer...
	contact := e.contacts[hostname]
	if contact == nil {
		return
	}
	delete(e.contacts, hostname)
	if contact.requestData == nil {
		// XXX: Notify caller that peer removed us.
	} else {
		// XXX: Notify caller that peer rejected us.
	}
}

func (e *Endpoint) onMessageReceived(hostname, messageBody string) {
	msg := new(IncomingMessage)
	msg.From = hostname
	msg.Body = messageBody

	e.incomingMsgQueue.In() <- msg
}

func (e *Endpoint) removeAndCloseConnLocked(hostname string) {
	// e.Lock() should be held at this point.

	wasPending := false
	contact := e.contacts[hostname]
	if contact == nil {
		contact = e.pendingContacts[hostname]
		if contact == nil {
			return
		}
		delete(e.pendingContacts, hostname)
		wasPending = true
	} else {
		delete(e.contacts, hostname)
	}
	if contact.conn != nil {
		if wasPending {
			// XXX: Send a rejection.
		}
		contact.conn.closeConn()
	}
}

func (contact *ricochetContact) updateConn(conn *ricochetConn) {
	// If the connection already is set, do nothing.
	if contact.conn == conn {
		return
	}

	// If there is no connection, just set it.
	if contact.conn == nil {
		contact.conn = conn
		return
	}

	// XXX: If the old connection isn't established yet, new one wins.

	//
	// Taken from `ContactUser::assignConnection(Protocol::Connection)`
	//

	// If the new connection and the existing connection have the
	// same peers in the same positions (direction is the same),
	// favor the new one.
	if contact.conn.isServer == conn.isServer {
		contact.conn.closeConn()
		contact.conn = conn
		return
	}

	// XXX: If the old connection is more than 30 sec old, since when it was
	// fully established, prefer the new connection.

	// Tiebreak with strcmp based on digetests.
	preferOutbound := conn.hostname < conn.endpoint.hostname
	if !contact.conn.isServer && preferOutbound {
		conn.closeConn()
	} else {
		contact.conn.closeConn()
		contact.conn = conn
	}
}

func normalizeHostname(hostname string) (string, error) {
	// Convert the hostname to lower case, strip off 'ricochet:' and
	// '.onion' if present.  This will need to be changed for ed25519
	// hidden services, but that's a while out yet, and the whole protocol
	// will need a revamp.
	newStr := strings.ToLower(hostname)
	newStr = strings.TrimPrefix(newStr, ricochetPrefix)
	newStr = strings.TrimSuffix(newStr, onionSuffix)

	if len(newStr) != ricochetHostnameSize {
		return "", fmt.Errorf("invalid hostname, not %d bytes", ricochetHostnameSize)
	}
	for _, ch := range newStr {
		if !ricochetHostnameMap[ch] {
			return "", fmt.Errorf("invalid hostname char: '%v'", ch)
		}
	}

	return newStr, nil
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

func init() {
	ricochetHostnameMap = make(map[rune]bool)
	for _, ch := range "abcdefghijklmnopqrstuvwxyz234567" {
		ricochetHostnameMap[ch] = true
	}
}

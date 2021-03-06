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
	"io"
	"io/ioutil"
	golog "log"
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
	// PublicKeyBits is the size of a Ricochet RSA public modulus in bits.
	PublicKeyBits = 1024

	ricochetPort         = 9878
	ricochetHostnameSize = 16

	unknownHostname = "<unknown>"
	onionSuffix     = ".onion"
	ricochetPrefix  = "ricochet:"

	reconnectDelay    = 15 * time.Second
	contactRetryDelay = 60 * time.Second
)

var (
	// ErrAlreadyExists is the error returned when a contact already exists.
	ErrAlreadyExists = errors.New("contact already exists")
	// ErrNoSuchContact is the error returned when a contact does not exist.
	ErrNoSuchContact = errors.New("no such contact")
	// ErrBlacklisted is the error returned when a contact is blacklisted.
	ErrBlacklisted = errors.New("contact is blacklisted")

	ricochetHostnameMap map[rune]bool
)

// EndpointConfig is a Ricochet endpoint configuration.
type EndpointConfig struct {
	TorControlPort *bulb.Conn
	PrivateKey     *rsa.PrivateKey

	KnownContacts       []string
	BlacklistedContacts []string
	PendingContacts     map[string]*ContactRequest

	LogWriter io.Writer
}

// Endpoint is a active Ricochet client/server instance.
type Endpoint struct {
	sync.Mutex

	EventChan <-chan interface{}

	log        *golog.Logger
	hostname   string
	privateKey *rsa.PrivateKey
	ctrl       *bulb.Conn
	isoBase    *proxy.Auth
	ln         net.Listener

	blacklist       map[string]bool
	contacts        map[string]*ricochetContact
	pendingContacts map[string]*ricochetContact

	outgoingQueue *channels.InfiniteChannel
	eventQueue    *channels.InfiniteChannel
}

// IncomingMessage is a incoming message event from a peer.
type IncomingMessage struct {
	From    string
	Message string
}

// ContactState is the status for a given peer.
type ContactState int

const (
	ContactStateOffline ContactState = iota
	ContactStateRejected
	ContactStateRemoved
	ContactStateOnline
)

// ContactStateChange is a peer status change notification event.
type ContactStateChange struct {
	Hostname string
	OldState ContactState
	State    ContactState
}

type ricochetContact struct {
	conn        *ricochetConn
	requestData *ContactRequest
	state       ContactState
}

// NewEndpoint creates a Ricochet client/server endpoint with the provided
// configuration, including registering the ephemeral HS with Tor.
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
	e.eventQueue = channels.NewInfiniteChannel()
	e.pendingContacts = make(map[string]*ricochetContact)

	e.EventChan = e.eventQueue.Out()

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

	logWr := cfg.LogWriter
	if logWr == nil {
		logWr = ioutil.Discard
	}
	e.log = golog.New(logWr, "", golog.LstdFlags)

	e.log.Printf("server: online as '%v'", e.hostname)

	go e.hsAcceptWorker()
	go e.hsConnectWorker()

	return e, nil
}

// AddContact adds a peer to the contact list.  This routine is also should
// be used to accept contact requests received from remote peers.
func (e *Endpoint) AddContact(hostname string, requestData *ContactRequest) error {
	hostname, err := normalizeHostname(hostname)
	if err != nil {
		return err
	}
	if requestData != nil {
		// The caller shouldn't set this, and it shouldn't get used.
		// Set it to something correct just to be sure.
		requestData.Hostname = hostname
	}
	if e.isBlacklisted(hostname) {
		return ErrBlacklisted
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
		if contact.conn != nil {
			// Send the accept if possible.  If not, the right
			// thing will happen as part of connection teardown.
			if ch := contact.conn.getContactRequestChan(); ch != nil {
				if err := ch.sendContactReqResponse(true); err == nil {
					e.onContactStateChange(contact, hostname, ContactStateOnline)
				}
				return nil
			}
		} else {
			// No connection to peer, schedule one.
			e.outgoingQueue.In() <- hostname
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

// BlacklistContact adds/removes a given peer to/from the blacklist.
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

// RemoveContact removes a peer from the contact list.
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
			time.AfterFunc(contactRetryDelay, func() { e.outgoingQueue.In() <- hostname })
			continue
		}
	}
}

func (e *Endpoint) dialClient(hostname string) (*ricochetConn, error) {
	dialHostname := hostname + onionSuffix
	dialHostname = fmt.Sprintf("%s:%d", dialHostname, ricochetPort)
	e.log.Printf("client: New outgoing connection: '%v'", hostname)

	// Obtain a Tor backed proxy.Dialer with appropriate isolation set.
	auth := &proxy.Auth{User: e.isoBase.User, Password: hostname}
	d, err := e.ctrl.Dialer(auth)
	if err != nil {
		e.log.Printf("client: Failed to get outgoing Dialer: %v", err)
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
		contact.updateConnLocked(conn)
		e.onContactStateChange(contact, conn.hostname, ContactStateOnline)
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

			e.onContactStateChange(contact, conn.hostname, ContactStateOffline)
			time.AfterFunc(reconnectDelay, func() { e.outgoingQueue.In() <- conn.hostname })
		}
	} else if contact := e.pendingContacts[conn.hostname]; contact != nil {
		// If this was a contact request from a peer pending approval...
		if contact.conn == conn {
			// Remove the connection, but do not remove the data structure.
			contact.conn = nil
		}
	}
}

func (e *Endpoint) onContactRequest(conn *ricochetConn, requestData *ContactRequest) (bool, error) {
	e.Lock()
	defer e.Unlock()

	if e.blacklist[conn.hostname] {
		return false, fmt.Errorf("peer is blacklisted")
	}
	if contact := e.contacts[conn.hostname]; contact != nil {
		return true, nil
	}
	contact := e.pendingContacts[conn.hostname]
	if contact != nil {
		if contact.conn != nil {
			// Hm, they re-establised a new connection and re-sent
			// the request.  Keep the new connection since they must
			// have done it for a reason.
			contact.conn.closeConn()
		}
	} else {
		contact = new(ricochetContact)
		e.pendingContacts[conn.hostname] = contact
	}
	contact.conn = conn
	contact.requestData = requestData

	e.eventQueue.In() <- requestData

	return false, nil
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
		e.onContactStateChange(contact, hostname, ContactStateRemoved)
	} else {
		e.onContactStateChange(contact, hostname, ContactStateRejected)
	}
}

func (e *Endpoint) onMessageReceived(hostname, messageBody string) {
	msg := new(IncomingMessage)
	msg.From = hostname
	msg.Message = messageBody

	e.eventQueue.In() <- msg
}

func (e *Endpoint) onContactStateChange(contact *ricochetContact, hostname string, state ContactState) {
	// Suppress duplicate state change messages.
	if contact.state == state {
		return
	}

	e.log.Printf("[%v]: onContactStateChange '%v' -> '%v'", hostname, contact.state, state)

	msg := new(ContactStateChange)
	msg.Hostname = hostname
	msg.OldState = contact.state
	msg.State = state
	contact.state = state

	e.eventQueue.In() <- msg
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
		// Send a rejection.  Failures are harmless since the conn is
		// getting closed anyway.
		if wasPending {
			if ch := contact.conn.getContactRequestChan(); ch != nil {
				ch.sendContactReqResponse(false)
			}
		}
		contact.conn.closeConn()
	}
}

func (contact *ricochetContact) updateConnLocked(conn *ricochetConn) {
	// e.Lock() should be held at this point.
	log := conn.endpoint.log

	// If the connection already is set, do nothing.
	if contact.conn == conn {
		return
	}

	// If there is no connection, just set it.
	if contact.conn == nil {
		contact.conn = conn
		return
	}

	// If the old connection isn't established yet, new one wins.
	establishedAt := contact.conn.getEstablished()
	if establishedAt.Equal(time.Time{}) {
		log.Printf("[%v]: old connection is not established, new wins", conn.hostname)
		contact.conn.closeConn()
		contact.conn = conn
		return
	}

	//
	// Taken from `ContactUser::assignConnection(Protocol::Connection)`
	//

	// If the new connection and the existing connection have the
	// same peers in the same positions (direction is the same),
	// favor the new one.
	if contact.conn.isServer == conn.isServer {
		log.Printf("[%v]: both connections in same direction, new wins", conn.hostname)
		contact.conn.closeConn()
		contact.conn = conn
		return
	}

	// If the old connection is more than 30 sec old, since when it was
	// fully established, prefer the new connection.
	if establishedAt.Add(30 * time.Second).Before(time.Now()) {
		log.Printf("[%v]: old conn over 30 sec old, new wins", conn.hostname)
		contact.conn.closeConn()
		contact.conn = conn
		return
	}

	// Tiebreak with strcmp based on digetests.
	preferOutbound := conn.hostname < conn.endpoint.hostname
	if !contact.conn.isServer && preferOutbound {
		log.Printf("[%v]: old connection won tiebreak", conn.hostname)
		conn.closeConn()
	} else {
		log.Printf("[%v]: new connection won tiebreak", conn.hostname)
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

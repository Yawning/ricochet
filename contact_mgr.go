// contact_mgr.go - Ricochet contact/connection manager.
//
// To the extent possible under law, Yawning Angel waived all copyright
// and related or neighboring rights to ricochet (library), using the Creative
// Commons "CC0" public domain dedication. See LICENSE or
// <http://creativecommons.org/publicdomain/zero/1.0/> for full details.

package ricochet

import (
	"log"
	"sync"
	"time"
)

const (
	contactDispatchInterval = 15 * time.Second
)

type contactMgr struct {
	sync.Mutex

	endpoint *Endpoint

	knownContacts   map[string]*ricochetContact
	pendingContacts map[string]*ricochetContact
	//unknownContacts map[string]*ricochetContact
}

type ricochetContact struct {
	incomingConn *ricochetConn
	outgoingConn *ricochetConn
}

func (m *contactMgr) outgoingConnectionWorker() {
	for {
		m.Lock()
		log.Printf("contacts: dispatching outgoing connection attempts")

		var err error
		for id, contact := range m.knownContacts {
			if contact.outgoingConn != nil {
				continue
			}
			contact.outgoingConn, err = m.endpoint.dialClient(id)
			if err != nil {
				log.Printf("contacts: failed to dial '%v': %v", id, err)
			}
		}
		for id, contact := range m.pendingContacts {
			if contact.outgoingConn != nil {
				continue
			}
			contact.outgoingConn, err = m.endpoint.dialClient(id)
			if err != nil {
				log.Printf("contacts: failed to dial '%v': %v", id, err)
			}
		}

		m.Unlock()
		time.Sleep(contactDispatchInterval)
	}
}

func (m *contactMgr) onIncomingConnection(conn *ricochetConn) (known bool, err error) {
	m.Lock()
	defer m.Unlock()

	// The spec is unclear about what to do when there is more than one
	// connection to a given peer.  Assume that the newest one always
	// takes priority.

	if contact := m.knownContacts[conn.hostname]; contact != nil {
		hadConn := false
		if contact.outgoingConn != nil {
			hadConn = true
			contact.outgoingConn.conn.Close()
			contact.outgoingConn = nil
		}
		if contact.incomingConn != nil {
			hadConn = true
			contact.incomingConn.conn.Close()
		}
		contact.incomingConn = conn
		if !hadConn {
			// XXX: Notify caller that a given contact is online.
			log.Printf("contacts: '%v' is now online", conn.hostname)
		}
		return true, nil
	}

	if contact := m.pendingContacts[conn.hostname]; contact != nil {
		// XXX: The peer just connected back to us, when we were pending
		// authorization.  Should this be counted as accepted or what?
	}

	return false, nil
}

func (m *contactMgr) onOutgoingConnectionAuthed(conn *ricochetConn) {
	m.Lock()
	defer m.Unlock()

	isKnown := conn.getControlChan().isKnownToPeer
	if !isKnown {
		// We know about the peer, but they no longer do, they must have
		// removed us from their contact list.
		if contact := m.knownContacts[conn.hostname]; contact != nil {
			log.Printf("contacts: '%v' removed us from their contact list", conn.hostname)

			delete(m.knownContacts, conn.hostname)
			if contact.incomingConn != nil {
				contact.incomingConn.conn.Close()
			}

			// Close the connection, since the peer doesn't know about us
			// anymore.  The caller can choose to re-add the same host again
			// later.
			contact.outgoingConn.conn.Close()

			// XXX: Notify caller that a given contact has removed us from the
			// contact list.

			return
		}

		// This should be a pending contact, since the peer doesn't know about
		// us and we're connected to them.
		contact := m.pendingContacts[conn.hostname]
		if contact == nil {
			// XXX: WTF, we connected to a contact we are not interested in
			// at all.
			conn.conn.Close()
			return
		}
		if contact.incomingConn != nil {
			contact.incomingConn.conn.Close()
			contact.incomingConn = nil
		}

		// XXX: HACK HACK HACK, use the user-provided data.
		req := &ContactRequest{
			MyNickname: "TestClientPlsIgnore",
			Message:    "Testing contact request...",
		}
		err := newClientContactReqChan(conn, req)
		if err != nil {
			conn.conn.Close()
		}
		return
	}

	_ = isKnown
}

func (m *contactMgr) onOutgoingConnectionClosed(conn *ricochetConn) {
	m.Lock()
	defer m.Unlock()

	if contact := m.knownContacts[conn.hostname]; contact != nil {
		if contact.outgoingConn == conn {
			contact.outgoingConn = nil
		}
	}
	if contact := m.pendingContacts[conn.hostname]; contact != nil {
		if contact.outgoingConn == conn {
			contact.outgoingConn = nil
		}
	}
}

func newContactMgr(e *Endpoint, knownContacts []string) *contactMgr {
	m := new(contactMgr)
	m.endpoint = e
	m.knownContacts = make(map[string]*ricochetContact)
	m.pendingContacts = make(map[string]*ricochetContact)
	// m.unknownContacts = make(map[string]*ricochetContact)

	for _, id := range knownContacts {
		m.knownContacts[id] = new(ricochetContact)
	}

	go m.outgoingConnectionWorker()

	return m
}

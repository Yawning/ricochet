// control.go - Ricochet control channel implementation.
//
// To the extent possible under law, Yawning Angel waived all copyright
// and related or neighboring rights to ricochet (library), using the Creative
// Commons "CC0" public domain dedication. See LICENSE or
// <http://creativecommons.org/publicdomain/zero/1.0/> for full details.

package ricochet

import (
	"fmt"
	"io"
	"math"
	"time"

	"log"

	"github.com/golang/protobuf/proto"
	"github.com/yawning/ricochet/packet"
)

const (
	invalidChanID = -1
	controlChanID = 0

	keepAliveMinInterval = 30 * time.Second
)

type chanState int

const (
	chanStateOpening = iota
	chanStateOpen
	chanStateDone
)

type controlChan struct {
	conn *ricochetConn

	lastKeepAliveResp time.Time

	isAuthenticated      bool
	isKnownToPeer        bool
	sentEnableFeatures   bool
	keepAliveOutstanding bool

	authChan         int
	contactReqChan   int
	incomingChatChan int
}

func (conn *ricochetConn) getControlChan() *controlChan {
	ch := conn.chanMap[controlChanID]
	return ch.(*controlChan)
}

func (conn *ricochetConn) getContactRequestChan() *contactReqChan {
	conn.Lock()
	defer conn.Unlock()

	ctrl := conn.getControlChan()
	if ctrl.contactReqChan != invalidChanID {
		ch := conn.chanMap[(uint16)(ctrl.contactReqChan)]
		return ch.(*contactReqChan)
	}
	return nil
}

func (ch *controlChan) onOpenChannel() error {
	panic("onOpenChannel() called for control channel")
}

func (ch *controlChan) onChannelResult(msg *packet.ChannelResult) error {
	panic("onChannelResult() called for control channel")
}

func (ch *controlChan) onPacket(rawPkt []byte) (err error) {
	var ctrlPkt packet.ControlPacket
	if err = proto.Unmarshal(rawPkt, &ctrlPkt); err != nil {
		return
	}
	if err = ch.validatePacket(&ctrlPkt); err != nil {
		return fmt.Errorf("ctrlChan: %v", err)
	}

	if msg := ctrlPkt.GetOpenChannel(); msg != nil {
		err = ch.onOpenChannelMsg(msg)
	} else if msg := ctrlPkt.GetChannelResult(); msg != nil {
		err = ch.onChannelResultMsg(msg)
	} else if msg := ctrlPkt.GetKeepAlive(); msg != nil {
		err = ch.onKeepAlive(msg)
	} else if msg := ctrlPkt.GetEnableFeatures(); msg != nil {
		err = ch.onEnableFeatures(msg)
	} else if msg := ctrlPkt.GetFeaturesEnabled(); msg != nil {
		err = ch.onFeaturesEnabled(msg)
	} else {
		// This should *NEVER* happen since the validation ensures that at
		// least one of the fields is set.
		return fmt.Errorf("BUG: unhandled ctrl channel packet")
	}
	return
}

func (ch *controlChan) onClose() error {
	// Closing the control channel tears down the connection.
	return io.EOF
}

func (ch *controlChan) onOpenChannelMsg(msg *packet.OpenChannel) error {
	chanType := msg.GetChannelType()
	rawChanID := msg.GetChannelIdentifier()
	if rawChanID <= 0 || rawChanID >= math.MaxUint16 {
		return fmt.Errorf("attempted to open invalid channel ID: %v", rawChanID)
	}
	chanID := (uint16)(rawChanID) // So fucking stupid.
	if ch.conn.isServer && (chanID&1 == 0) {
		return fmt.Errorf("client attempted to open even channel ID: %v", chanID)
	}
	if !ch.conn.isServer && (chanID&1 == 1) {
		return fmt.Errorf("server attempted to open odd channel ID: %v", chanID)
	}
	if ch.conn.chanMap[chanID] != nil {
		return fmt.Errorf("attempted to open duplicate channel ID: %v", chanID)
	}

	log.Printf("chan open attempt: %v (%d)", chanType, chanID)

	var newCh ricochetChan
	var err error
	switch chanType {
	case authHiddenServiceChannelType:
		if !ch.conn.isServer {
			return fmt.Errorf("attempted to open auth channel to client")
		}
		if ch.isAuthenticated {
			return fmt.Errorf("attempted to open auth channel when authed")
		}
		if ch.authChan != invalidChanID {
			return fmt.Errorf("attempted to open auth channel when one exists")
		}
		if newCh, err = newServerAuthHSChan(ch.conn, msg); err != nil {
			return err
		}
		ch.authChan = (int)(chanID)
	case contactReqChannelType:
		if !ch.conn.isServer {
			return fmt.Errorf("attempted to open contact req channel to client")
		}
		if !ch.isAuthenticated {
			return fmt.Errorf("attempted to open contact req channel pre-auth")
		}
		if ch.contactReqChan != invalidChanID {
			return fmt.Errorf("attempted to open contact req channel when one exists")
		}
		if newCh, err = newServerContactReqChan(ch.conn, msg); err != nil {
			return err
		}
		ch.contactReqChan = (int)(chanID)
	case chatChannelType:
		if !ch.isAuthenticated {
			return fmt.Errorf("attempted to open chat channel pre-auth")
		}
		if ch.incomingChatChan != invalidChanID {
			return fmt.Errorf("attempted to open chat channel when one exists")
		}
		if newCh, err = newServerChatChan(ch.conn, msg); err != nil {
			return err
		}
		ch.incomingChatChan = (int)(chanID)
	default:
		return fmt.Errorf("attempted to open unknown channel type")
	}

	// Send the response and add the channel to the global channel map.
	//
	// Note: The code will opt to tear down the connection instead of sending
	// any sort of failure response.  Rather rude, but that's arguably correct
	// behavior for most responses anyway.
	if newCh != nil && err == nil {
		if err = newCh.onOpenChannel(); err != nil {
			return err
		}

		ch.conn.Lock()
		defer ch.conn.Unlock()
		ch.conn.chanMap[chanID] = newCh
	}
	return err
}

func (ch *controlChan) onChannelResultMsg(msg *packet.ChannelResult) error {
	rawChanID := msg.GetChannelIdentifier()
	if rawChanID <= 0 || rawChanID >= math.MaxUint16 {
		return fmt.Errorf("peer opened invalid channel ID: %v", rawChanID)
	}
	chanID := (uint16)(rawChanID) // So fucking stupid.
	if ch.conn.isServer && (chanID&1 == 1) {
		return fmt.Errorf("client opened odd channel ID: %v", chanID)
	}
	if !ch.conn.isServer && (chanID&1 == 0) {
		return fmt.Errorf("server opened even channel ID: %v", chanID)
	}
	openedChan := ch.conn.chanMap[chanID]
	if openedChan == nil {
		return fmt.Errorf("peer open unknown channel ID: %v", chanID)
	}
	if !msg.GetOpened() {
		return openedChan.onClose()
	}
	return openedChan.onChannelResult(msg)
}

func (ch *controlChan) onKeepAlive(msg *packet.KeepAlive) error {
	if !ch.isAuthenticated {
		return fmt.Errorf("received KeepAlive pre-auth")
	}
	if !msg.GetResponseRequested() {
		// Handle the response to our(?) KeepAlive.
		if !ch.keepAliveOutstanding {
			return fmt.Errorf("received spurious KeepAlive response")
		}
		ch.keepAliveOutstanding = false
		// TODO: push back the idle timer or something?
		return nil
	}

	// Send a response to a peer's KeepAlive.
	now := time.Now()
	if now.Add(-keepAliveMinInterval).After(ch.lastKeepAliveResp) {
		ch.lastKeepAliveResp = now
		return ch.sendKeepAlive(false)
	}
	return nil
}

func (ch *controlChan) onEnableFeatures(msg *packet.EnableFeatures) error {
	// There is only one logical place in a connection's lifespan for this to
	// be exchanged (pre-authentication).  Don't enforce that yet, since
	// there are no widely supported extensions, but do enforce "once and only
	// once" as far as responses go.
	if ch.sentEnableFeatures {
		return fmt.Errorf("received duplicate(?) EnableFeatures")
	}
	ch.sentEnableFeatures = true
	return ch.sendEnableFeatures(nil)
}

func (ch *controlChan) onFeaturesEnabled(msg *packet.FeaturesEnabled) error {
	// TODO: Actually parse the response when this implementation sends
	// EnableFeature requests to negotiate extensions.  Till then, no peer
	// should ever send this as a request.
	return fmt.Errorf("peer sent FeaturesEnabled without request")
}

func (ch *controlChan) sendEnableFeatures(features []string) error {
	ctrlPkt := &packet.ControlPacket{
		EnableFeatures: &packet.EnableFeatures{Feature: features},
	}
	rawPkt, err := proto.Marshal(ctrlPkt)
	if err != nil {
		return err
	}
	return ch.conn.sendPacket(controlChanID, rawPkt)
}

func (ch *controlChan) sendKeepAlive(wantResp bool) error {
	ctrlPkt := &packet.ControlPacket{
		KeepAlive: &packet.KeepAlive{ResponseRequested: proto.Bool(wantResp)},
	}
	if wantResp {
		ch.keepAliveOutstanding = true
	}
	rawPkt, err := proto.Marshal(ctrlPkt)
	if err != nil {
		return err
	}
	return ch.conn.sendPacket(controlChanID, rawPkt)
}

func (ch *controlChan) validatePacket(pkt *packet.ControlPacket) error {
	nSet := 0
	if msg := pkt.GetOpenChannel(); msg != nil {
		nSet++
	}
	if msg := pkt.GetChannelResult(); msg != nil {
		nSet++
	}
	if msg := pkt.GetKeepAlive(); msg != nil {
		nSet++
	}
	if msg := pkt.GetEnableFeatures(); msg != nil {
		nSet++
	}
	if msg := pkt.GetFeaturesEnabled(); msg != nil {
		nSet++
	}
	if nSet != 1 {
		return fmt.Errorf("has %d fields set", nSet)
	}
	return nil
}

func newControlChan(conn *ricochetConn, chanID uint16) *controlChan {
	ch := new(controlChan)
	ch.conn = conn
	ch.authChan = invalidChanID
	ch.contactReqChan = invalidChanID
	ch.incomingChatChan = invalidChanID
	return ch
}

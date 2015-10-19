// chat.go - Ricochet chat channel implementation.
//
// To the extent possible under law, Yawning Angel waived all copyright
// and related or neighboring rights to ricochet (library), using the Creative
// Commons "CC0" public domain dedication. See LICENSE or
// <http://creativecommons.org/publicdomain/zero/1.0/> for full details.

package ricochet

import (
	"errors"
	"fmt"
	"log"

	"github.com/golang/protobuf/proto"
	"github.com/yawning/ricochet/packet"
)

const (
	// MessageMaxCharacters is the (currently undocumented) maximum chat
	// message length, painstakingly extracted from protocol/ChatChannel.h.
	MessageMaxCharacters = 2000

	chatChannelType = "im.ricochet.chat"
)

type chatChan struct {
	conn   *ricochetConn
	chanID uint16

	isOutgoing bool
}

// ErrMessageSize is the error returned when a chat message is over the limit.
var ErrMessageSize = errors.New("chat message too large")

func (ch *chatChan) onOpenChannel() error {
	// XXX: Check to see if this is a contact we're willing to accept.
	if !ch.conn.getControlChan().isKnownToPeer {
		// The peer is allowed to open a chat channel instead of making a
		// contact request response to signal acceptance. FML.
	}

	chanResult := &packet.ChannelResult{
		ChannelIdentifier: proto.Int32((int32)(ch.chanID)),
		Opened:            proto.Bool(true),
	}
	ctrlPkt := &packet.ControlPacket{ChannelResult: chanResult}
	rawPkt, err := proto.Marshal(ctrlPkt)
	if err != nil {
		return err
	}
	return ch.conn.sendPacket(controlChanID, rawPkt)
}

func (ch *chatChan) onChannelResult(msg *packet.ChannelResult) error {

	return nil
}

func (ch *chatChan) onPacket(rawPkt []byte) (err error) {
	var chatPkt packet.ChatPacket
	if err = proto.Unmarshal(rawPkt, &chatPkt); err != nil {
		return
	}
	if err = ch.validatePacket(&chatPkt); err != nil {
		return
	}

	if chatMsg := chatPkt.GetChatMessage(); chatMsg != nil {
		accepted := true
		msgText := chatMsg.GetMessageText()
		deltaT := chatMsg.GetTimeDelta()
		msgID := chatMsg.GetMessageId()

		if len(msgText) > MessageMaxCharacters {
			log.Printf("[%v]: Oversized chat message, rejecting")
			accepted = false
		}

		// XXX: Deliver the chat message to the caller.
		if accepted {
			log.Printf("[%v]: %v:%v '%v'", ch.conn.hostname, msgID, deltaT, msgText)
		}

		// Ack the packet.
		if chatMsg.MessageId != nil {
			err = ch.sendChatAck(chatMsg.GetMessageId(), accepted)
		}
	}
	if chatAck := chatPkt.GetChatAcknowledge(); chatAck != nil {
		// XXX: Handle the ACK somehow.
		log.Printf("[%v]: ACK: %d Accepted: %v", ch.conn.hostname, chatAck.GetMessageId(), chatAck.GetAccepted())
	}

	return nil
}

func (ch *chatChan) sendChatAck(msgID uint32, accepted bool) error {
	chatAck := &packet.ChatAcknowledge{
		MessageId: proto.Uint32(msgID),
		Accepted:  proto.Bool(accepted),
	}
	chatPkt := &packet.ChatPacket{ChatAcknowledge: chatAck}
	rawPkt, err := proto.Marshal(chatPkt)
	if err != nil {
		return err
	}
	return ch.conn.sendPacket(ch.chanID, rawPkt)
}

func (ch *chatChan) onClose() error {
	ch.conn.Lock()
	defer ch.conn.Unlock()
	if _, ok := ch.conn.chanMap[ch.chanID]; !ok {
		return fmt.Errorf("received duplicate chat chan close")
	}
	delete(ch.conn.chanMap, ch.chanID)
	if ch.isOutgoing {
		// Whowa, the peer closed our outgoing chat channel on us,
		// how rude.  AFAIK the reference implementation never closes
		// chat channels, and neither does this implementation...
		return fmt.Errorf("peer closed our outgoing chat channel")
	} else {
		// Clear the incoming chat channel ID, the peer can open a new one
		// if they desire.
		ch.conn.getControlChan().incomingChatChan = invalidChanID
	}
	return nil
}

func (ch *chatChan) validatePacket(chatPkt *packet.ChatPacket) error {
	if ch.isOutgoing && chatPkt.GetChatMessage() != nil {
		return fmt.Errorf("received chat message on outgoing channel")
	}
	if !ch.isOutgoing && chatPkt.GetChatAcknowledge() != nil {
		return fmt.Errorf("received chat ack message on inbound channel")
	}
	return nil
}

func newServerChatChan(conn *ricochetConn, msg *packet.OpenChannel) (*chatChan, error) {
	ch := new(chatChan)
	ch.conn = conn
	ch.chanID = (uint16)(msg.GetChannelIdentifier())
	ch.isOutgoing = false

	return ch, nil
}

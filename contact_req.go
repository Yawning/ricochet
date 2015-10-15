// contact_req.go - Ricochet contact request channel implementation.
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
	contactReqChannelType = "im.ricochet.contact.request"

	// Limits from src/protocol/ContactsRequestChannel.proto
	ContactReqMessageMaxCharacters  = 2000
	ContactReqNicknameMaxCharacters = 30
)

type ContactRequest struct {
	MyNickname string
	Message    string
}

var errContactRequestAgain = errors.New("unspecified contact request error")

func (req *ContactRequest) String() string {
	return fmt.Sprintf("'%v':'%v'", req.MyNickname, req.Message)
}

type contactReqChan struct {
	conn   *ricochetConn
	chanID uint16

	isOpen  bool
	isDone  bool
	reqData *ContactRequest
}

func (ch *contactReqChan) onOpenChannel() error {
	// Stop the timer since the peer took sufficient action.
	ch.conn.authTimer.Stop()

	log.Printf("server: ContactRequest from: '%v' (%s)", ch.conn.hostname, ch.reqData)

	resp := &packet.ContactRequestResponse{
		Status: packet.ContactRequestResponse_Pending.Enum(),
	}
	chanResult := &packet.ChannelResult{
		ChannelIdentifier: proto.Int32((int32)(ch.chanID)),
		Opened:            proto.Bool(true),
	}
	if err := proto.SetExtension(chanResult, packet.E_Response, resp); err != nil {
		return err
	}
	ctrlPkt := &packet.ControlPacket{ChannelResult: chanResult}
	rawPkt, err := proto.Marshal(ctrlPkt)
	if err != nil {
		return err
	}
	return ch.conn.sendPacket(controlChanID, rawPkt)
}

func (ch *contactReqChan) onChannelResult(msg *packet.ChannelResult) error {
	if ch.conn.isServer {
		return fmt.Errorf("opened contact req channel to client")
	}
	if ch.isOpen {
		return fmt.Errorf("received spurious ContactRequest ChannelResult")
	}

	ch.isOpen = true
	// If this routine was called, the channel WAS opened, without incident.
	// Extract the response, and take action accordingly.
	ext, err := proto.GetExtension(msg, packet.E_Response)
	if err != nil {
		return err
	}
	resp := ext.(*packet.ContactRequestResponse)
	return ch.onResponse(resp)
}

func (ch *contactReqChan) onPacket(rawPkt []byte) error {
	if ch.conn.isServer {
		return fmt.Errorf("received contact req packet from client")
	}
	if ch.isDone {
		return fmt.Errorf("received contact req packet after completion")
	}

	var resp packet.ContactRequestResponse
	if err := proto.Unmarshal(rawPkt, &resp); err != nil {
		return err
	}
	return ch.onResponse(&resp)
}

func (ch *contactReqChan) onResponse(resp *packet.ContactRequestResponse) error {
	switch resp.GetStatus() {
	case packet.ContactRequestResponse_Pending:
		// Nothing to do for this case, further responses to come.
		log.Printf("client: server '%s' acked pending contact request", ch.conn.hostname)
	case packet.ContactRequestResponse_Accepted:
		// Accepted.
		log.Printf("client: server '%s' accepted contact request", ch.conn.hostname)
		ch.conn.getControlChan().isKnownToPeer = true
		// XXX: Mark peer online.
		// XXX: Close the channel.
		ch.isDone = true
	case packet.ContactRequestResponse_Rejected:
		log.Printf("client: server '%s' rejected contact request", ch.conn.hostname)
		// XXX: Mark peer as rejected.
		return fmt.Errorf("contact request rejected by peer")
	case packet.ContactRequestResponse_Error:
		// XXX: Mark peer as having issues, reschedule connection.
		return errContactRequestAgain
	default:
		return fmt.Errorf("unknown ContactRequest Status")
	}
	return nil
}

func (ch *contactReqChan) onClose() error {
	ch.conn.Lock()
	defer ch.conn.Unlock()
	if _, ok := ch.conn.chanMap[ch.chanID]; !ok {
		return fmt.Errorf("received duplicate contact req chan close")
	}
	delete(ch.conn.chanMap, ch.chanID)
	// Explicitly do not clear controlChan's contactReqChan field, since there
	// is only one ContactRequest channel ever per connection.
	return nil
}

func newServerContactReqChan(conn *ricochetConn, msg *packet.OpenChannel) (*contactReqChan, error) {
	ch := new(contactReqChan)
	ch.conn = conn
	ch.chanID = (uint16)(msg.GetChannelIdentifier())
	ch.reqData = new(ContactRequest)

	ext, err := proto.GetExtension(msg, packet.E_ContactRequest)
	if err != nil {
		return nil, err
	}
	if ext == nil {
		return nil, fmt.Errorf("server: missing ContactRequest extension")
	}
	req := ext.(*packet.ContactRequest)
	ch.reqData.MyNickname = req.GetNickname()
	if len(ch.reqData.MyNickname) > ContactReqNicknameMaxCharacters {
		return nil, fmt.Errorf("server: ContactRequest nickname too long")
	}
	ch.reqData.Message = req.GetMessageText()
	if len(ch.reqData.Message) > ContactReqMessageMaxCharacters {
		return nil, fmt.Errorf("server: ContactRequest message too long")
	}
	return ch, nil
}

func newClientContactReqChan(conn *ricochetConn, reqData *ContactRequest) (err error) {
	ch := new(contactReqChan)
	ch.conn = conn
	ch.chanID, err = conn.allocateNextChanID()
	if err != nil {
		return
	}

	req := &packet.ContactRequest{
		Nickname:    proto.String(reqData.MyNickname),
		MessageText: proto.String(reqData.Message),
	}
	openChan := &packet.OpenChannel{
		ChannelIdentifier: proto.Int32((int32)(ch.chanID)),
		ChannelType:       proto.String(contactReqChannelType),
	}
	if err = proto.SetExtension(openChan, packet.E_ContactRequest, req); err != nil {
		return
	}
	ctrlPkt := &packet.ControlPacket{OpenChannel: openChan}
	rawPkt, err := proto.Marshal(ctrlPkt)
	if err != nil {
		return err
	}
	err = ch.conn.sendPacket(controlChanID, rawPkt)

	conn.Lock()
	defer conn.Unlock()
	conn.chanMap[ch.chanID] = ch
	conn.getControlChan().contactReqChan = (int)(ch.chanID)

	return
}

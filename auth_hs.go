// auth_hs.go - Ricochet Auth Hidden Service implementation.
//
// To the extent possible under law, Yawning Angel waived all copyright
// and related or neighboring rights to ricochet (library), using the Creative
// Commons "CC0" public domain dedication. See LICENSE or
// <http://creativecommons.org/publicdomain/zero/1.0/> for full details.

package ricochet

import (
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"io"

	"log"

	"github.com/golang/protobuf/proto"
	"github.com/yawning/bulb/utils/pkcs1"
	"github.com/yawning/ricochet/packet"
)

const (
	authHiddenServiceChannelType   = "im.ricochet.auth.hidden-service"
	authHiddenServiceCookieSize    = 16
	authHiddenServicePublicKeyBits = PublicKeyBits
)

type authHSChan struct {
	conn   *ricochetConn
	chanID uint16
	state  chanState

	clientCookie []byte
	serverCookie []byte
}

func (ch *authHSChan) onOpenChannel() error {
	ch.state = chanStateOpen
	ch.serverCookie = make([]byte, authHiddenServiceCookieSize)
	if _, err := rand.Read(ch.serverCookie); err != nil {
		return err
	}

	chanResult := &packet.ChannelResult{
		ChannelIdentifier: proto.Int32((int32)(ch.chanID)),
		Opened:            proto.Bool(true),
	}
	if err := proto.SetExtension(chanResult, packet.E_ServerCookie, ch.serverCookie); err != nil {
		return err
	}
	ctrlPkt := &packet.ControlPacket{ChannelResult: chanResult}
	rawPkt, err := proto.Marshal(ctrlPkt)
	if err != nil {
		return err
	}
	return ch.conn.sendPacket(controlChanID, rawPkt)
}

func (ch *authHSChan) onChannelResult(msg *packet.ChannelResult) error {
	if ch.conn.isServer {
		return fmt.Errorf("opened auth channel to client")
	}
	if ch.state != chanStateOpening {
		return fmt.Errorf("received spurious AuthHiddenService ChannelResult")
	}
	ch.state = chanStateOpen

	// If this routine was called, the channel WAS opened, without incident.
	// Extract the server cookie, and send the proof.
	ext, err := proto.GetExtension(msg, packet.E_ServerCookie)
	if err != nil {
		return err
	}
	ch.serverCookie = ext.([]byte)
	if len(ch.serverCookie) != authHiddenServiceCookieSize {
		return fmt.Errorf("invalid AuthHiddenService server_cookie")
	}

	// Encode the public key to DER.
	pkDER, err := pkcs1.EncodePublicKeyDER(&ch.conn.endpoint.privateKey.PublicKey)
	if err != nil {
		return err
	}

	// Calculate the proof.
	proof := ch.calculateProof(ch.conn.endpoint.hostname, ch.conn.hostname)

	// Sign the proof.
	sig, err := rsa.SignPKCS1v15(rand.Reader, ch.conn.endpoint.privateKey, crypto.SHA256, proof)
	if err != nil {
		return err
	}

	return ch.sendProof(pkDER, sig)
}

func (ch *authHSChan) onPacket(rawPkt []byte) error {
	if ch.state != chanStateOpen {
		return fmt.Errorf("received AuthHiddenService packet after auth")
	}
	ch.state = chanStateDone // Only get one packet.

	var authPkt packet.AuthHSPacket
	if err := proto.Unmarshal(rawPkt, &authPkt); err != nil {
		return err
	}
	if err := ch.validatePacket(&authPkt); err != nil {
		return fmt.Errorf("authHSChan: %v", err)
	}

	if ch.conn.isServer {
		return ch.onPacketServer(&authPkt)
	}
	return ch.onPacketClient(&authPkt)
}

func (ch *authHSChan) onPacketClient(authPkt *packet.AuthHSPacket) error {
	resultMsg := authPkt.GetResult()
	if resultMsg == nil {
		return fmt.Errorf("missing result")
	}
	if !resultMsg.GetAccepted() {
		ch.conn.endpoint.onRemoteReject(ch.conn.hostname)
		return fmt.Errorf("client: auth to '%s' rejected", ch.conn.hostname)
	}

	isKnown := resultMsg.GetIsKnownContact()
	log.Printf("client: auth to server '%s' accepted isKnown: %v", ch.conn.hostname, isKnown)

	ch.conn.getControlChan().isAuthenticated = true
	ch.conn.getControlChan().isKnownToPeer = isKnown
	ch.conn.authTimer.Stop() // Stop the fuck().

	// XXX: Send a channel close?  This is something the server ought to be
	// doing, so don't bother for now.  This code will not use this channel
	// past this point, apart from processing the server's close.

	if isKnown {
		ch.conn.endpoint.onConnectionEstablished(ch.conn)
		return nil
	}

	// The peer doesn't immediately recognize us. If this is expected,
	// dispatch a ContactRequest, otherwise, we got removed.
	requestData := ch.conn.endpoint.requestData(ch.conn.hostname)
	if requestData == nil {
		ch.conn.endpoint.onRemoteReject(ch.conn.hostname)
		return fmt.Errorf("client: remote peer remove us from contacts")
	}
	return newClientContactReqChan(ch.conn, requestData)
}

func (ch *authHSChan) onPacketServer(authPkt *packet.AuthHSPacket) error {
	proofMsg := authPkt.GetProof()
	if proofMsg == nil {
		return fmt.Errorf("missing proof")
	}

	// Decode and validate the public key.
	pk, rest, err := pkcs1.DecodePublicKeyDER(proofMsg.GetPublicKey())
	if err != nil {
		return err
	} else if rest != nil && len(rest) > 0 {
		return fmt.Errorf("trailing garbage present after public key")
	} else if pk.N.BitLen() != authHiddenServicePublicKeyBits {
		return fmt.Errorf("invalid public modulus size: %d", pk.N.BitLen())
	}

	// Calculate the client hostname.
	clientHostname, err := pkcs1.OnionAddr(pk)
	if err != nil {
		return err
	}

	sigOk, isKnown := false, false

	// Note: The reference implementation checks against the hostname
	// blacklist for rejected peers, and early rejects clients durring
	// the authentication phase by closing the connection.
	//
	// This is a bit rude.  Check the blacklist and send a rejected
	// response, then close the connection (Done by virtue of returning
	// an error).
	if !ch.conn.endpoint.isBlacklisted(clientHostname) {
		// Calculate the proof.
		proof := ch.calculateProof(clientHostname, ch.conn.endpoint.hostname)

		// Verify proof.
		//
		// The spec neglects to mention PKCS #1 v1.5/SHA256.  Also, not
		// SHA256 suming proof is deliberate because the ricochet code
		// doesn't bother hashing the proof.
		sig := proofMsg.GetSignature()
		err = rsa.VerifyPKCS1v15(pk, crypto.SHA256, proof, sig)
		if err == nil {
			sigOk = true
			ch.conn.getControlChan().isAuthenticated = true
			ch.conn.getControlChan().isKnownToPeer = true
			ch.conn.hostname = clientHostname
			isKnown = ch.conn.endpoint.isKnown(clientHostname)
		}
	} else {
		err = fmt.Errorf("auth from blacklisted peer: '%v'", clientHostname)
	}

	log.Printf("server: auth from client '%s' accepted: %v", clientHostname, sigOk)

	//  Send the result to the client.
	if wrErr := ch.sendResult(sigOk, isKnown); wrErr != nil {
		return wrErr
	}

	if sigOk {
		if isKnown {
			ch.conn.authTimer.Stop()
			ch.conn.endpoint.onConnectionEstablished(ch.conn)
		} else {
			// Give them another interval to request contact.
			ch.conn.authTimer.Reset(authenticationTimeout)
		}
	}

	// Close the authentication channel.
	if wrErr := ch.conn.sendChanClose(ch.chanID); wrErr != nil {
		return wrErr
	}
	return err
}

func (ch *authHSChan) onClose() error {
	ch.conn.Lock()
	defer ch.conn.Unlock()
	if _, ok := ch.conn.chanMap[ch.chanID]; !ok {
		return fmt.Errorf("received duplicate auth chan close")
	}
	delete(ch.conn.chanMap, ch.chanID)
	// Explicitly do not clear controlChan's authChan field, since there is
	// only one auth channel ever per connection.
	if ch.state != chanStateDone {
		// Peer refused to open/closed the channel before completing auth.
		return io.EOF
	}
	return nil
}

func (ch *authHSChan) validatePacket(pkt *packet.AuthHSPacket) error {
	nSet := 0
	if msg := pkt.GetProof(); msg != nil {
		nSet++
		if pkDER := msg.GetPublicKey(); pkDER == nil {
			return fmt.Errorf("missing public_key")
		}
		if sig := msg.GetSignature(); sig == nil {
			return fmt.Errorf("missing signature")
		}
	}
	if msg := pkt.GetResult(); msg != nil {
		nSet++
	}
	if nSet != 1 {
		return fmt.Errorf("has %d fields set", nSet)
	}
	return nil
}

func (ch *authHSChan) sendResult(accepted, isKnown bool) error {
	authResult := &packet.AuthHSResult{Accepted: proto.Bool(accepted)}
	if accepted {
		authResult.IsKnownContact = proto.Bool(isKnown)
	}
	authPkt := &packet.AuthHSPacket{Result: authResult}
	rawPkt, err := proto.Marshal(authPkt)
	if err != nil {
		return err
	}
	return ch.conn.sendPacket(ch.chanID, rawPkt)
}

func (ch *authHSChan) sendProof(pkDER, sig []byte) error {
	authPkt := &packet.AuthHSPacket{
		Proof: &packet.AuthHSProof{
			PublicKey: pkDER,
			Signature: sig,
		},
	}
	rawPkt, err := proto.Marshal(authPkt)
	if err != nil {
		return err
	}
	return ch.conn.sendPacket(ch.chanID, rawPkt)
}

func (ch *authHSChan) calculateProof(clientHostname, serverHostname string) []byte {
	mK := append(ch.clientCookie, ch.serverCookie...)
	mac := hmac.New(sha256.New, mK)
	mac.Write([]byte(clientHostname))
	mac.Write([]byte(serverHostname))
	return mac.Sum(nil)
}

func newServerAuthHSChan(conn *ricochetConn, msg *packet.OpenChannel) (*authHSChan, error) {
	ch := new(authHSChan)
	ch.conn = conn
	ch.chanID = (uint16)(msg.GetChannelIdentifier())

	ext, err := proto.GetExtension(msg, packet.E_ClientCookie)
	if err != nil {
		return nil, err
	}
	ch.clientCookie = ext.([]byte)
	if len(ch.clientCookie) != authHiddenServiceCookieSize {
		return nil, fmt.Errorf("invalid AuthHiddenService client_cookie")
	}
	return ch, nil
}

func newClientAuthHSChan(conn *ricochetConn) (err error) {
	ch := new(authHSChan)
	ch.conn = conn
	ch.chanID, err = conn.allocateNextChanID()
	if err != nil {
		return
	}

	ch.clientCookie = make([]byte, authHiddenServiceCookieSize)
	if _, err = rand.Read(ch.clientCookie); err != nil {
		return err
	}
	openChan := &packet.OpenChannel{
		ChannelIdentifier: proto.Int32((int32)(ch.chanID)),
		ChannelType:       proto.String(authHiddenServiceChannelType),
	}
	if err = proto.SetExtension(openChan, packet.E_ClientCookie, ch.clientCookie); err != nil {
		return
	}
	ctrlPkt := &packet.ControlPacket{OpenChannel: openChan}
	rawPkt, err := proto.Marshal(ctrlPkt)
	if err != nil {
		return err
	}
	err = conn.sendPacket(controlChanID, rawPkt)

	conn.Lock()
	defer conn.Unlock()
	conn.chanMap[ch.chanID] = ch
	conn.getControlChan().authChan = (int)(ch.chanID)

	return
}

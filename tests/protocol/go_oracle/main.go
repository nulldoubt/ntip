// Command noise-oracle emits deterministic NTIP Noise transcripts using the
// independent github.com/flynn/noise implementation. It is a test oracle only.
package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"github.com/flynn/noise"
)

var (
	suite                     = noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashBLAKE2s)
	prologuePrefix            = []byte{'N', 'T', 'I', 'P', 0, 1, 0}
	initiatorTransportPayload = []byte("node-to-master")
	responderTransportPayload = []byte("master-to-node")
)

type transportMessages struct {
	InitiatorToResponder string `json:"initiator_to_responder"`
	ResponderToInitiator string `json:"responder_to_initiator"`
}

type transcript struct {
	Messages  []string          `json:"messages"`
	Hash      string            `json:"hash"`
	Transport transportMessages `json:"transport"`
}

type negativeResults struct {
	XKWrongPSK             bool `json:"xkpsk1_wrong_psk_rejected"`
	XKWrongResponderStatic bool `json:"xkpsk1_wrong_responder_static_rejected"`
	XKAlteredPrologue      bool `json:"xkpsk1_altered_prologue_rejected"`
	IKWrongResponderStatic bool `json:"ik_wrong_responder_static_rejected"`
	IKAlteredPrologue      bool `json:"ik_altered_prologue_rejected"`
}

type output struct {
	Oracle   string          `json:"oracle"`
	XK       transcript      `json:"xkpsk1"`
	IK       transcript      `json:"ik"`
	Negative negativeResults `json:"negative"`
}

func secret(fill byte) []byte {
	key := bytes.Repeat([]byte{fill}, 32)
	key[0]++
	return key
}

func keypair(fill byte) noise.DHKey {
	key, err := noise.DH25519.GenerateKeypair(bytes.NewReader(secret(fill)))
	if err != nil {
		panic(err)
	}
	return key
}

func prologue(fill byte) []byte {
	result := append([]byte{}, prologuePrefix...)
	return append(result, bytes.Repeat([]byte{fill}, 16)...)
}

func state(pattern noise.HandshakePattern, initiator bool, staticFill, ephemeralFill, contextFill byte, peerStatic []byte, psk []byte, placement int) *noise.HandshakeState {
	configuration := noise.Config{
		CipherSuite:           suite,
		Random:                bytes.NewReader(secret(ephemeralFill)),
		Pattern:               pattern,
		Initiator:             initiator,
		Prologue:              prologue(contextFill),
		PresharedKey:          psk,
		PresharedKeyPlacement: placement,
		StaticKeypair:         keypair(staticFill),
		PeerStatic:            peerStatic,
	}
	result, err := noise.NewHandshakeState(configuration)
	if err != nil {
		panic(err)
	}
	return result
}

func write(peer *noise.HandshakeState, payload string) []byte {
	message, _, _, err := peer.WriteMessage(nil, []byte(payload))
	if err != nil {
		panic(err)
	}
	return append([]byte{}, message...)
}

func read(peer *noise.HandshakeState, message []byte, expected string) {
	payload, _, _, err := peer.ReadMessage(nil, message)
	if err != nil {
		panic(err)
	}
	if string(payload) != expected {
		panic(fmt.Sprintf("payload mismatch: got %q, want %q", payload, expected))
	}
}

func readRejected(peer *noise.HandshakeState, message []byte, caseName string) bool {
	if _, _, _, err := peer.ReadMessage(nil, message); err != nil {
		return true
	}
	panic(fmt.Sprintf("%s: altered credentials or transcript were accepted", caseName))
}

func firstTransportMessages(initiatorToResponderEncrypt, initiatorToResponderDecrypt, responderToInitiatorEncrypt, responderToInitiatorDecrypt *noise.CipherState) transportMessages {
	initiatorToResponder, err := initiatorToResponderEncrypt.Encrypt(nil, nil, initiatorTransportPayload)
	if err != nil {
		panic(err)
	}
	plaintext, err := initiatorToResponderDecrypt.Decrypt(nil, nil, initiatorToResponder)
	if err != nil {
		panic(err)
	}
	if !bytes.Equal(plaintext, initiatorTransportPayload) {
		panic(fmt.Sprintf("initiator transport payload mismatch: got %q, want %q", plaintext, initiatorTransportPayload))
	}

	responderToInitiator, err := responderToInitiatorEncrypt.Encrypt(nil, nil, responderTransportPayload)
	if err != nil {
		panic(err)
	}
	plaintext, err = responderToInitiatorDecrypt.Decrypt(nil, nil, responderToInitiator)
	if err != nil {
		panic(err)
	}
	if !bytes.Equal(plaintext, responderTransportPayload) {
		panic(fmt.Sprintf("responder transport payload mismatch: got %q, want %q", plaintext, responderTransportPayload))
	}

	return transportMessages{
		InitiatorToResponder: hex.EncodeToString(initiatorToResponder),
		ResponderToInitiator: hex.EncodeToString(responderToInitiator),
	}
}

func xk() transcript {
	master := keypair(2)
	psk := bytes.Repeat([]byte{5}, 32)
	initiator := state(noise.HandshakeXK, true, 1, 3, 6, master.Public, psk, 1)
	responder := state(noise.HandshakeXK, false, 2, 4, 6, nil, psk, 1)
	m1 := write(initiator, "enroll")
	read(responder, m1, "enroll")
	m2 := write(responder, "accept")
	read(initiator, m2, "accept")
	m3, initiatorCipherOne, initiatorCipherTwo, err := initiator.WriteMessage(nil, []byte("confirm"))
	if err != nil {
		panic(err)
	}
	payload, responderCipherOne, responderCipherTwo, err := responder.ReadMessage(nil, m3)
	if err != nil {
		panic(err)
	}
	if string(payload) != "confirm" {
		panic(fmt.Sprintf("payload mismatch: got %q, want %q", payload, "confirm"))
	}
	if !bytes.Equal(initiator.ChannelBinding(), responder.ChannelBinding()) {
		panic("XK channel bindings disagree")
	}
	return transcript{
		Messages:  []string{hex.EncodeToString(m1), hex.EncodeToString(m2), hex.EncodeToString(m3)},
		Hash:      hex.EncodeToString(initiator.ChannelBinding()),
		Transport: firstTransportMessages(initiatorCipherOne, responderCipherOne, responderCipherTwo, initiatorCipherTwo),
	}
}

func ik() transcript {
	master := keypair(12)
	node := keypair(11)
	initiator := state(noise.HandshakeIK, true, 11, 13, 15, master.Public, nil, 0)
	responder := state(noise.HandshakeIK, false, 12, 14, 15, nil, nil, 0)
	m1 := write(initiator, "reconnect")
	read(responder, m1, "reconnect")
	if !bytes.Equal(responder.PeerStatic(), node.Public) {
		panic("IK responder recovered the wrong Node static key")
	}
	m2, responderCipherOne, responderCipherTwo, err := responder.WriteMessage(nil, []byte("session"))
	if err != nil {
		panic(err)
	}
	payload, initiatorCipherOne, initiatorCipherTwo, err := initiator.ReadMessage(nil, m2)
	if err != nil {
		panic(err)
	}
	if string(payload) != "session" {
		panic(fmt.Sprintf("payload mismatch: got %q, want %q", payload, "session"))
	}
	if !bytes.Equal(initiator.ChannelBinding(), responder.ChannelBinding()) {
		panic("IK channel bindings disagree")
	}
	return transcript{
		Messages:  []string{hex.EncodeToString(m1), hex.EncodeToString(m2)},
		Hash:      hex.EncodeToString(initiator.ChannelBinding()),
		Transport: firstTransportMessages(initiatorCipherOne, responderCipherOne, responderCipherTwo, initiatorCipherTwo),
	}
}

func negativeCases() negativeResults {
	xkPSK := bytes.Repeat([]byte{5}, 32)
	xkInitiator := state(noise.HandshakeXK, true, 1, 3, 6, keypair(2).Public, xkPSK, 1)
	xkWrongPSK := state(noise.HandshakeXK, false, 2, 4, 6, nil, bytes.Repeat([]byte{8}, 32), 1)
	wrongPSKMessage := write(xkInitiator, "enroll")

	xkWrongStaticInitiator := state(noise.HandshakeXK, true, 1, 3, 6, keypair(7).Public, xkPSK, 1)
	xkResponder := state(noise.HandshakeXK, false, 2, 4, 6, nil, xkPSK, 1)
	wrongXKStaticMessage := write(xkWrongStaticInitiator, "enroll")

	xkPrologueInitiator := state(noise.HandshakeXK, true, 1, 3, 6, keypair(2).Public, xkPSK, 1)
	xkAlteredPrologue := state(noise.HandshakeXK, false, 2, 4, 7, nil, xkPSK, 1)
	alteredXKPrologueMessage := write(xkPrologueInitiator, "enroll")

	ikWrongStaticInitiator := state(noise.HandshakeIK, true, 11, 13, 15, keypair(16).Public, nil, 0)
	ikResponder := state(noise.HandshakeIK, false, 12, 14, 15, nil, nil, 0)
	wrongIKStaticMessage := write(ikWrongStaticInitiator, "reconnect")

	ikPrologueInitiator := state(noise.HandshakeIK, true, 11, 13, 15, keypair(12).Public, nil, 0)
	ikAlteredPrologue := state(noise.HandshakeIK, false, 12, 14, 16, nil, nil, 0)
	alteredIKPrologueMessage := write(ikPrologueInitiator, "reconnect")

	return negativeResults{
		XKWrongPSK:             readRejected(xkWrongPSK, wrongPSKMessage, "XKpsk1 wrong PSK"),
		XKWrongResponderStatic: readRejected(xkResponder, wrongXKStaticMessage, "XKpsk1 wrong responder static"),
		XKAlteredPrologue:      readRejected(xkAlteredPrologue, alteredXKPrologueMessage, "XKpsk1 altered prologue"),
		IKWrongResponderStatic: readRejected(ikResponder, wrongIKStaticMessage, "IK wrong responder static"),
		IKAlteredPrologue:      readRejected(ikAlteredPrologue, alteredIKPrologueMessage, "IK altered prologue"),
	}
}

func main() {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(output{
		Oracle:   "github.com/flynn/noise@v1.1.0",
		XK:       xk(),
		IK:       ik(),
		Negative: negativeCases(),
	}); err != nil {
		panic(err)
	}
}

package packets

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
)

type CapabilityFlags uint32

const (
	clientLongPassword CapabilityFlags = 1 << iota
	clientFoundRows
	clientLongFlag
	clientConnectWithDB
	clientNoSchema
	clientCompress
	clientODBC
	clientLocalFiles
	clientIgnoreSpace
	clientProtocol41
	clientInteractive
	clientSSL
	clientIgnoreSIGPIPE
	clientTransactions
	clientReserved
	clientSecureConn
	clientMultiStatements
	clientMultiResults
	clientPSMultiResults
	clientPluginAuth
	clientConnectAttrs
	clientPluginAuthLenEncClientData
	clientCanHandleExpiredPasswords
	clientSessionTrack
	clientDeprecateEOF
)

var flags = map[CapabilityFlags]string{
	clientLongPassword:               "clientLongPassword",
	clientFoundRows:                  "clientFoundRows",
	clientLongFlag:                   "clientLongFlag",
	clientConnectWithDB:              "clientConnectWithDB",
	clientNoSchema:                   "clientNoSchema",
	clientCompress:                   "clientCompress",
	clientODBC:                       "clientODBC",
	clientLocalFiles:                 "clientLocalFiles",
	clientIgnoreSpace:                "clientIgnoreSpace",
	clientProtocol41:                 "clientProtocol41",
	clientInteractive:                "clientInteractive",
	clientSSL:                        "clientSSL",
	clientIgnoreSIGPIPE:              "clientIgnoreSIGPIPE",
	clientTransactions:               "clientTransactions",
	clientReserved:                   "clientReserved",
	clientSecureConn:                 "clientSecureConn",
	clientMultiStatements:            "clientMultiStatements",
	clientMultiResults:               "clientMultiResults",
	clientPSMultiResults:             "clientPSMultiResults",
	clientPluginAuth:                 "clientPluginAuth",
	clientConnectAttrs:               "clientConnectAttrs",
	clientPluginAuthLenEncClientData: "clientPluginAuthLenEncClientData",
	clientCanHandleExpiredPasswords:  "clientCanHandleExpiredPasswords",
	clientSessionTrack:               "clientSessionTrack",
	clientDeprecateEOF:               "clientDeprecateEOF",
}

func (r CapabilityFlags) Has(flag CapabilityFlags) bool {
	return r&flag != 0
}

func (r CapabilityFlags) String() string {
	var names []string

	for i := uint64(1); i <= uint64(1)<<31; i = i << 1 {
		name, ok := flags[CapabilityFlags(i)]
		if ok {
			names = append(names, fmt.Sprintf("0x%08x - %032b - %s", i, i, name))
		}
	}

	return strings.Join(names, "\n")
}

type MySQLHandshakePacket struct {
	header            MySQLPacketHeader
	ProtocolVersion   uint8
	ServerVersion     []byte
	ConnectionId      uint32
	AuthPluginData    []byte
	Filler            byte
	CapabilitiesFlags CapabilityFlags
	CharacterSet      uint8
	StatusFlags       uint16
	AuthPluginDataLen uint8
	AuthPluginName    []byte
}

// Decode decodes the first packet received from the MySQl Server
// It's a handshake packet
func (r *MySQLHandshakePacket) Decode(conn net.Conn) error {
	data := make([]byte, 1024)
	_, err := conn.Read(data)
	if err != nil {
		return err
	}

	header := &MySQLPacketHeader{}
	ln := []byte{data[0], data[1], data[2], 0x00}
	header.length = binary.LittleEndian.Uint32(ln)
	// a single byte integer is the same in BigEndian and LittleEndian
	header.sequence_id = data[3]

	r.header = *header
	/**
	Assign payload only data to new var just  for convenience
	*/
	payload := data[4 : header.length+4]
	position := 0
	/**
	As defined in the documentation, this value is alway 10 (0x00 in hex)
	1	[0a] protocol version
	*/
	r.ProtocolVersion = payload[0]
	if r.ProtocolVersion != 0x0a {
		return errors.New("non supported protocol for the proxy. Only version 10 is supported")
	}

	position += 1

	/**
	Extract server version, by finding the terminal character (0x00) index,
	and extracting the data in between
	string[NUL]    server version
	*/
	index := bytes.IndexByte(payload, byte(0x00))
	r.ServerVersion = payload[position:index]
	position = index + 1

	connectionId := payload[position : position+4]
	id := binary.LittleEndian.Uint32(connectionId)
	r.ConnectionId = id
	position += 4

	/*
		The auth-plugin-data is the concatenation of strings auth-plugin-data-part-1 and auth-plugin-data-part-2.
	*/

	r.AuthPluginData = make([]byte, 8)
	copy(r.AuthPluginData, payload[position:position+8])

	position += 8

	r.Filler = payload[position]
	if r.Filler != 0x00 {
		return errors.New("failed to decode filler value")
	}

	position += 1

	capabilitiesFlags1 := payload[position : position+2]
	position += 2

	r.CharacterSet = payload[position]
	position += 1

	r.StatusFlags = binary.LittleEndian.Uint16(payload[position : position+2])
	position += 2

	capabilityFlags2 := payload[position : position+2]
	position += 2

	/**
	Reconstruct 32 bit integer from two 16 bit integers.
	Take low 2 bytes and high 2 bytes, ans sum it.
	*/
	capLow := binary.LittleEndian.Uint16(capabilitiesFlags1)
	capHi := binary.LittleEndian.Uint16(capabilityFlags2)
	cap := uint32(capLow) | uint32(capHi)<<16

	r.CapabilitiesFlags = CapabilityFlags(cap)

	if r.CapabilitiesFlags&clientPluginAuth != 0 {
		r.AuthPluginDataLen = payload[position]
		if r.AuthPluginDataLen == 0 {
			return errors.New("wrong auth plugin data len")
		}
	}

	/*
		Skip reserved bytes
		string[10]     reserved (all [00])
	*/

	position += 1 + 10

	/**
	This flag tell us that the client should hash the password using algorithm described here:
	https://dev.mysql.com/doc/internals/en/secure-password-authentication.html#packet-Authentication::Native41
	*/
	if r.CapabilitiesFlags&clientSecureConn != 0 {
		/*
			The auth-plugin-data is the concatenation of strings auth-plugin-data-part-1 and auth-plugin-data-part-2.
		*/
		end := position + Max(13, int(r.AuthPluginDataLen)-8)
		r.AuthPluginData = append(r.AuthPluginData, payload[position:end]...)
		position = end
	}

	index = bytes.IndexByte(payload[position:], byte(0x00))

	/*
		Due to Bug#59453 the auth-plugin-name is missing the terminating NUL-char in versions prior to 5.5.10 and 5.6.2.
		We know the length of the payload, so if there is no NUL-char, just read all the data until the end
	*/
	if index != -1 {
		r.AuthPluginName = payload[position : position+index]
	} else {
		r.AuthPluginName = payload[position:]
	}

	return nil
}

// Encode encodes the InitialHandshakePacket to bytes
func (r MySQLHandshakePacket) Encode() ([]byte, error) {
	buf := make([]byte, 0)
	buf = append(buf, r.ProtocolVersion)
	buf = append(buf, r.ServerVersion...)
	buf = append(buf, byte(0x00))

	connectionId := make([]byte, 4)
	binary.LittleEndian.PutUint32(connectionId, r.ConnectionId)
	buf = append(buf, connectionId...)

	//auth1 := make([]byte, 8)
	auth1 := r.AuthPluginData[0:8]
	buf = append(buf, auth1...)
	buf = append(buf, 0x00)

	cap := make([]byte, 4)
	binary.LittleEndian.PutUint32(cap, uint32(r.CapabilitiesFlags))

	cap1 := cap[0:2]
	cap2 := cap[2:]

	buf = append(buf, cap1...)
	buf = append(buf, r.CharacterSet)

	statusFlag := make([]byte, 2)
	binary.LittleEndian.PutUint16(statusFlag, r.StatusFlags)
	buf = append(buf, statusFlag...)
	buf = append(buf, cap2...)
	buf = append(buf, r.AuthPluginDataLen)

	reserved := make([]byte, 10)
	buf = append(buf, reserved...)
	buf = append(buf, r.AuthPluginData[8:]...)
	buf = append(buf, r.AuthPluginName...)
	buf = append(buf, 0x00)

	h := MySQLPacketHeader{
		length:      uint32(len(buf)),
		sequence_id: r.header.sequence_id,
	}

	newBuf := make([]byte, 0, h.length+4)

	ln := make([]byte, 4)
	binary.LittleEndian.PutUint32(ln, h.length)

	newBuf = append(newBuf, ln[:3]...)
	newBuf = append(newBuf, h.sequence_id)
	newBuf = append(newBuf, buf...)

	return newBuf, nil
}

func Max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func (r MySQLHandshakePacket) String() string {
	return "Handshake pkt"
}

type MySQLAuthPacket struct {
	header          MySQLPacketHeader
	CapabilityFlags CapabilityFlags
	CharacterSet    byte
	MaxPacketSize   uint32
	Reserved        []byte
	Username        string
	AuthRespLength  byte
	AuthResp        []byte
	Database        string
	AuthPluginName  string
	ConnectAttrs    []byte
}

func (r *MySQLAuthPacket) Decode(conn net.Conn) error {
	data := make([]byte, 1024)
	_, err := conn.Read(data)
	if err != nil {
		return err
	}

	header := &MySQLPacketHeader{}
	ln := []byte{data[0], data[1], data[2], 0x00}
	header.length = binary.LittleEndian.Uint32(ln)
	// a single byte integer is the same in BigEndian and LittleEndian
	header.sequence_id = data[3]

	r.header = *header

	payload := data[4 : header.length+4]
	position := 0

	cap := binary.LittleEndian.Uint32(payload[position : position+4])
	position += 4

	r.CapabilityFlags = CapabilityFlags(cap)
	//fmt.Printf("CapabilityFlags: %s\n", r.CapabilityFlags.String())

	r.MaxPacketSize = binary.LittleEndian.Uint32(payload[position : position+4])
	position += 4

	r.CharacterSet = payload[position]
	position++

	r.Reserved = payload[position : position+23]
	position += 23

	index := bytes.IndexByte(payload[position:], byte(0x00))
	r.Username = string(payload[position : position+index])
	fmt.Printf("Username: %s\n", r.Username)
	position += index + 1

	if r.CapabilityFlags&clientPluginAuthLenEncClientData != 0 {
		length := int(payload[position])
		position++
		r.AuthResp = payload[position : position+length]
		position += length
	} else if r.CapabilityFlags&clientSecureConn != 0 {
		length := int(payload[position])
		position++
		r.AuthResp = payload[position : position+length]
		position += length
	} else {
		index := bytes.IndexByte(payload[position:], byte(0x00))
		r.AuthResp = payload[position : position+index]
		position += index + 1
	}

	if r.CapabilityFlags&clientConnectWithDB != 0 {
		index := bytes.IndexByte(payload[position:], byte(0x00))
		r.Database = string(payload[position : position+index])
		fmt.Printf("Database: %s\n", r.Database)
		position += index + 1
	}

	if r.CapabilityFlags&clientPluginAuth != 0 {
		index := bytes.IndexByte(payload[position:], byte(0x00))
		r.AuthPluginName = string(payload[position : position+index])
		fmt.Printf("AuthPluginName: %s\n", r.AuthPluginName)
		position += index + 1
	}

	if r.CapabilityFlags&clientConnectAttrs != 0 {
		r.ConnectAttrs = payload[position:]
	}

	return nil
}

func (r *MySQLAuthPacket) Encode() ([]byte, error) {
	buf := make([]byte, 0, 1024)

	cap := make([]byte, 4)
	binary.LittleEndian.PutUint32(cap, uint32(r.CapabilityFlags))
	buf = append(buf, cap...)

	max_pkt_size := make([]byte, 4)
	binary.LittleEndian.PutUint32(max_pkt_size, r.MaxPacketSize)
	buf = append(buf, max_pkt_size...)

	cs := make([]byte, 1)
	cs[0] = r.CharacterSet
	buf = append(buf, cs...)

	filler := make([]byte, 23)
	buf = append(buf, filler...)

	username := []byte(r.Username)
	username = append(username, byte(0x00))
	buf = append(buf, username...)

	if r.CapabilityFlags&clientPluginAuthLenEncClientData != 0 {
		auth_resp_len := make([]byte, 1)
		auth_resp_len[0] = byte(len(r.AuthResp))
		buf = append(buf, auth_resp_len...)
		buf = append(buf, r.AuthResp...)
	} else if r.CapabilityFlags&clientSecureConn != 0 {
		auth_resp_len := make([]byte, 1)
		auth_resp_len[0] = byte(len(r.AuthResp))
		buf = append(buf, auth_resp_len...)
		buf = append(buf, r.AuthResp...)
	} else {
		auth_resp := []byte(r.AuthResp)
		auth_resp = append(auth_resp, byte(0x00))
		buf = append(buf, auth_resp...)
	}

	if r.CapabilityFlags&clientConnectWithDB != 0 {
		db := []byte(r.Database)
		db = append(db, byte(0x00))
		buf = append(buf, db...)
	}

	if r.CapabilityFlags&clientPluginAuth != 0 {
		plugin := []byte(r.AuthPluginName)
		plugin = append(plugin, byte(0x00))
		buf = append(buf, plugin...)
	}

	if r.CapabilityFlags&clientConnectAttrs != 0 {
		buf = append(buf, r.ConnectAttrs...)
	}

	h := MySQLPacketHeader{
		length:      uint32(len(buf)),
		sequence_id: r.header.sequence_id,
	}

	new_buf := make([]byte, 0, h.length+4)
	ln := make([]byte, 4)
	binary.LittleEndian.PutUint32(ln, h.length)
	new_buf = append(new_buf, ln[:3]...)
	new_buf = append(new_buf, h.sequence_id)
	new_buf = append(new_buf, buf...)

	return new_buf, nil
}

func (r *MySQLAuthPacket) String() string {
	return fmt.Sprintf("User: %s", r.Username)
}

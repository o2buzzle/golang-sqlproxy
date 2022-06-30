package proxy

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net"
	"o2buzzle/sqlproxy/authn"
	"o2buzzle/sqlproxy/packets"
)

func NewConnection(host string, port string, conn net.Conn, id uint64, proxy_uname, proxy_pass string) *Connection {
	return &Connection{
		host:        host,
		port:        port,
		conn:        conn,
		id:          id,
		proxy_uname: proxy_uname,
		proxy_pass:  proxy_pass,
	}
}

type Connection struct {
	id          uint64
	conn        net.Conn
	host        string
	port        string
	proxy_uname string
	proxy_pass  string
}

const MAX_PACKET_LENGTH = 16 * 1024 * 1024

func (r *Connection) Handle() error {
	address := fmt.Sprintf("%s%s", r.host, r.port)
	mysql, err := net.Dial("tcp", address)
	if err != nil {
		log.Printf("Failed to connection to MySQL: [%d] %s", r.id, err.Error())
		return err
	}
	handshake_pkt := &packets.MySQLHandshakePacket{}
	err = handshake_pkt.Decode(mysql)
	if err != nil {
		log.Printf("Failed to decode handshake packet: [%d] %s", r.id, err.Error())
		return err
	}
	//log.Printf("Handshake packet: [%d] %s", r.id, handshake_pkt.String())
	//fmt.Printf("Authentication Data: %s\n", handshake_pkt.AuthPluginData)
	auth_random := handshake_pkt.AuthPluginData

	enc, err := handshake_pkt.Encode()
	if err != nil {
		log.Printf("Failed to encode handshake packet: [%d] %s", r.id, err.Error())
		return err
	}
	_, err = r.conn.Write(enc)

	if err != nil {
		log.Printf("Failed to write handshake packet: [%d] %s", r.id, err.Error())
		return err
	}

	handshake_auth_pkt := &packets.MySQLAuthPacket{}
	err = handshake_auth_pkt.Decode(r.conn)
	if err != nil {
		log.Printf("Failed to decode handshake auth packet: [%d] %s", r.id, err.Error())
		return err
	}
	//log.Printf("Handshake auth packet: [%d] %s", r.id, handshake_auth_pkt.String())

	proxy_user := handshake_auth_pkt.Username
	//fmt.Printf("Authentication Response (hex): %x\n", handshake_auth_pkt.AuthResp)

	// Verify it on our own, then replace with what the proxy will use
	user_password, err := authn.ReadProxyPassword("proxyauthn.json", proxy_user)
	if err != nil {
		log.Printf("Failed to read proxy password: [%d] %s", r.id, err.Error())
		return err
	}
	fmt.Printf("Proxy Password: %s\n", user_password)
	if user_password == "" {
		log.Printf("Failed to find user password for %s", proxy_user)
		return fmt.Errorf("Failed to find user password for %s", proxy_user)
	}

	hashed_pw := authn.HashNativePassword(user_password, auth_random)
	//fmt.Printf("Hashed Password: %x\n", hashed_pw)
	//fmt.Printf("Handshake auth packet: %x\n", handshake_auth_pkt.AuthResp)

	res := bytes.Compare(hashed_pw, handshake_auth_pkt.AuthResp)
	if res != 0 {
		log.Printf("Failed to verify proxy password for %s", proxy_user)
		return fmt.Errorf("Failed to verify proxy password for %s", proxy_user)
	}

	// Replace the auth response with the one that the proxy will use

	handshake_auth_pkt.Username = r.proxy_uname
	handshake_auth_pkt.AuthResp = authn.HashNativePassword(r.proxy_pass, auth_random)

	enc, err = handshake_auth_pkt.Encode()
	if err != nil {
		log.Printf("Failed to encode handshake auth packet: [%d] %s", r.id, err.Error())
		return err
	}

	_, err = mysql.Write(enc)

	go func() {
		buf := make([]byte, MAX_PACKET_LENGTH)
		for {
			n, err := mysql.Read(buf)
			if err != nil {
				if err == io.EOF {
					log.Printf("MySQL connection closed: [%d] %s", r.id, err.Error())
					return
				}
				log.Printf("Error reading from MySQL: [%d] %s", r.id, err.Error())
				return
			}
			log.Default().Printf("MySQL --> %s:\n", proxy_user)
			// packets.DecodePackets(buf[:n], false)
			r.conn.Write(buf[:n])
		}
	}()

	go func() {
		buf := make([]byte, MAX_PACKET_LENGTH)
		for {
			n, err := r.conn.Read(buf)
			if err != nil {
				if err == io.EOF {
					log.Printf("Proxy connection closed: [%d] %s", r.id, err.Error())
					return
				}
				log.Printf("Error reading from Proxy: [%d] %s", r.id, err.Error())
				return
			}
			log.Default().Printf("%s --> MySQL:\n", proxy_user)
			// packets.DecodePackets(buf[:n], true)
			new_buf, err := packets.InjectUser(buf[:n], true, proxy_user)
			if err != nil {
				log.Printf("Failed to inject user: [%d] %s", r.id, err.Error())
				return
			}
			mysql.Write(new_buf)
		}
	}()

	if err != nil {
		log.Printf("Connection error: [%d] %s", r.id, err.Error())
		return err
	}

	log.Printf("Connection closed.")
	return nil
}

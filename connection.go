package main

import (
	"fmt"
	"io"
	"log"
	"net"
)

func NewConnection(host string, port string, conn net.Conn, id uint64) *Connection {
	return &Connection{
		host: host,
		port: port,
		conn: conn,
		id:   id,
	}
}

type Connection struct {
	id   uint64
	conn net.Conn
	host string
	port string
}

const MAX_PACKET_LENGTH = 16 * 1024 * 1024

func (r *Connection) Handle() error {
	address := fmt.Sprintf("%s%s", r.host, r.port)
	mysql, err := net.Dial("tcp", address)
	if err != nil {
		log.Printf("Failed to connection to MySQL: [%d] %s", r.id, err.Error())
		return err
	}
	handshake_pkt := &mysql_handshake_packet{}
	err = handshake_pkt.Decode(mysql)
	if err != nil {
		log.Printf("Failed to decode handshake packet: [%d] %s", r.id, err.Error())
		return err
	}
	log.Printf("Handshake packet: [%d] %s", r.id, handshake_pkt.String())
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

	handshake_auth_pkt := &mysql_auth_packet{}
	err = handshake_auth_pkt.Decode(r.conn)
	if err != nil {
		log.Printf("Failed to decode handshake auth packet: [%d] %s", r.id, err.Error())
		return err
	}
	log.Printf("Handshake auth packet: [%d] %s", r.id, handshake_auth_pkt.String())

	proxy_user := handshake_auth_pkt.Username

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
			decode_packets(buf[:n])
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
			decode_packets(buf[:n])
			mysql.Write(buf[:n])
		}
	}()

	if err != nil {
		log.Printf("Connection error: [%d] %s", r.id, err.Error())
		return err
	}

	log.Printf("Connection closed.")
	return nil
}

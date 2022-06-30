package main

import (
	"encoding/binary"
	"fmt"
)

func decode_packets(packets []byte) {
	packet_seq := []mysql_generic_packet{}
	for i := 0; i < len(packets); {
		header := mysql_packet_header{}
		header.length = binary.LittleEndian.Uint32([]byte{packets[i], packets[i+1], packets[i+2], 0})
		header.sequence_id = packets[i+3]

		packet := mysql_generic_packet{}
		packet.header = header
		packet.data = packets[i+4 : i+4+int(header.length)]

		packet_seq = append(packet_seq, packet)
		i += 4 + int(header.length)
	}
	for _, packet := range packet_seq {
		fmt.Println(packet.string())
	}
}

package packets

import (
	"encoding/binary"
	"fmt"
)

type MySQLPacketHeader struct {
	length      uint32 // 3 bytes
	sequence_id uint8  // 1 byte
}

type MySQLGenericPacket struct {
	header MySQLPacketHeader
	data   []byte
}

func (r *MySQLGenericPacket) dumpBytes() string {
	return string(r.data)
}

func (r *MySQLGenericPacket) Encode() ([]byte, error) {
	ln := []byte{}
	ln = append(ln, r.header.Encode()...)
	return append(ln, r.data...), nil
}

func (r *MySQLGenericPacket) String() string {
	ret := ""
	ret += fmt.Sprintf("length: %d\n", r.header.length)
	ret += fmt.Sprintf("sequence_id: %d\n", r.header.sequence_id)
	//ret += fmt.Sprintf("raw data: %v\n", r.data)
	ret += fmt.Sprintf("data: %s\n", r.dumpBytes())
	return ret
}

func (r *MySQLPacketHeader) Decode(data []byte) {
	length := binary.LittleEndian.Uint32([]byte{data[0], data[1], data[2], 0})
	sequence_id := data[3]
	r.length = length
	r.sequence_id = sequence_id
}

func (r *MySQLPacketHeader) Encode() []byte {
	ln := make([]byte, 4)
	binary.LittleEndian.PutUint32(ln, r.length)
	ln[3] = r.sequence_id
	//fmt.Println(ln)
	return ln
}

func DecodePackets(packets []byte, direction bool) {
	packet_seq := []MySQLGenericPacket{}
	for i := 0; i < len(packets); {
		header := MySQLPacketHeader{}
		header.length = binary.LittleEndian.Uint32([]byte{packets[i], packets[i+1], packets[i+2], 0})
		header.sequence_id = packets[i+3]

		packet := MySQLGenericPacket{}
		packet.header = header
		packet.data = packets[i+4 : i+4+int(header.length)]

		packet_seq = append(packet_seq, packet)
		i += 4 + int(header.length)
	}
	for _, packet := range packet_seq {
		if direction {
			magic := packet.data[0]
			switch magic {
			case byte(PacketComSleep):
				fmt.Printf("PacketComSleep\n")
				fmt.Printf("%s\n", packet.data)
			case byte(PacketComQuit):
				fmt.Printf("PacketComQuit\n")
				fmt.Printf("%s\n", packet.data)
			case byte(PacketComInitDB):
				fmt.Printf("PacketComInitDB\n")
				fmt.Printf("%s\n", packet.data)
			case byte(PacketComQuery):
				query := MySQLCOMQueryPacket{}
				query.Decode(packet)
				fmt.Printf("%s\n", query.sql)
			case byte(PacketComFieldList):
				fmt.Printf("PacketComFieldList\n")
				fmt.Printf("%s\n", packet.data)
			case byte(PacketComCreateDB):
				fmt.Printf("PacketComCreateDB\n")
				fmt.Printf("%s\n", packet.data)
			case byte(PacketComDropDB):
				fmt.Printf("PacketComDropDB\n")
				fmt.Printf("%s\n", packet.data)
			case byte(PacketComRefresh):
				fmt.Printf("PacketComRefresh\n")
				fmt.Printf("%s\n", packet.data)
			case byte(PacketComShutdown):
				fmt.Printf("PacketComShutdown\n")
				fmt.Printf("%s\n", packet.data)
			case byte(PacketComStatistics):
				fmt.Printf("PacketComStatistics\n")
				fmt.Printf("%s\n", packet.data)
			case byte(PacketComProcessInfo):
				fmt.Printf("PacketComProcessInfo\n")
				fmt.Printf("%s\n", packet.data)
			case byte(PacketComConnect):
				fmt.Printf("PacketComConnect\n")
				fmt.Printf("%s\n", packet.data)
			case byte(PacketComProcessKill):
				fmt.Printf("PacketComProcessKill\n")
				fmt.Printf("%s\n", packet.data)
			case byte(PacketComDebug):
				fmt.Printf("PacketComDebug\n")
				fmt.Printf("%s\n", packet.data)
			case byte(PacketComPing):
				fmt.Printf("PacketComPing\n")
				fmt.Printf("%s\n", packet.data)
			case byte(PacketComTime):
				fmt.Printf("PacketComTime\n")
				fmt.Printf("%s\n", packet.data)
			case byte(PacketComDelayedInsert):
				fmt.Printf("PacketComDelayedInsert\n")
				fmt.Printf("%s\n", packet.data)
			case byte(PacketComChangeUser):
				fmt.Printf("PacketComChangeUser\n")
				fmt.Printf("%s\n", packet.data)
			case byte(PacketResetConnection):
				fmt.Printf("PacketResetConnection\n")
				fmt.Printf("%s\n", packet.data)
			case byte(PacketComDaemon):
				fmt.Printf("PacketComDaemon\n")
				fmt.Printf("%s\n", packet.data)
			default:
				fmt.Printf("Unknown packet: %x\n", magic)
				fmt.Println(packet)
			}
		} else {
			//fmt.Println(packet)
		}

	}
}

func InjectUser(packets []byte, direction bool, username string) ([]byte, error) {
	packet_seq := []MySQLGenericPacket{}
	for i := 0; i < len(packets); {
		header := MySQLPacketHeader{}
		header.length = binary.LittleEndian.Uint32([]byte{packets[i], packets[i+1], packets[i+2], 0})
		header.sequence_id = packets[i+3]

		packet := MySQLGenericPacket{}
		packet.header = header
		packet.data = packets[i+4 : i+4+int(header.length)]

		packet_seq = append(packet_seq, packet)
		i += 4 + int(header.length)
	}
	ret := []byte{}
	for _, packet := range packet_seq {
		if direction {
			magic := packet.data[0]
			switch magic {
			case byte(PacketComSleep):

			case byte(PacketComQuit):

			case byte(PacketComInitDB):

			case byte(PacketComQuery):
				query := MySQLCOMQueryPacket{}
				query.Decode(packet)
				query.InjectUserName(username)
				packet.header = query.header
				data, err := query.EncodeData()
				if err != nil {
					return nil, err
				}
				packet.data = data

			case byte(PacketComFieldList):

			case byte(PacketComCreateDB):

			case byte(PacketComDropDB):

			case byte(PacketComRefresh):

			case byte(PacketComShutdown):

			case byte(PacketComStatistics):

			case byte(PacketComProcessInfo):

			case byte(PacketComConnect):

			case byte(PacketComProcessKill):

			case byte(PacketComDebug):

			case byte(PacketComPing):

			case byte(PacketComTime):

			case byte(PacketComDelayedInsert):

			case byte(PacketComChangeUser):

			case byte(PacketResetConnection):

			case byte(PacketComDaemon):

			default:

			}
		} else {
			//fmt.Println(packet)
		}
		data, err := packet.Encode()
		if err != nil {
			return nil, err
		}
		//fmt.Println(data)
		ret = append(ret, data...)
	}
	return ret, nil
}

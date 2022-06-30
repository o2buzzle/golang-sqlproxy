package packets

type MySQLCOMQueryPacket struct {
	header MySQLPacketHeader
	magic  uint8
	sql    string
}

func (r *MySQLCOMQueryPacket) Decode(pkt MySQLGenericPacket) error {
	r.header = pkt.header
	r.magic = pkt.data[0]
	r.sql = string(pkt.data[1:])

	return nil
}

func (r *MySQLCOMQueryPacket) EncodeData() ([]byte, error) {
	buf := make([]byte, len(r.sql)+1)
	buf[0] = r.magic
	copy(buf[1:], []byte(r.sql))
	return buf, nil
}

func (r *MySQLCOMQueryPacket) InjectUserName(user string) {
	r.sql += " /* user: " + user + " */"
	// Update header
	r.header.length = uint32(len(r.sql) + 1)
}

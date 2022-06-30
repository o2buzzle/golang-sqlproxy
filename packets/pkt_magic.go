package packets

type PacketMagic uint8

const (
	PacketComSleep PacketMagic = iota
	PacketComQuit
	PacketComInitDB
	PacketComQuery
	PacketComFieldList
	PacketComCreateDB
	PacketComDropDB
	PacketComRefresh
	PacketComShutdown
	PacketComStatistics
	PacketComProcessInfo
	PacketComConnect
	PacketComProcessKill
	PacketComDebug
	PacketComPing
	PacketComTime
	PacketComDelayedInsert
	PacketComChangeUser
	PacketResetConnection
	PacketComDaemon
)

const MAX_PACKET_LENGTH = 16 * 1024 * 1024

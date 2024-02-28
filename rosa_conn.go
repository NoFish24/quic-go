package quic

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync"
)

func byteArrayToInt(byteSlice []byte) uint32 {
	return binary.BigEndian.Uint32(byteSlice[:4])
}

type ROSAConn struct {
	sourceIP, destIP, ingressIP, egressIP       net.IP
	sourcePort, destPort                        int
	keyid, sourceConnectionID, destConnectionID []byte
	siteRequest                                 string
	responseReceived                            bool
	requestSent                                 bool
	currentID                                   uint32
	IDMode                                      int
}

var rosaConnections = struct {
	sync.RWMutex
	conns map[uint32]ROSAConn
}{conns: make(map[uint32]ROSAConn)}

func CreateROSAConn(sourceIP, ingressIP net.IP,
	sourcePort int,
	sourceConnectionID []byte,
	siteRequest string,
	IDMode int,
	endpoint uint32) ROSAConn {
	//sourceid := uint32(binary.BigEndian.Uint16(idbuf[0:1])) << 29
	//initialid := endpoint<<31 + sourceid //id construction: 1bit if client or server, 2bit identification, rest is counting packet id
	initialid := endpoint << 31 //TODO: Do we really need unique ids? We identify by ConnID, not PacketID
	return ROSAConn{sourceIP: sourceIP, ingressIP: ingressIP, sourcePort: sourcePort, sourceConnectionID: sourceConnectionID, siteRequest: siteRequest, currentID: initialid, IDMode: IDMode}
}

func AddConnection(conn ROSAConn, keyid []byte) error {
	conn.keyid = keyid
	key := byteArrayToInt(cleanConnID(keyid))

	//Check if connection already exists

	rosaConnections.RLock()
	if _, check := rosaConnections.conns[key]; check {
		return nil
	}
	rosaConnections.RUnlock()

	rosaConnections.Lock()
	rosaConnections.conns[key] = conn
	rosaConnections.Unlock()
	fmt.Printf("Connection added:\nConnID: % x\nSourceIP: %s\nSourcePort: %d\nDestIP: %s\nDestPort: %d\nIngress: %s\nEgress: %s\n", conn.sourceConnectionID, conn.sourceIP, conn.sourcePort, conn.destIP, conn.destPort, conn.ingressIP, conn.egressIP)
	return nil
}

func RemoveConnection(connectionID []byte) error {
	key := byteArrayToInt(cleanConnID(connectionID))
	rosaConnections.Lock()
	delete(rosaConnections.conns, key)
	rosaConnections.Unlock()
	return nil
}

func UpdateConn(connectionID []byte, update uint8, value any) error {
	key := byteArrayToInt(cleanConnID(connectionID))
	rosaConnections.Lock()
	if entry, ok := rosaConnections.conns[key]; ok {
		switch update {
		case CLIENT_IP:
			entry.sourceIP = net.IP(value.([]byte))
		case INSTANCE_IP:
			entry.destIP = net.IP(value.([]byte))
		case PORT:
			entry.sourcePort = value.(int)
		case INSTANCE_PORT:
			entry.destPort = value.(int)
		case CLIENT_CONNECTIONID:
			entry.sourceConnectionID = value.([]byte)
		case INSTANCE_CONNECTIONID:
			entry.destConnectionID = value.([]byte)
		case SERVICE_REQUEST:
			entry.siteRequest = value.(string)
		case PACKETID:
			entry.currentID = value.(uint32)
		case ID_MODE:
			entry.IDMode = value.(int)
		case REQUEST_SENT:
			entry.requestSent = value.(bool)
		case RESPONSE:
			entry.responseReceived = value.(bool)
		default:
			return fmt.Errorf("no such fiels in ROSAConn")
		}
		rosaConnections.conns[key] = entry
	}
	rosaConnections.Unlock()
	return nil
}

func GetConn(connectionID []byte) (ROSAConn, error) {
	key := byteArrayToInt(cleanConnID(connectionID))
	rosaConnections.RLock()
	conn, ok := rosaConnections.conns[key]
	if !ok {
		rosaConnections.RUnlock()
		return ROSAConn{}, fmt.Errorf("no Connection for ConnectionID %X", connectionID)
	}
	rosaConnections.RUnlock()
	fmt.Println("Found Conn!")
	return conn, nil
}

func (conn ROSAConn) NextRetransmissionID() uint32 {
	id := conn.currentID
	conn.currentID++
	return id
}

func cleanConnID(id []byte) []byte {
	idbuf := append(id, []byte{0x0, 0x0, 0x0, 0x0}...)
	return idbuf[:4]
}

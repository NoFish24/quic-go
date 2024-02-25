package quic

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync"
)

func byteArrayToInt(byteSlice []byte) uint64 {
	return binary.BigEndian.Uint64(byteSlice[:4])
}

type ROSAConn struct {
	sourceIP, destIP, ingressIP, egressIP net.IP
	sourcePort, destPort                  int
	sourceConnectionID, destConnectionID  []byte
	siteRequest                           string
	responseReceived                      bool
	requestSent                           bool
	currentID                             uint32
	IDMode                                int
}

var rosaConnections = struct {
	sync.RWMutex
	conns map[uint64]ROSAConn
}{conns: make(map[uint64]ROSAConn)}

func CreateROSAConn(sourceIP, ingressIP net.IP,
	sourcePort int,
	sourceConnectionID []byte,
	siteRequest string,
	IDMode int,
	endpoint uint32) ROSAConn {
	sourceid := uint32(binary.BigEndian.Uint16(sourceConnectionID[0:1])) << 29
	initialid := endpoint<<31 + sourceid //id construction: 1bit if client or server, 2bit identification, rest is counting packet id
	initialid = endpoint << 31           //TODO: Do we really need unique ids? We identify by ConnID, not PacketID
	return ROSAConn{sourceIP: sourceIP, ingressIP: ingressIP, sourcePort: sourcePort, sourceConnectionID: sourceConnectionID, siteRequest: siteRequest, currentID: initialid, IDMode: IDMode}
}

func AddConnection(conn ROSAConn) error {
	key := byteArrayToInt(conn.sourceConnectionID)

	//Check if connection already exists

	rosaConnections.RLock()
	if _, check := rosaConnections.conns[key]; check {
		return nil
	}
	rosaConnections.RUnlock()

	rosaConnections.Lock()
	rosaConnections.conns[key] = conn
	rosaConnections.Unlock()
	return nil
}

func AddConnectionClient(conn ROSAConn) error { // used after getting a response; for affinity we only have the destination connection id available
	key := byteArrayToInt(conn.destConnectionID)

	//Check if connection already exists

	rosaConnections.RLock()
	if _, check := rosaConnections.conns[key]; check {
		return nil
	}
	rosaConnections.RUnlock()

	rosaConnections.Lock()
	rosaConnections.conns[key] = conn
	rosaConnections.Unlock()
	return nil
}

func RemoveConnection(connectionID []byte) error {
	key := byteArrayToInt(connectionID)
	rosaConnections.Lock()
	delete(rosaConnections.conns, key)
	rosaConnections.Unlock()
	return nil
}

func UpdateConn(connectionID []byte, update uint8, value any) error {
	key := byteArrayToInt(connectionID)
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
		default:
			return fmt.Errorf("no such fiels in ROSAConn")
		}
		rosaConnections.conns[key] = entry
	}
	rosaConnections.Unlock()
	return nil
}

func GetConn(connectionID []byte) (ROSAConn, error) {
	key := byteArrayToInt(connectionID)
	rosaConnections.RLock()
	conn, ok := rosaConnections.conns[key]
	if !ok {
		rosaConnections.RUnlock()
		return ROSAConn{}, fmt.Errorf("no Connection for ConnectionID %X", connectionID)
	}
	rosaConnections.RUnlock()
	return conn, nil
}

func (conn ROSAConn) NextRetransmissionID() uint32 {
	id := conn.currentID
	conn.currentID += 1
	return id
}

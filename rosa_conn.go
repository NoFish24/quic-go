package quic

import (
	"fmt"
	"net"
	"sync"
)

func byteArrayToInt(byteSlice []byte) (int, error) {
	var result int
	for _, b := range byteSlice {
		if b < '0' || b > '9' {
			return 0, fmt.Errorf("invalid byte: %c", b)
		}
		result = result*10 + int(b-'0')
	}
	return result, nil
}

type ROSAConn struct {
	sourceIP, destIP, ingressIP, egressIP net.IP
	sourcePort, destPort, ingressPort     int
	sourceConnectionID, destConnectionID  []byte
	siteRequest                           string
	responseReceived                      bool
	requestSent                           bool
	currentID                             int
	IDMode                                int
}

var rosaConnections = struct {
	sync.RWMutex
	conns map[int]ROSAConn
}{conns: make(map[int]ROSAConn)}

func CreateROSAConn(sourceIP, destIP, ingressIP net.IP,
	sourcePort, destPort, ingressPort int,
	sourceConnectionID, destConnectionID []byte,
	siteRequest string,
	IDMode int) ROSAConn {
	return ROSAConn{sourceIP, destIP, ingressIP, nil, sourcePort, destPort, 1337, sourceConnectionID,
		destConnectionID, siteRequest, false, false, 0, IDMode}
}

func CreateROSAConnServer(sourceIP, destIP, ingressIP net.IP,
	sourcePort, destPort int,
	sourceConnectionID, destConnectionID []byte,
	siteRequest string,
	IDMode int) ROSAConn {
	return ROSAConn{sourceIP, destIP, ingressIP, nil, sourcePort, destPort, 1337, sourceConnectionID,
		destConnectionID, siteRequest, true, false, 0, IDMode}
}

func AddConnection(conn ROSAConn) error {
	key, err := byteArrayToInt(conn.sourceConnectionID)
	if err != nil {
		return err
	}

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
	key, err := byteArrayToInt(connectionID)
	if err != nil {
		return err
	}
	rosaConnections.Lock()
	delete(rosaConnections.conns, key)
	rosaConnections.Unlock()
	return nil
}

func UpdateConn(connectionID []byte, update uint8, value any) error {
	key, err := byteArrayToInt(connectionID)
	if err != nil {
		return err
	}
	rosaConnections.Lock()
	if entry, ok := rosaConnections.conns[key]; ok {
		switch update {
		case SOURCEIP:
			entry.sourceIP = value.(net.IP)
		case DESTIP:
			entry.destIP = value.(net.IP)
		case SOURCEPORT:
			entry.sourcePort = value.(int)
		case DESTPORT:
			entry.destPort = value.(int)
		case SOURCEID:
			entry.sourceConnectionID = value.([]byte)
		case DESTID:
			entry.destConnectionID = value.([]byte)
		case SITE:
			entry.siteRequest = value.(string)
		case CURID:
			entry.currentID = value.(int)
		case MODE:
			entry.IDMode = value.(int)
		default:
			return fmt.Errorf("No such fiels in ROSAConn")
		}
		rosaConnections.conns[key] = entry
	}
	rosaConnections.Unlock()
	return nil
}

func GetConn(connectionID []byte) (ROSAConn, error) {
	key, err := byteArrayToInt(connectionID)
	rosaConnections.RLock()
	conn, ok := rosaConnections.conns[key]
	if !ok {
		rosaConnections.RUnlock()
		return ROSAConn{}, fmt.Errorf("no Connection for ConnectionID %X", connectionID)
	}
	rosaConnections.RUnlock()
	return conn, err
}

func (conn ROSAConn) NextRetransmissionID() int {
	id := conn.currentID
	conn.currentID += 1
	return id
}

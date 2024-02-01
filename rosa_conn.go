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
	sourceIP, destIP                     net.IP
	sourcePort, destPort                 int
	sourceConnectionID, destConnectionID []byte
	siteRequest                          string
	responseReceived                     bool
	currentID                            int
	IDMode                               int
}

var rosaConnections = struct {
	sync.RWMutex
	conns map[int]ROSAConn
}{conns: make(map[int]ROSAConn)}

func CreateROSAConn(sourceIP, destIP net.IP,
	sourcePort, destPort int,
	sourceConnectionID, destConnectionID []byte,
	siteRequest string,
	IDMode int) ROSAConn {
	return ROSAConn{sourceIP, destIP, sourcePort, destPort, sourceConnectionID,
		destConnectionID, siteRequest, false, 0, IDMode}
}

func CreateROSAConnServer(sourceIP, destIP net.IP,
	sourcePort, destPort int,
	sourceConnectionID, destConnectionID []byte,
	siteRequest string,
	IDMode int) ROSAConn {
	return ROSAConn{sourceIP, destIP, sourcePort, destPort, sourceConnectionID,
		destConnectionID, siteRequest, true, 0, IDMode}
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

func GetConn(connectionID []byte) (ROSAConn, error) {
	key, err := byteArrayToInt(connectionID)
	rosaConnections.RLock()
	conn := rosaConnections.conns[key]
	rosaConnections.RUnlock()
	return conn, err
}

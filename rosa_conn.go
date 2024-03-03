package quic

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
)

func byteArrayToInt(byteSlice []byte) uint32 {
	return binary.BigEndian.Uint32(byteSlice[:4])
}

type ROSAConn struct {
	sourceIP, destIP, ingressIP, egressIP                             net.IP
	sourcePort, destPort                                              int
	keyid, sourceConnectionID, destConnectionID, firstSrcConnectionID []byte
	siteRequest                                                       string
	responseReceived                                                  bool
	requestSent                                                       bool
	currentID                                                         uint32
	IDMode                                                            int
	memory                                                            Memory
}

type Memory struct {
	oob     []byte
	hdrType uint8
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
	return ROSAConn{sourceIP: sourceIP, ingressIP: ingressIP, sourcePort: sourcePort, sourceConnectionID: sourceConnectionID, firstSrcConnectionID: sourceConnectionID, siteRequest: siteRequest, currentID: initialid, IDMode: IDMode}
}

func AddConnection(conn ROSAConn, keyid []byte) error {
	conn.keyid = keyid
	key := byteArrayToInt(cleanConnID(keyid))
	//fmt.Printf("cleaned key: % x, dirtied keyid: % x\n", key, keyid)

	//Check if connection already exists

	rosaConnections.RLock()
	if _, check := rosaConnections.conns[key]; check {
		rosaConnections.RUnlock()
		return nil
	}
	rosaConnections.RUnlock()

	rosaConnections.Lock()
	rosaConnections.conns[key] = conn
	rosaConnections.Unlock()
	fmt.Printf("Connection added:\nKey: % x\nConnID: % x\nDestConnID: % x\nSourceIP: %s\nSourcePort: %d\nDestIP: %s\nDestPort: %d\nIngress: %s\nEgress: %s\n", conn.keyid, conn.sourceConnectionID, conn.destConnectionID, conn.sourceIP.String(), conn.sourcePort, conn.destIP.String(), conn.destPort, conn.ingressIP, conn.egressIP)
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

func (r ROSAConn) SetMemory(mem Memory) {
	r.memory = mem
	rosaConnections.Lock()
	rosaConnections.conns[byteArrayToInt(cleanConnID(r.keyid))] = r
	rosaConnections.Unlock()
}

func (r ROSAConn) GetMemory() (uint8, []byte) {
	if r.memory.oob != nil {
		ret := r.memory
		r.memory = Memory{}
		rosaConnections.Lock()
		rosaConnections.conns[byteArrayToInt(cleanConnID(r.keyid))] = r
		rosaConnections.Unlock()
		return ret.hdrType, ret.oob
	}
	return 0, nil
}

func GetConn(connectionID []byte) (ROSAConn, error) {
	key := byteArrayToInt(cleanConnID(connectionID))
	rosaConnections.RLock()
	conn, ok := rosaConnections.conns[key]
	if !ok {
		rosaConnections.RUnlock()
		return ROSAConn{}, fmt.Errorf("no Connection for ConnectionID % x", connectionID)
	}
	rosaConnections.RUnlock()
	fmt.Printf("Conn: % x, % x\n", conn.keyid, conn.firstSrcConnectionID)
	return conn, nil
}

func (r ROSAConn) NextRetransmissionID() uint32 {
	id := r.currentID
	UpdateConn(r.keyid, PACKETID, id+1)
	return id
}

func cleanConnID(id []byte) []byte {
	idbuf := append(id, []byte{0x0, 0x0, 0x0, 0x0}...)
	//fmt.Printf("cleaned idbuf: % x, id: % x\n", idbuf, id)
	return idbuf[:4]
}

func GetOnConnIDChange(srcconnid, newdestconnid []byte) (ROSAConn, error) {
	var target ROSAConn
	rosaConnections.RLock()
	for _, conn := range rosaConnections.conns {
		if bytes.Equal(srcconnid, conn.firstSrcConnectionID) {
			target = conn
			if bytes.Equal(newdestconnid, conn.keyid) {
				rosaConnections.RUnlock()
				return target, nil
			}
		}
	}

	if target.firstSrcConnectionID == nil {
		return ROSAConn{}, fmt.Errorf("No Conn to Change! GetConnIDChange\n")
	}

	rosaConnections.RUnlock()
	oldid := target.keyid
	target.destConnectionID = newdestconnid
	target.keyid = newdestconnid
	err := AddConnection(target, newdestconnid)
	err = RemoveConnection(oldid)
	return target, err
}

func CheckIDChange(conn ROSAConn, srcid, destid []byte) bool {
	if bytes.Equal(srcid, conn.sourceConnectionID) && bytes.Equal(destid, conn.destConnectionID) {
		return true
	} else {
		return false
	}
}

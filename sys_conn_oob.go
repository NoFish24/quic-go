//go:build darwin || linux || freebsd

package quic

import (
	"encoding/binary"
	"errors"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"
	"log"
	"net"
	"net/netip"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/nofish24/quic-go/internal/protocol"
	"github.com/nofish24/quic-go/internal/utils"
)

const (
	ecnMask       = 0x3
	oobBufferSize = 256 //ROSA: Need to enlarge to fit larger Responses
)

// Contrary to what the naming suggests, the ipv{4,6}.Message is not dependent on the IP version.
// They're both just aliases for x/net/internal/socket.Message.
// This means we can use this struct to read from a socket that receives both IPv4 and IPv6 messages.
var _ ipv4.Message = ipv6.Message{}

type batchConn interface {
	ReadBatch(ms []ipv4.Message, flags int) (int, error)
}

func inspectReadBuffer(c syscall.RawConn) (int, error) {
	var size int
	var serr error
	if err := c.Control(func(fd uintptr) {
		size, serr = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUF)
	}); err != nil {
		return 0, err
	}
	return size, serr
}

func inspectWriteBuffer(c syscall.RawConn) (int, error) {
	var size int
	var serr error
	if err := c.Control(func(fd uintptr) {
		size, serr = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_SNDBUF)
	}); err != nil {
		return 0, err
	}
	return size, serr
}

type oobConn struct {
	OOBCapablePacketConn
	batchConn batchConn

	readPos uint8
	// Packets received from the kernel, but not yet returned by ReadPacket().
	messages []ipv4.Message
	buffers  [batchSize]*packetBuffer

	cap connCapabilities
}

var _ rawConn = &oobConn{}

func newConn(c OOBCapablePacketConn, supportsDF bool) (*oobConn, error) {
	rawConn, err := c.SyscallConn()
	if err != nil {
		return nil, err
	}
	needsPacketInfo := false
	if udpAddr, ok := c.LocalAddr().(*net.UDPAddr); ok && udpAddr.IP.IsUnspecified() {
		needsPacketInfo = true
	}

	//Set if DestinationOptions is needed (IPv6-only)
	needsDestOpts := true

	// We don't know if this a IPv4-only, IPv6-only or a IPv4-and-IPv6 connection.
	// Try enabling receiving of ECN and packet info for both IP versions.
	// We expect at least one of those syscalls to succeed.
	var errECNIPv4, errECNIPv6, errPIIPv4, errPIIPv6, errDestOpts, errDestOptsRecv, errMTU, errMTUSize error
	if err := rawConn.Control(func(fd uintptr) {
		errECNIPv4 = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_RECVTOS, 1)
		errECNIPv6 = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_RECVTCLASS, 1)

		if needsPacketInfo {
			errPIIPv4 = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, ipv4PKTINFO, 1)
			errPIIPv6 = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_RECVPKTINFO, 1)
		}

		if needsDestOpts {
			errDestOpts = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_DSTOPTS, 1)
			errDestOptsRecv = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_RECVDSTOPTS, 1)
			errMTU = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_MTU_DISCOVER, unix.IPV6_PMTUDISC_OMIT)
			errMTUSize = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_MTU, 1500)
			errMTUSize = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_MTU, 1500)
			//fmt.Println("Set DestOpts!")
		}

	}); err != nil {
		return nil, err
	}
	switch {
	case errECNIPv4 == nil && errECNIPv6 == nil:
		utils.DefaultLogger.Debugf("Activating reading of ECN bits for IPv4 and IPv6.")
	case errECNIPv4 == nil && errECNIPv6 != nil:
		utils.DefaultLogger.Debugf("Activating reading of ECN bits for IPv4.")
	case errECNIPv4 != nil && errECNIPv6 == nil:
		utils.DefaultLogger.Debugf("Activating reading of ECN bits for IPv6.")
	case errECNIPv4 != nil && errECNIPv6 != nil:
		return nil, errors.New("activating ECN failed for both IPv4 and IPv6")
	}
	if needsPacketInfo {
		switch {
		case errPIIPv4 == nil && errPIIPv6 == nil:
			utils.DefaultLogger.Debugf("Activating reading of packet info for IPv4 and IPv6.")
		case errPIIPv4 == nil && errPIIPv6 != nil:
			utils.DefaultLogger.Debugf("Activating reading of packet info bits for IPv4.")
		case errPIIPv4 != nil && errPIIPv6 == nil:
			utils.DefaultLogger.Debugf("Activating reading of packet info bits for IPv6.")
		case errPIIPv4 != nil && errPIIPv6 != nil:
			return nil, errors.New("activating packet info failed for both IPv4 and IPv6")
		}
	}

	if needsDestOpts {
		switch {
		case errDestOpts == nil && errDestOptsRecv == nil:
			utils.DefaultLogger.Debugf("Activating writing and reading of destination info for IPv6.")
		case errDestOpts == nil && errDestOptsRecv != nil:
			utils.DefaultLogger.Debugf("Activating sending of destination info for IPv6.")
		case errDestOpts != nil && errDestOptsRecv == nil:
			utils.DefaultLogger.Debugf("Activating reading of destination info for IPv6.")
		case errDestOpts != nil && errDestOptsRecv != nil:
			return nil, errors.New("activation of sending and reading of destination info for IPv6 failed")
		case errMTU != nil && errMTUSize != nil:
			//fmt.Printf("Error setting up no MTUDisc: %d\n", errMTU)
			//fmt.Printf("Error setting MTU Size: %s\n", errMTUSize)
		case errMTU != nil:
			//fmt.Printf("Error setting up no MTUDisc: %d\n", errMTU)
		case errMTUSize != nil:
			//fmt.Printf("Error setting MTU Size: %s\n", errMTUSize)
		}
	}

	// Allows callers to pass in a connection that already satisfies batchConn interface
	// to make use of the optimisation. Otherwise, ipv4.NewPacketConn would unwrap the file descriptor
	// via SyscallConn(), and read it that way, which might not be what the caller wants.
	var bc batchConn
	if ibc, ok := c.(batchConn); ok {
		bc = ibc
	} else {
		bc = ipv4.NewPacketConn(c)
	}

	msgs := make([]ipv4.Message, batchSize)
	for i := range msgs {
		// preallocate the [][]byte
		msgs[i].Buffers = make([][]byte, 1)
	}
	oobConn := &oobConn{
		OOBCapablePacketConn: c,
		batchConn:            bc,
		messages:             msgs,
		readPos:              batchSize,
		cap: connCapabilities{
			DF: supportsDF,
			//GSO: isGSOSupported(rawConn),
			GSO: false,
		},
	}
	for i := 0; i < batchSize; i++ {
		oobConn.messages[i].OOB = make([]byte, oobBufferSize)
	}
	return oobConn, nil
}

var invalidCmsgOnceV4, invalidCmsgOnceV6 sync.Once

func (c *oobConn) ReadPacket() (receivedPacket, error) {
	if len(c.messages) == int(c.readPos) { // all messages read. Read the next batch of messages.
		c.messages = c.messages[:batchSize]
		// replace buffers data buffers up to the packet that has been consumed during the last ReadBatch call
		for i := uint8(0); i < c.readPos; i++ {
			buffer := getPacketBuffer()
			buffer.Data = buffer.Data[:protocol.MaxPacketBufferSize]
			c.buffers[i] = buffer
			c.messages[i].Buffers[0] = c.buffers[i].Data
		}
		c.readPos = 0

		n, err := c.batchConn.ReadBatch(c.messages, 0)
		if n == 0 || err != nil {
			return receivedPacket{}, err
		}
		c.messages = c.messages[:n]
	}

	msg := c.messages[c.readPos]
	buffer := c.buffers[c.readPos]
	c.readPos++

	data := msg.OOB[:msg.NN]
	p := receivedPacket{
		remoteAddr: msg.Addr,
		rcvTime:    time.Now(),
		data:       msg.Buffers[0][:msg.N],
		buffer:     buffer,
	}

	//fmt.Printf("Received Packet from %s\n", p.remoteAddr.String())

	//fmt.Printf("Data:\n% x\n", data)

	for len(data) > 0 {
		hdr, body, remainder, err := unix.ParseOneSocketControlMessage(data)
		if err != nil {
			return receivedPacket{}, err
		}
		if hdr.Level == unix.IPPROTO_IP {
			switch hdr.Type {
			case msgTypeIPTOS:
				p.ecn = protocol.ECN(body[0] & ecnMask)
			case ipv4PKTINFO:
				ip, ifIndex, ok := parseIPv4PktInfo(body)
				if ok {
					p.info.addr = ip
					p.info.ifIndex = ifIndex
				} else {
					invalidCmsgOnceV4.Do(func() {
						log.Printf("Received invalid IPv4 packet info control message: %+x. "+
							"This should never occur, please open a new issue and include details about the architecture.", body)
					})
				}
			}
		}
		if hdr.Level == unix.IPPROTO_IPV6 {
			switch hdr.Type {
			case unix.IPV6_TCLASS:
				p.ecn = protocol.ECN(body[0] & ecnMask)
			case unix.IPV6_PKTINFO:
				// struct in6_pktinfo {
				// 	struct in6_addr ipi6_addr;    /* src/dst IPv6 address */
				// 	unsigned int    ipi6_ifindex; /* send/recv interface index */
				// };
				if len(body) == 20 {
					p.info.addr = netip.AddrFrom16(*(*[16]byte)(body[:16]))
					p.info.ifIndex = binary.LittleEndian.Uint32(body[16:])
				} else {
					invalidCmsgOnceV6.Do(func() {
						log.Printf("Received invalid IPv6 packet info control message: %+x. "+
							"This should never occur, please open a new issue and include details about the architecture.", body)
					})
				}
			case unix.IPV6_DSTOPTS: //ROSA Header
				//Parse ROSA Header
				//fmt.Printf("Received ROSAHdr: %d\n", uint8(body[2]))
				switch uint8(body[2]) {
				case SERVICE_REQUEST: //Get request from a Client, create Connection State
					if len(body) != 0 {

						//fmt.Printf("Body:\n% x\nRemainder:\n% x\n", body, remainder)

						rosadata := DecodeROSAOptionTLVFields(body)

						conn := ROSAConn{}
						var destip net.IP
						var destport int
						var clid []byte
						var ingress net.IP
						//var egress net.IP
						var IDmode int

						for _, rd := range rosadata {
							switch rd.FieldType {
							case CLIENT_IP:
								destip = rd.FieldData
							case PORT:
								destport = int(binary.BigEndian.Uint16(rd.FieldData))
							case CLIENT_CONNECTIONID:
								clid = append(make([]byte, 0), rd.FieldData...)
							case INGRESS_IP:
								ingress = rd.FieldData
							/*
								case EGRESS_IP:
								egress = rd.FieldData
							*/

							case ID_MODE:
								IDmode = int(binary.BigEndian.Uint16(rd.FieldData))
							default:
								continue
							}
						}

						if testc, _ := GetConn(clid); testc.ingressIP == nil {
							conn.sourceIP = c.LocalAddr().(*net.UDPAddr).IP
							conn.sourcePort = c.LocalAddr().(*net.UDPAddr).Port
							conn.currentID = 0 // uint(0)<<31 + uint32(binary.BigEndian.Uint16(conn.sourceConnectionID[0:1]))<<29
							conn.destIP = append(make([]byte, 0), destip...)
							conn.destPort = destport
							conn.sourceConnectionID = append(make([]byte, 0), clid...)
							conn.ingressIP = p.remoteAddr.(*net.UDPAddr).IP
							conn.egressIP = append(make([]byte, 0), ingress...)
							conn.IDMode = IDmode
							conn.firstSrcConnectionID = conn.sourceConnectionID

							conn.responseReceived = true //To signal that next packet should contain response -> responsiveReceived & !requestSent

							err := AddConnection(conn, conn.sourceConnectionID)
							//fmt.Printf("Add connection with key: % x\n", conn.sourceConnectionID)
							if err != nil {
								//fmt.Println("Error adding connection")
								return p, nil
							}
						}
					}
				case SERVICE_RESPONSE: //Client receive response from server, update to actual Destination ID, Destination IP and Destination Port; all other fields should still be the same
					//fmt.Printf("Hdr: % x\nOOB:\n% x\nRemainder:\n% x\n", hdr, body, remainder)
					if len(body) != 0 {
						rosadata := DecodeROSAOptionTLVFields(body)

						var connID []byte
						var inconnID []byte

						for i := range rosadata {
							if rosadata[i].FieldType == CLIENT_CONNECTIONID {
								connID = rosadata[i].FieldData
							}
							if rosadata[i].FieldType == INSTANCE_CONNECTIONID {
								inconnID = make([]byte, len(rosadata[i].FieldData))
								inconnID = append(make([]byte, 0), rosadata[i].FieldData...)
							}
						}

						//fmt.Printf("DestConn: % x, SrcConn: % x\n", inconnID, connID)

						//Check if a response already was received and if yes ignore procedure, assess like an affinity on Client (not at all)
						if _, err := GetConn(inconnID); err != nil {
							conn, err := GetConn(connID)
							if err != nil {
								panic(err)
							}
							conn.responseReceived = true
							conn.destConnectionID = inconnID

							for i := range rosadata {
								switch rosadata[i].FieldType {
								case PORT:
									conn.sourcePort = int(binary.BigEndian.Uint16(rosadata[i].FieldData))
								case CLIENT_IP:
									conn.sourceIP = append(make([]byte, 0), rosadata[i].FieldData...)
								case INSTANCE_PORT:
									conn.destPort = int(binary.BigEndian.Uint16(rosadata[i].FieldData))
								case INSTANCE_IP:
									conn.destIP = append(make([]byte, 0), rosadata[i].FieldData...)
								case EGRESS_IP:
									conn.egressIP = append(make([]byte, 0), rosadata[i].FieldData...)
								default:
									continue
								}
							}
							//fmt.Printf("Creating Connection with ConnID: % x, inconn: % x\n", conn.destConnectionID, inconnID)

							err = AddConnection(conn, conn.destConnectionID)
							if err != nil {
								//fmt.Printf("Problem with Request Connection Handling")
								return receivedPacket{}, err
							}
							err = RemoveConnection(connID)
							if err != nil {
								//fmt.Printf("Problem with Request Connection Handling")
								return receivedPacket{}, err
							}
						}

					}
				case SERVICE_AFFINITY:
					// Might not be needed
					/*
						if len(body) != 0 {
							var connID []byte

							rosadata := DecodeROSAOptionTLVFields(body)

							for i := range rosadata {
								if rosadata[i].FieldType == CLIENT_CONNECTIONID {
									connID = rosadata[i].FieldData
								}
							}
							conn, err := GetConn(connID)
							if err == nil {
								if !conn.requestSent || conn.responseReceived {
									UpdateConn(connID, REQUEST_SENT, true)
								}
							}
						}
					*/

				default:
					//fmt.Println("Whyyy! DSTOpts received, but no ROSA :(")
				}

			}
			//fmt.Println("DstOpts handled!")
		}
		data = remainder
	}
	return p, nil
}

// WritePacket writes a new packet.
// If the connection supports GSO, it's the caller's responsibility to append the right control mesage.
func (c *oobConn) WritePacket(b []byte, addr net.Addr, oob []byte) (int, error) {

	//ROSA
	var conn ROSAConn
	var err error
	var hdrType uint8
	var rosadata []byte

	srcid := []byte{0x0}
	var id []byte

	//Obtain correct ROSA connection state
	//Overcomplicated
	//TODO: Simplify id identification
	if b[0]>>7 == 1 { //Packet is in Long Header Format
		//fmt.Println("Long Header Packet!")
		//fmt.Printf("First Bytes: % x\n", b[:30])
		if b[6+b[5]] != 0 {
			//fmt.Printf("Length of DstConnID: %d\n", b[5])
			id = append(id, b[6+b[5]+1:6+b[5]+b[6+b[5]]+1]...)
			//fmt.Printf("id: % x\n", id)
			conn, err = GetConn(id) //Source ConnID for Request
			srcid = id
			if err != nil {
				if b[5] != 0 {
					err = nil
					id = nil
					id = append(id, b[6:5+b[5]+1]...)
					conn, err = GetConn(id) //DestConnID for Affinity
					if err != nil {
						err = nil
						conn, err = GetConn([]byte{0x0, 0x0, 0x0, 0x0}) //Zero-Length Destination ConnID
					}
				} else {
					err = nil
					conn, err = GetConn([]byte{0x0, 0x0, 0x0, 0x0}) //Zero-Length Destination ConnID
					srcid = []byte{0x0, 0x0, 0x0, 0x0}
				}
			}
		} else {
			if b[5] != 0 {
				id = nil
				id = append(id, b[6:5+b[5]+1]...)
				conn, err = GetConn(id) //DestConnID for Affinity
				if err != nil {
					err = nil
					conn, err = GetConn([]byte{0x0, 0x0, 0x0, 0x0}) //Zero-Length Destination ConnID
					srcid = []byte{0x0, 0x0, 0x0, 0x0}
				}
			} else {
				conn, err = GetConn([]byte{0x0, 0x0, 0x0, 0x0}) //Zero-Length Destination ConnID
				srcid = []byte{0x0, 0x0, 0x0, 0x0}
			}
		}
	} else { //Packet is NOT in Long Header Format
		//fmt.Println("Short Header Packet!")
		id = nil
		id = append(id, b[1:5]...)
		//fmt.Printf("ID for Short Header: % x\nExtracted ID: % x, Len: %d\n", id, b[1:5], len(b[1:5]))
		conn, err = GetConn(id)
	}
	if err != nil {
		//Replace ConnID if the destination id changes (SHOULD happen before Short Headers... i hope)
		//Should be replaced with system within the assignment mechanisms of QUIC -> ConnIDGenerator or Manager OR Connection/Transport
		//No Idea where though (see handleNewConnectionIDFrame in connection.go)
		/*
			if b[0]>>7 == 1 {
				err = nil
				conn, err = GetOnConnIDChange(b[6+b[5]+1:6+b[5]+b[6+b[5]]+1], b[6:5+b[5]+1])
			}
		*/
		if err != nil {
			//fmt.Println("No conn found.")
			//fmt.Println(err.Error())
			//fmt.Printf("Body of no conn:\n% x\n", b)
			return 0, err
		}
	}
	hdrType, rosadata = c.createROSAOOB(conn, srcid)
	//fmt.Printf("%d ROSA clean:\n% x\n\n", hdrType, rosadata)

	//Construct Header and merge with other OOB

	oob = CreateDestOptsOOB(oob, rosadata, hdrType) //Take ROSA data created in connection and append to OOB
	//fmt.Printf("OOB complete:\n% x\n\n", oob)

	//fmt.Printf("Text after ROSA:\n% x\n", b)

	n, _, err := c.OOBCapablePacketConn.WriteMsgUDP(b, oob, addr.(*net.UDPAddr))
	if n == 0 {
		//fmt.Printf("\nSend failed\n%s\n", err)
		//fmt.Printf("Failed Message lengths: N: %d, OOB; %d\n", len(b), len(oob))
	} else {
		//fmt.Printf("Sent Packet!\n")
	}
	//fmt.Printf("N: %d, OOBN: %d\n", n, oobn)
	rc, _ := c.OOBCapablePacketConn.SyscallConn()
	err = rc.Control(func(fd uintptr) {
		_, err := syscall.GetsockoptInt(int(fd), syscall.IPPROTO_IPV6, syscall.IPV6_MTU_DISCOVER)
		//fmt.Printf("MTU: %d\n", sockinfo)
		if err != nil {
			//fmt.Printf("Error when reading MTU: %s\n", err)
		}
	})
	if err != nil {
		return 0, err
	}
	return n, err
}

func (c *oobConn) capabilities() connCapabilities {
	return c.cap
}

type packetInfo struct {
	addr    netip.Addr
	ifIndex uint32
}

func (info *packetInfo) OOB() []byte {
	if info == nil {
		return nil
	}
	if info.addr.Is4() {
		ip := info.addr.As4()
		// struct in_pktinfo {
		// 	unsigned int   ipi_ifindex;  /* Interface index */
		// 	struct in_addr ipi_spec_dst; /* Local address */
		// 	struct in_addr ipi_addr;     /* Header Destination address */
		// };
		cm := ipv4.ControlMessage{
			Src:     ip[:],
			IfIndex: int(info.ifIndex),
		}
		return cm.Marshal()
	} else if info.addr.Is6() {
		ip := info.addr.As16()
		// struct in6_pktinfo {
		// 	struct in6_addr ipi6_addr;    /* src/dst IPv6 address */
		// 	unsigned int    ipi6_ifindex; /* send/recv interface index */
		// };
		cm := ipv6.ControlMessage{
			Src:     ip[:],
			IfIndex: int(info.ifIndex),
		}
		return cm.Marshal()
	}
	return nil
}

func CreateDestOptsOOB(oob []byte, dstoptdata []byte, optType uint8) []byte {
	dstoptdata = append([]byte{optType, uint8(len(dstoptdata))}, dstoptdata...)
	dstoptdata = append([]byte{optType, uint8((len(dstoptdata) + 2) / 8)}, dstoptdata...)
	pad := len(dstoptdata) % 8
	if pad != 0 {
		dstoptdata = append(dstoptdata, make([]byte, 8-pad)...)
	}

	startLen := len(oob)
	dataLen := len(dstoptdata)
	oob = append(oob, make([]byte, unix.CmsgSpace(dataLen))...)
	h := (*unix.Cmsghdr)(unsafe.Pointer(&oob[startLen]))
	h.Level = syscall.IPPROTO_IPV6
	h.Type = unix.IPV6_DSTOPTS
	h.SetLen(unix.CmsgLen(dataLen))

	// UnixRights uses the private `data` method, but I *think* this achieves the same goal.
	offset := startLen + unix.CmsgSpace(0)
	copy(oob[offset:], dstoptdata)

	return oob

}

func (c *oobConn) createROSAOOB(conn ROSAConn, srcid []byte) (uint8, []byte) {

	var hdrType uint8
	var rosadata []byte

	//Obtain correct header type (Request, Response, Affinity)
	if conn.requestSent && conn.responseReceived { //Connection established, Affinity
		hdrType = SERVICE_AFFINITY
	} else if conn.requestSent && !conn.responseReceived { //Client sent Request, Response not received
		hdrType = SERVICE_REQUEST
	} else if !conn.requestSent && conn.responseReceived { //Server got Request, send Response
		hdrType = SERVICE_RESPONSE
	} else if !conn.requestSent && !conn.responseReceived { //First Packet, Client sends Request
		hdrType = SERVICE_REQUEST
	}

	//fmt.Printf("RosaHeader: %x\n IP of Source: %s\n", hdrType, conn.sourceIP.String())
	//Create TLV Fields for ROSA Header
	switch hdrType {
	case SERVICE_REQUEST:
		//DOES NOT WORK; if added here the packet will not arrive in one piece, if added at an edge, the packet will be fine for some reason
		/*
			clientIPField := &ROSAOptionTLVField{
				FieldType: CLIENT_IP,
				FieldData: net.IP{0xfd, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x2},
			}
			clientPortField := &ROSAOptionTLVField{
				FieldType: PORT,
				FieldData: make([]byte, 2),
			}
		*/

		ingressIPField := &ROSAOptionTLVField{
			FieldType: INGRESS_IP,
			FieldData: []byte(conn.ingressIP),
		}
		sourceIDField := &ROSAOptionTLVField{
			FieldType: CLIENT_CONNECTIONID,
			FieldData: conn.sourceConnectionID,
		}
		requestField := &ROSAOptionTLVField{
			FieldType: SERVICE_ID,
			FieldData: []byte(conn.siteRequest),
		}
		transmissionIDField := &ROSAOptionTLVField{
			FieldType: PACKETID,
			FieldData: make([]byte, 4),
		}
		idModeField := &ROSAOptionTLVField{
			FieldType: ID_MODE,
			FieldData: make([]byte, 2),
		}
		//binary.BigEndian.PutUint16(clientPortField.FieldData, uint16(c.LocalAddr().(*net.UDPAddr).Port))
		id := conn.NextRetransmissionID()
		binary.BigEndian.PutUint32(transmissionIDField.FieldData, id)
		binary.BigEndian.PutUint16(idModeField.FieldData, uint16(0))

		UpdateConn(conn.sourceConnectionID, REQUEST_SENT, true)

		//_, rosadata = SerializeAllROSAOptionFields(&[]ROSAOptionTLVField{*clientIPField, *clientPortField, *ingressIPField, *egressIPField, *sourceIDField, *requestField, *transmissionIDField, *idModeField})
		_, rosadata = SerializeAllROSAOptionFields(&[]ROSAOptionTLVField{*sourceIDField, *requestField, *ingressIPField, *idModeField, *transmissionIDField})

	case SERVICE_RESPONSE:

		UpdateConn(conn.keyid, INSTANCE_CONNECTIONID, srcid)

		clientIPField := &ROSAOptionTLVField{
			FieldType: CLIENT_IP,
			FieldData: conn.destIP,
		}
		clientPortField := &ROSAOptionTLVField{
			FieldType: PORT,
			FieldData: make([]byte, 2),
		}
		destIPField := &ROSAOptionTLVField{
			FieldType: INSTANCE_IP,
			FieldData: conn.sourceIP,
		}
		destPortField := &ROSAOptionTLVField{
			FieldType: INSTANCE_PORT,
			FieldData: make([]byte, 2),
		}
		ingressIPField := &ROSAOptionTLVField{
			FieldType: INGRESS_IP,
			FieldData: conn.egressIP,
		}
		egressIPField := &ROSAOptionTLVField{
			FieldType: EGRESS_IP,
			FieldData: conn.ingressIP,
		}
		sourceIDField := &ROSAOptionTLVField{
			FieldType: CLIENT_CONNECTIONID,
			FieldData: conn.sourceConnectionID,
		}
		instanceIDField := &ROSAOptionTLVField{
			FieldType: INSTANCE_CONNECTIONID,
			FieldData: srcid,
		}
		transmissionIDField := &ROSAOptionTLVField{
			FieldType: PACKETID,
			FieldData: make([]byte, 4),
		}
		binary.BigEndian.PutUint16(clientPortField.FieldData, uint16(conn.destPort))
		binary.BigEndian.PutUint16(destPortField.FieldData, uint16(conn.sourcePort))
		id := conn.NextRetransmissionID()
		binary.BigEndian.PutUint32(transmissionIDField.FieldData, id)

		//fmt.Printf("TransmissionID: % x\n", transmissionIDField.FieldData)
		UpdateConn(conn.sourceConnectionID, REQUEST_SENT, true)

		_, rosadata = SerializeAllROSAOptionFields(&[]ROSAOptionTLVField{*sourceIDField, *instanceIDField, *clientIPField, *clientPortField, *destIPField, *destPortField, *ingressIPField, *egressIPField, *transmissionIDField})

	case SERVICE_AFFINITY:

		sourceIDField := &ROSAOptionTLVField{
			FieldType: CLIENT_CONNECTIONID,
			FieldData: conn.firstSrcConnectionID,
		}
		destIPField := &ROSAOptionTLVField{
			FieldType: INSTANCE_IP,
			FieldData: []byte(conn.destIP),
		}
		ingressIPField := &ROSAOptionTLVField{
			FieldType: INGRESS_IP,
			FieldData: conn.ingressIP,
		}
		egressIPField := &ROSAOptionTLVField{
			FieldType: EGRESS_IP,
			FieldData: conn.egressIP,
		}
		destPortField := &ROSAOptionTLVField{
			FieldType: INSTANCE_PORT,
			FieldData: make([]byte, 2),
		}
		transmissionIDField := &ROSAOptionTLVField{
			FieldType: PACKETID,
			FieldData: make([]byte, 4),
		}

		binary.BigEndian.PutUint16(destPortField.FieldData, uint16(conn.destPort))

		id := conn.NextRetransmissionID()

		binary.BigEndian.PutUint32(transmissionIDField.FieldData, id)

		_, rosadata = SerializeAllROSAOptionFields(&[]ROSAOptionTLVField{*sourceIDField, *ingressIPField, *egressIPField, *destIPField, *destPortField, *transmissionIDField})

	}

	return hdrType, rosadata
}

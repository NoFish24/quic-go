//go:build darwin || linux || freebsd

package quic

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"strconv"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"

	"github.com/nofish24/quic-go/internal/protocol"
	"github.com/nofish24/quic-go/internal/utils"
)

const (
	ecnMask       = 0x3
	oobBufferSize = 128
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

func isECNDisabled() bool {
	disabled, err := strconv.ParseBool(os.Getenv("QUIC_GO_DISABLE_ECN"))
	return err == nil && disabled
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
	var errECNIPv4, errECNIPv6, errPIIPv4, errPIIPv6, errDestOpts, errDestOptsRecv error
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
			DF:  supportsDF,
			GSO: isGSOSupported(rawConn),
			ECN: !isECNDisabled(),
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
	for len(data) > 0 {
		hdr, body, remainder, err := unix.ParseOneSocketControlMessage(data)
		if err != nil {
			return receivedPacket{}, err
		}
		if hdr.Level == unix.IPPROTO_IP {
			switch hdr.Type {
			case msgTypeIPTOS:
				p.ecn = protocol.ParseECNHeaderBits(body[0] & ecnMask)
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
				p.ecn = protocol.ParseECNHeaderBits(body[0] & ecnMask)
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
				switch uint8(hdr.Type) {
				case SERVICE_REQUEST: //Get request from a Client, create Connection State
					if len(body) != 0 {
						rosadata := DecodeROSAOptionTLVFields(body)

						conn := ROSAConn{}

						for _, rd := range rosadata {
							switch rd.FieldType {
							case CLIENT_IP:
								conn.destIP = body
							case PORT:
								conn.destPort = int(binary.BigEndian.Uint16(body))
							case CLIENT_CONNECTIONID:
								conn.sourceConnectionID = body
							case INGRESS_IP:
								conn.egressIP = body
							case EGRESS_IP:
								conn.ingressIP = body
							case ID_MODE:
								conn.IDMode = int(binary.BigEndian.Uint16(body))
							default:
								continue
							}
						}

						conn.sourceIP = SourceAddr.(*net.UDPAddr).IP
						conn.sourcePort = SourceAddr.(*net.UDPAddr).Port
						conn.currentID = 0 // uint(0)<<31 + uint32(binary.BigEndian.Uint16(conn.sourceConnectionID[0:1]))<<29

						conn.responseReceived = true //To signal that next packet should contain response -> responsiveReceived & !requestSent

						err := AddConnection(conn)
						if err != nil {
							return p, err
						}
					}
				case SERVICE_RESPONSE: //Client receive response from server, update to actual Destination ID, Destination IP and Destination Port; all other fields should still be the same
					if len(body) != 0 {
						rosadata := DecodeROSAOptionTLVFields(body)

						var connID []byte

						for i := range rosadata {
							if rosadata[i].FieldType == CLIENT_CONNECTIONID {
								connID = rosadata[i].FieldData
							}
						}

						conn, err := GetConn(connID)
						if err != nil {
							panic(err)
						}
						conn.responseReceived = true

						for i := range rosadata {
							switch rosadata[i].FieldType {
							case INSTANCE_PORT:
								conn.destPort = int(binary.BigEndian.Uint16(rosadata[i].FieldData))
							case INSTANCE_IP:
								conn.destIP = rosadata[i].FieldData
							case INGRESS_IP:
								conn.egressIP = rosadata[i].FieldData
							case INSTANCE_CONNECTIONID:
								conn.destConnectionID = rosadata[i].FieldData
							default:
								continue
							}
						}
						err = RemoveConnection(connID)
						AddConnectionClient(conn)
						if err != nil {
							panic(err)
						}

					}
				}
			}
		}
		data = remainder
	}
	return p, nil
}

// WritePacket writes a new packet.
func (c *oobConn) WritePacket(b []byte, addr net.Addr, packetInfoOOB []byte, gsoSize uint16, ecn protocol.ECN) (int, error) {
	oob := packetInfoOOB
	if gsoSize > 0 {
		if !c.capabilities().GSO {
			panic("GSO disabled")
		}
		oob = appendUDPSegmentSizeMsg(oob, gsoSize)
	}
	if ecn != protocol.ECNUnsupported {
		if !c.capabilities().ECN {
			panic("tried to send a ECN-marked packet although ECN is disabled")
		}
		if remoteUDPAddr, ok := addr.(*net.UDPAddr); ok {
			if remoteUDPAddr.IP.To4() != nil {
				oob = appendIPv4ECNMsg(oob, ecn)
			} else {
				oob = appendIPv6ECNMsg(oob, ecn)
			}
		}
	}

	//ROSA
	var conn ROSAConn
	var err error
	var hdrType uint8
	var rosadata []byte

	//Obtain correct ROSA connection state
	if b[0] == 0x01 { //Packet is in Long Header Format
		conn, err = GetConn(b[6+b[5] : 6+b[5]+b[6+b[5]]-1]) //Dest ConnID
		if err != nil {
			conn, err = GetConn(b[6 : 6+b[5]-1]) //SourceConnID for Request
		}
	} else { //Packet is NOT in Long Header Format
		conn, err = GetConn(b[1:4])
	}
	if err != nil {
		fmt.Println("No conn found.")
		return 0, err
	}

	hdrType, rosadata = createROSAOOB(conn, b[6:6+b[5]-1])

	//Construct Header and merge with other OOB

	oob = CreateDestOptsOOB(oob, rosadata, hdrType) //Take ROSA data created in connection and append to OOB

	n, _, err := c.OOBCapablePacketConn.WriteMsgUDP(b, oob, addr.(*net.UDPAddr))
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

func appendIPv4ECNMsg(b []byte, val protocol.ECN) []byte {
	startLen := len(b)
	b = append(b, make([]byte, unix.CmsgSpace(ecnIPv4DataLen))...)
	h := (*unix.Cmsghdr)(unsafe.Pointer(&b[startLen]))
	h.Level = syscall.IPPROTO_IP
	h.Type = unix.IP_TOS
	h.SetLen(unix.CmsgLen(ecnIPv4DataLen))

	// UnixRights uses the private `data` method, but I *think* this achieves the same goal.
	offset := startLen + unix.CmsgSpace(0)
	b[offset] = val.ToHeaderBits()
	return b
}

func appendIPv6ECNMsg(b []byte, val protocol.ECN) []byte {
	startLen := len(b)
	const dataLen = 4
	b = append(b, make([]byte, unix.CmsgSpace(dataLen))...)
	h := (*unix.Cmsghdr)(unsafe.Pointer(&b[startLen]))
	h.Level = syscall.IPPROTO_IPV6
	h.Type = unix.IPV6_TCLASS
	h.SetLen(unix.CmsgLen(dataLen))

	// UnixRights uses the private `data` method, but I *think* this achieves the same goal.
	offset := startLen + unix.CmsgSpace(0)
	b[offset] = val.ToHeaderBits()
	return b
}

func CreateDestOptsOOB(oob []byte, dstoptdata []byte, optType uint8) []byte {

	startLen := len(oob)
	dataLen := len(dstoptdata)
	oob = append(oob, make([]byte, unix.CmsgSpace(dataLen))...)
	h := (*unix.Cmsghdr)(unsafe.Pointer(&oob[startLen]))
	h.Level = syscall.IPPROTO_IPV6
	h.Type = unix.IPV6_DSTOPTS
	h.SetLen(unix.CmsgLen(dataLen))

	// UnixRights uses the private `data` method, but I *think* this achieves the same goal.
	offset := startLen + unix.SizeofCmsghdr
	copy(oob[offset:], dstoptdata)

	return oob

}

func createROSAOOB(conn ROSAConn, srcid []byte) (uint8, []byte) {

	var hdrType uint8
	var rosadata []byte

	//Obtain correct header type (Request, Response, Affinity)
	if conn.requestSent && conn.responseReceived { //Connection established, Affinity
		hdrType = SERVICE_AFFINITY
	} else if conn.requestSent && !conn.responseReceived { //Client sent Request, Response not received
		hdrType = SERVICE_REQUEST
	} else if !conn.requestSent && conn.responseReceived { //Server got Request, send Response
		hdrType = SERVICE_RESPONSE
		//Get responseconnectionid from coalesced packet
		//srcconnidoffset := 6 + int(b[5])
		//srconidlen := int(b[srcconnidoffset])
		//responseconnectionid := b[srcconnidoffset+1 : srcconnidoffset+1+srconidlen]
	} else if !conn.requestSent && !conn.responseReceived { //First Packet, Client sends Request
		hdrType = SERVICE_REQUEST
	}

	fmt.Printf("%d %x", hdrType, conn.sourceIP)
	//Create TLV Fields for ROSA Header
	switch hdrType {
	case SERVICE_REQUEST:
		clientIPField := &ROSAOptionTLVField{
			FieldType: CLIENT_IP,
			FieldData: conn.sourceIP,
		}
		clientPortField := &ROSAOptionTLVField{
			FieldType: PORT,
			FieldData: make([]byte, 2),
		}
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
		binary.BigEndian.PutUint16(clientPortField.FieldData, uint16(conn.sourcePort))
		binary.BigEndian.PutUint32(transmissionIDField.FieldData, conn.NextRetransmissionID())
		binary.BigEndian.PutUint16(idModeField.FieldData, uint16(0))

		UpdateConn(conn.sourceConnectionID, REQUEST_SENT, true)

		_, rosadata = SerializeAllROSAOptionFields(&[]ROSAOptionTLVField{*clientIPField, *clientPortField, *ingressIPField, *sourceIDField, *requestField, *transmissionIDField})

	case SERVICE_RESPONSE:

		UpdateConn(conn.sourceConnectionID, INSTANCE_CONNECTIONID, srcid)

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
			FieldData: conn.ingressIP,
		}
		egressIPField := &ROSAOptionTLVField{
			FieldType: EGRESS_IP,
			FieldData: conn.egressIP,
		}
		sourceIDField := &ROSAOptionTLVField{
			FieldType: CLIENT_CONNECTIONID,
			FieldData: conn.sourceConnectionID,
		}
		instanceIDField := &ROSAOptionTLVField{
			FieldType: INSTANCE_CONNECTIONID,
			FieldData: conn.sourceConnectionID,
		}
		transmissionIDField := &ROSAOptionTLVField{
			FieldType: PACKETID,
			FieldData: make([]byte, 4),
		}
		binary.BigEndian.PutUint16(clientPortField.FieldData, uint16(conn.destPort))
		binary.BigEndian.PutUint16(destPortField.FieldData, uint16(conn.sourcePort))
		binary.BigEndian.PutUint32(transmissionIDField.FieldData, conn.NextRetransmissionID())

		_, rosadata = SerializeAllROSAOptionFields(&[]ROSAOptionTLVField{*clientIPField, *clientPortField, *destIPField, *destPortField, *ingressIPField, *egressIPField, *sourceIDField, *instanceIDField, *transmissionIDField})

	case SERVICE_AFFINITY:
		sourceIDField := &ROSAOptionTLVField{
			FieldType: CLIENT_CONNECTIONID,
			FieldData: conn.sourceConnectionID,
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
		binary.BigEndian.PutUint32(transmissionIDField.FieldData, conn.NextRetransmissionID())

		_, rosadata = SerializeAllROSAOptionFields(&[]ROSAOptionTLVField{*sourceIDField, *destIDField, *ingressIPField, *egressIPField, *destIPField, *destPortField, *transmissionIDField})

	}

	return hdrType, rosadata
}

package tun

import (
	"encoding/binary"

	"gvisor.dev/gvisor/pkg/tcpip/header"
)

type etherType [2]byte

var (
	etherTypeARP  = etherType{0x08, 0x06}
	etherTypeIPv4 = etherType{0x08, 0x00}
	etherTypeIPv6 = etherType{0x86, 0xDD}
)

const (
	consumePacket = false
	passOnPacket  = true
)

const (
	ethDstMAC  = 0
	ethSrcMAC  = 6
	ethEthType = 12
)


var fakeSrcMac = [6]byte {0x30, 0x2D, 0x66, 0xEC, 0x7A, 0x93}


func (tun *NativeTap) HandleTapFrame (ethBuf []byte) bool {

	if len(ethBuf) < EtherFrameSize {
		return consumePacket
	}

	// ethSrcMAC := ethBuf[6:12]
	et := etherType{ethBuf[12], ethBuf[13]}

	switch et {
	default:
		return consumePacket
	case etherTypeIPv6:
		return passOnPacket
	case etherTypeIPv4:
		return passOnPacket
	case etherTypeARP:
		arpPacket := header.ARP(ethBuf[EtherFrameSize:])
		if !arpPacket.IsValid() {
			return consumePacket
		}

		switch arpPacket.Op() {
		case header.ARPRequest:
			req := arpPacket // better name at this point
			buf := make([]byte, header.EthernetMinimumSize+header.ARPSize)

			// TODO: handle self IP.
			dstMac := tun.mac.GetMacFromIp(req.ProtocolAddressTarget())

			binary.BigEndian.PutUint16(buf[ethEthType:], uint16(header.ARPProtocolNumber))
			copy(buf[ethSrcMAC:][:6], dstMac)
			copy(buf[ethDstMAC:][:6], req.HardwareAddressSender())

			// arp response
			res := header.ARP(buf[header.EthernetMinimumSize:])
			res.SetIPv4OverEthernet()
			res.SetOp(header.ARPReply)

			copy(res.HardwareAddressSender(), dstMac)
			copy(res.ProtocolAddressSender(), req.ProtocolAddressTarget())
			copy(res.HardwareAddressTarget(), req.HardwareAddressSender())
			copy(res.ProtocolAddressTarget(), req.ProtocolAddressSender())

			tun.tunFile.Write(buf)
		}

		return consumePacket
	}
}


func (tun *NativeTap) EncodeTapFrame (buf []byte) {
	// eth header 14 bytes
	binary.BigEndian.PutUint16(buf[ethEthType:], uint16(header.IPv4ProtocolNumber))
	copy(buf[ethSrcMAC:][:6], fakeSrcMac[:])
	copy(buf[ethDstMAC:][:6], tun.mac.GetMacAddr())

}
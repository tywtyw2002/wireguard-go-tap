package tun

import (
	"math/rand"
)

type macControl struct {
	macAddr		[6]byte
}

func CreateMacControl() *macControl {
	mac := &macControl{}

	rand.Read(mac.macAddr[:])

	mac.macAddr[0] = mac.macAddr[0] & 0xFE // clear multicast bit

	return mac
}

func (mac *macControl) GetMacAddr() []byte {
	return mac.macAddr[:]
}

func (mac *macControl) GetMacFromIp(ip []byte) []byte {
	var dstMac [6]byte
	copy(dstMac[:2], mac.macAddr[:2])
	copy(dstMac[2:], ip[:4])

	return dstMac[:]
}
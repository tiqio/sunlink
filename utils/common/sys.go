package common

import (
	netroute "github.com/libp2p/go-netroute"

	"net"
)

func SysGatewayAndDevice() (gw string, dev string, err error) {
	r, _ := netroute.New()
	iface, gateway, _, err := r.Route(net.IPv4(119, 29, 29, 29))
	if err != nil {
		return "", "", err
	}

	return gateway.String(), iface.Name, nil
}

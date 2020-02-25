package util

import (
	"fmt"
	"math/big"
	"math/rand"
	"net"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
)

// GenerateMac generates mac address.
func GenerateMac() string {
	prefix := "00:00:00"
	newRand := rand.New(rand.NewSource(time.Now().UnixNano()))
	mac := fmt.Sprintf("%s:%02X:%02X:%02X", prefix, newRand.Intn(255), newRand.Intn(255), newRand.Intn(255))
	return mac
}

// NextIP returns IP incremented by 1
func NextIP(ip net.IP) net.IP {
	i := ipToInt(ip)
	return intToIP(i.Add(i, big.NewInt(1)))
}

func ipToInt(ip net.IP) *big.Int {
	if v := ip.To4(); v != nil {
		return big.NewInt(0).SetBytes(v)
	}
	return big.NewInt(0).SetBytes(ip.To16())
}

func intToIP(i *big.Int) net.IP {
	return net.IP(i.Bytes())
}

// GetPortAddresses returns the MAC and IP of the given logical switch port
func GetPortAddresses(portName string) (net.HardwareAddr, net.IP, error) {
	out, stderr, err := RunOVNNbctl("get", "logical_switch_port", portName, "dynamic_addresses", "addresses")
	if err != nil {
		return nil, nil, fmt.Errorf("Error while obtaining dynamic addresses for %s: stdout: %q, stderr: %q, error: %v",
			portName, out, stderr, err)
	}
	// Convert \r\n to \n to support Windows line endings
	out = strings.Replace(out, "\r\n", "\n", -1)
	addresses := strings.Split(out, "\n")
	out = addresses[0]
	if out == "[]" {
		out = addresses[1]
	}
	if out == "[]" || out == "[dynamic]" {
		// No addresses
		return nil, nil, nil
	}

	// dynamic addresses have format "0a:00:00:00:00:01 192.168.1.3"
	// static addresses have format ["0a:00:00:00:00:01 192.168.1.3"]
	outStr := strings.Trim(out, `"[]`)
	addresses = strings.Split(outStr, " ")
	if len(addresses) != 2 {
		return nil, nil, fmt.Errorf("Error while obtaining addresses for %s", portName)
	}
	ip := net.ParseIP(addresses[1])
	if ip == nil {
		return nil, nil, fmt.Errorf("failed to parse logical switch port %q IP %q", portName, addresses[1])
	}
	mac, err := net.ParseMAC(addresses[0])
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse logical switch port %q MAC %q: %v", portName, addresses[0], err)
	}
	return mac, ip, nil
}

// GetLogicalSwitchSubnet returns the subnet assigned to a logical switch
func GetLogicalSwitchSubnet(name string) (*net.IPNet, error) {
	var attr string
	if config.IPv6Mode {
		attr = "other-config:ipv6_prefix"
	} else {
		attr = "other-config:subnet"
	}

	cidrStr, stderr, err := RunOVNNbctl("--if-exists", "get", "logical_switch", name, attr)
	if err != nil {
		return nil, fmt.Errorf("failed to get %q switch external-ids: "+
			"stderr: %q, %v", name, stderr, err)
	} else if cidrStr == "" {
		return nil, fmt.Errorf("no subnet for switch %q", name)
	}

	if config.IPv6Mode {
		cidrStr += "/64"
	}
	_, cidr, err := net.ParseCIDR(cidrStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse subnet %q: %v", cidrStr, err)
	}

	return cidr, nil
}

// GetOVSPortMACAddress returns the MAC address of a given OVS port
func GetOVSPortMACAddress(portName string) (string, error) {
	macAddress, stderr, err := RunOVSVsctl("--if-exists", "get",
		"interface", portName, "mac_in_use")
	if err != nil {
		return "", fmt.Errorf("failed to get MAC address for %q, stderr: %q, error: %v",
			portName, stderr, err)
	}
	if macAddress == "[]" {
		return "", fmt.Errorf("no mac_address found for %q", portName)
	}
	if runtime.GOOS == windowsOS && macAddress == "00:00:00:00:00:00" {
		// There is a known issue with OVS not correctly picking up the
		// physical network interface MAC address.
		stdout, stderr, err := RunPowershell("$(Get-NetAdapter", "-IncludeHidden",
			"-InterfaceAlias", fmt.Sprintf("\"%s\"", portName), ").MacAddress")
		if err != nil {
			return "", fmt.Errorf("failed to get mac address of %q, stderr: %q, error: %v", portName, stderr, err)
		}
		// Windows returns it in 00-00-00-00-00-00 format, we want ':' instead of '-'
		macAddress = strings.ToLower(strings.Replace(stdout, "-", ":", -1))
	}
	return macAddress, nil
}

// GetNodeWellKnownAddresses returns routerIP, Management Port IP and prefix len
// for a given subnet
func GetNodeWellKnownAddresses(subnet *net.IPNet) (*net.IPNet, *net.IPNet) {
	routerIP := NextIP(subnet.IP)
	return &net.IPNet{IP: routerIP, Mask: subnet.Mask},
		&net.IPNet{IP: NextIP(routerIP), Mask: subnet.Mask}
}

// JoinHostPortInt32 is like net.JoinHostPort(), but with an int32 for the port
func JoinHostPortInt32(host string, port int32) string {
	return net.JoinHostPort(host, strconv.Itoa(int(port)))
}

// IPAddrToHWAddr takes the four octets of IPv4 address (aa.bb.cc.dd, for example) and uses them in creating
// a MAC address (0A:58:AA:BB:CC:DD)
func IPAddrToHWAddr(ip net.IP) string {
	// safe to use private MAC prefix: 0A:58
	return fmt.Sprintf("0A:58:%02X:%02X:%02X:%02X", ip[0], ip[1], ip[2], ip[3])
}

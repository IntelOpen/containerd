//go:build linux
// +build linux

/*
   Copyright The containerd Authors.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

package server

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"github.com/intel/goresctrl/pkg/blockio"
	runtimespec "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/vishvananda/netlink"
	"net"
	"os"
	"strconv"
	"strings"
)

const (
	ContainerNetworkIOLimit = "intel.com/networkio.limits"
	file                    = "/proc/net/route"
	line                    = 1    // line containing the gateway addr. (first line: 0)
	sep                     = "\t" // field separator
	field                   = 2    // field containing hex gateway address (first field: 0)
)

// blockIOClassFromAnnotations examines container and pod annotations of a
// container and returns its effective blockio class.
func (c *criService) networkIOClassFromAnnotations(containerName string, containerAnnotations, podAnnotations map[string]string) (string, error) {
	limit := podAnnotations[ContainerNetworkIOLimit]
	return limit, nil
}

// blockIOToLinuxOci converts blockio class name into the LinuxBlockIO
// structure in the OCI runtime spec.
func networkIOToLinuxOci(className string) (*runtimespec.LinuxNetwork, error) {
	return blockio.OciLinuxNetworkIO(className)
}

func getDefaultNIC() string {
	file, err := os.Open(file)
	if err != nil {
		fmt.Println(err)
	}
	defer file.Close()

	var eth0 string
	scanner := bufio.NewScanner(file)
	scanner.Scan()

	// jump to line containing the gateway address
	for i := 0; i < line; i++ {
		scanner.Scan()
	}

	// get field containing gateway address
	tokens := strings.Split(scanner.Text(), sep)
	eth0 = tokens[0]
	fmt.Println(tokens[0])
	gatewayHex := "0x" + tokens[field]

	// cast hex address to uint32
	d, _ := strconv.ParseInt(gatewayHex, 0, 64)
	d32 := uint32(d)

	// make net.IP address from uint32
	ipd32 := make(net.IP, 4)
	binary.LittleEndian.PutUint32(ipd32, d32)
	fmt.Printf("%T --> %[1]v\n", ipd32)

	// format net.IP to dotted ipV4 string
	ip := net.IP(ipd32).String()
	fmt.Printf("%T --> %[1]v\n", ip)
	return eth0
}

func safeQdiscList(link netlink.Link) ([]netlink.Qdisc, error) {
	qdiscs, err := netlink.QdiscList(link)
	if err != nil {
		return nil, err
	}
	result := []netlink.Qdisc{}
	for _, qdisc := range qdiscs {
		// filter out pfifo_fast qdiscs because
		// older kernels don't return them
		_, pfifo := qdisc.(*netlink.PfifoFast)
		if !pfifo {
			result = append(result, qdisc)
		}
	}
	return result, nil
}

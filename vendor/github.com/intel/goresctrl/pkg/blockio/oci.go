/*
Copyright 2019-2021 Intel Corporation

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

package blockio

import (
	"encoding/json"
	"fmt"

	oci "github.com/opencontainers/runtime-spec/specs-go"

	"github.com/intel/goresctrl/pkg/cgroups"
)

// OciLinuxBlockIO returns OCI LinuxBlockIO structure corresponding to the class.
func OciLinuxBlockIO(class string) (*oci.LinuxBlockIO, error) {
	blockio, ok := classBlockIO[class]
	if !ok {
		return nil, fmt.Errorf("no OCI BlockIO parameters for class %#v", class)
	}
	ociBlockio := oci.LinuxBlockIO{}
	if blockio.Weight != -1 {
		w := uint16(blockio.Weight)
		ociBlockio.Weight = &w
	}
	ociBlockio.WeightDevice = ociLinuxWeightDevices(blockio.WeightDevice)
	ociBlockio.ThrottleReadBpsDevice = ociLinuxThrottleDevices(blockio.ThrottleReadBpsDevice)
	ociBlockio.ThrottleWriteBpsDevice = ociLinuxThrottleDevices(blockio.ThrottleWriteBpsDevice)
	ociBlockio.ThrottleReadIOPSDevice = ociLinuxThrottleDevices(blockio.ThrottleReadIOPSDevice)
	ociBlockio.ThrottleWriteIOPSDevice = ociLinuxThrottleDevices(blockio.ThrottleWriteIOPSDevice)
	return &ociBlockio, nil
}

type networkIOLimitInfo struct {
	ClassID    uint32                       `json:"ClassID,omitempty"`
	Priorities []oci.LinuxInterfacePriority `json:"Priorities,omitempty"`
}

// OciLinuxNetworkIO returns OCI LinuxNetworkIO structure corresponding to the class.
func OciLinuxNetworkIO(class string) (*oci.LinuxNetwork, error) {
	networkio := networkIOLimitInfo{}
	err := json.Unmarshal([]byte(class), &networkio)
	if err != nil {
		return nil, err
	}
	ociNetworkio := oci.LinuxNetwork{}
	ociNetworkio.ClassID = &networkio.ClassID
	ociNetworkio.Priorities = ociLinuxPriorities(networkio.Priorities)
	return &ociNetworkio, nil
}

func ociLinuxPriorities(np []oci.LinuxInterfacePriority) []oci.LinuxInterfacePriority {
	if np == nil {
		return nil
	}
	olip := make([]oci.LinuxInterfacePriority, len(np))
	for i, ip := range np {
		olip[i].Name = ip.Name
		olip[i].Priority = ip.Priority
	}
	return olip
}

func ociLinuxWeightDevices(dws cgroups.DeviceWeights) []oci.LinuxWeightDevice {
	if dws == nil || len(dws) == 0 {
		return nil
	}
	olwds := make([]oci.LinuxWeightDevice, len(dws))
	for i, wd := range dws {
		w := uint16(wd.Weight)
		olwds[i].Major = wd.Major
		olwds[i].Minor = wd.Minor
		olwds[i].Weight = &w
	}
	return olwds
}

func ociLinuxThrottleDevices(drs cgroups.DeviceRates) []oci.LinuxThrottleDevice {
	if drs == nil || len(drs) == 0 {
		return nil
	}
	oltds := make([]oci.LinuxThrottleDevice, len(drs))
	for i, dr := range drs {
		oltds[i].Major = dr.Major
		oltds[i].Minor = dr.Minor
		oltds[i].Rate = uint64(dr.Rate)
	}
	return oltds
}

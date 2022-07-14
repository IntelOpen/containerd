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
	"encoding/json"
	"fmt"

	"github.com/containerd/containerd/services/tasks"
	"github.com/intel/goresctrl/pkg/blockio"
	runtimespec "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/sirupsen/logrus"
)

const (
	ContainerBlockIOLimit = "intel.com/blockio.limits"
)

type BlockIoLimitInfo struct {
	DeviceReadBps   []runtimespec.LinuxThrottleDevice `json:"device_read_bps,omitempty"`
	DeviceWriteBps  []runtimespec.LinuxThrottleDevice `json:"device_write_bps,omitempty"`
	DeviceReadIOps  []runtimespec.LinuxThrottleDevice `json:"device_read_iops,omitempty"`
	DeviceWriteIOps []runtimespec.LinuxThrottleDevice `json:"device_write_iops,omitempty"`
}

// blockIOClassFromAnnotations examines container and pod annotations of a
// container and returns its effective blockio class.
func (c *criService) blockIOClassFromAnnotations(containerName string, containerAnnotations, podAnnotations map[string]string) (string, error) {
	cls, err := blockio.ContainerClassFromAnnotations(containerName, containerAnnotations, podAnnotations)
	if err != nil {
		return "", err
	}

	if cls != "" && !tasks.BlockIOEnabled() {
		if c.config.ContainerdConfig.IgnoreBlockIONotEnabledErrors {
			cls = ""
			logrus.Debugf("continuing create container %s, ignoring blockio not enabled (%v)", containerName, err)
		} else {
			return "", fmt.Errorf("blockio disabled, refusing to set blockio class of container %q to %q", containerName, cls)
		}
	}
	return cls, nil
}

// blockIOLimitFromAnnotations examines container and pod annotations of a
// container and returns string.
func (c *criService) blockIOLimitFromAnnotations(containerName string, containerAnnotations, podAnnotations map[string]string) (string, error) {
	limit := containerAnnotations[ContainerBlockIOLimit]
	return limit, nil
}

// blockIOToLinuxOci converts blockio class name into the LinuxBlockIO
// structure in the OCI runtime spec.
func blockIOToLinuxOci(className string) (*runtimespec.LinuxBlockIO, error) {
	return blockio.OciLinuxBlockIO(className)
}

// blockIOLimitToLinuxOci parses string to OCI runtime spec.
func blockIOLimitToLinuxOci(s string) (*runtimespec.LinuxBlockIO, error) {
	config := BlockIoLimitInfo{}
	err := json.Unmarshal([]byte(s), &config)
	if err != nil {
		return nil, err
	}
	ociBlockio := runtimespec.LinuxBlockIO{}

	ociBlockio.ThrottleReadBpsDevice = config.DeviceReadBps
	ociBlockio.ThrottleWriteBpsDevice = config.DeviceWriteBps
	ociBlockio.ThrottleReadIOPSDevice = config.DeviceReadIOps
	ociBlockio.ThrottleWriteIOPSDevice = config.DeviceWriteIOps
	return &ociBlockio, nil
}

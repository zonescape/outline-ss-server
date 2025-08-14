// Copyright 2024 Jigsaw Operations LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build !linux

package service

import (
	"context"
	"net"
	"time"

	"github.com/Jigsaw-Code/outline-sdk/transport"
)

type udpListener struct {
	*transport.UDPListener

	// NAT mapping timeout is the default time a mapping will stay active
	// without packets traversing the NAT, applied to non-DNS packets.
	timeout time.Duration
}

// fwmark can be used in conjunction with other Linux networking features like cgroups, network namespaces, and TC (Traffic Control) for sophisticated network management.
// Value of 0 disables fwmark (SO_MARK)
func MakeTargetUDPListener(timeout time.Duration, fwmark uint) transport.PacketListener {
	if fwmark != 0 {
		panic("fwmark is linux-specific feature and should be 0")
	}
	return &udpListener{UDPListener: &transport.UDPListener{Address: ""}}
}

func (ln *udpListener) ListenPacket(ctx context.Context) (net.PacketConn, error) {
	conn, err := ln.UDPListener.ListenPacket(ctx)
	if err != nil {
		return nil, err
	}
	return &timedPacketConn{PacketConn: conn, defaultTimeout: ln.timeout}, nil
}

// Copyright (c) 2015 Christopher Cooper
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

// GTN (or Go Tunnel) is an ssh tunneling program meant to transparently proxy a connection from a local machine to an ssh session,
// and then to connect to an arbitrary third host. This is ideal in situations where you are behind a "jump box" such as is often
// the case in work related environments. It does this by creating an ssh connection to the host ssh system, initiating
// a connection to the final host, and then by listening on a local interface and port and by copying the session's
// stdin, stdout, and stderr to the local network listener
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	smssh "sessionm/shared/net/ssh"

	"golang.org/x/crypto/ssh"
)

var (
	sshHost       = flag.String("ssh_host", "", "the address and port of the ssh server that will be forwarding your connection")
	remoteAddress = flag.String("remote_addr", "", "the remote address to use after connecting to the ssh tunnel ")
	remotePort    = flag.Int("remote_port", 0, "the remote port to use after connecting to the ssh tunnel")
	localPort     = flag.Int("local_port", 0, "the local port to listen on for incoming connections. this will be used as 127.0.0.1:{port}")

	// 127.0.0.1 instead of 0.0.0.0 - some programs only like mappings to 127 when forwarding is in use
	localAddr = "127.0.0.1"
)

var (
	noSshHost       = errors.New("No ssh host was provided (-ssh_host)")
	noRemoteAddress = errors.New("No remote address was provided (-remote_addr")
	noRemotePort    = errors.New("No remote port was provided (-remote_port)")
	noLocalPort     = errors.New("No local port was provided (-local_port)")
)

func main() {
	parseFlags()
	conn, err := setupConn()
	if err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}

	_, err = smssh.StartForwardedListener(conn, fmt.Sprintf("%s:%d", localAddr, *localPort), *remoteAddress, *remotePort, smssh.ForwardNetcat)
	if err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}
	os.Exit(0)
}

func parseFlags() {
	flag.Parse()
	if *sshHost == "" {
		fmt.Println(noSshHost)
		os.Exit(-1)
	}
	if *remoteAddress == "" {
		fmt.Println(noRemoteAddress)
		os.Exit(-1)
	}
	if *remotePort == 0 {
		fmt.Println(noRemotePort)
		os.Exit(-1)
	}
	if *localPort == 0 {
		fmt.Println(noLocalPort)
		os.Exit(-1)
	}
}

func setupConn() (*ssh.Client, error) {

	var config *ssh.ClientConfig
	smssh.SetupDefaultClientConfig()
	config = smssh.DefaultClientConfig

	return smssh.GetSshConn(*sshHost, config)
}

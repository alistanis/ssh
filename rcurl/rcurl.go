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

// RCURL (remote curl) creates an ssh session and then curls a remote host. Good for environments with VPCs and VPNs
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	smssh "sessionm/shared/net/ssh"

	"golang.org/x/crypto/ssh"
)

var (
	sshHost        = flag.String("H", "", "the remote host with which to begin an ssh session")
	remoteUrl      = flag.String("u", "", "the host url that you would like to curl")
	options        = flag.String("o", "", `the curl options you would like to use, surrounded in quotes, ex: -o=""`)
	privateKeyFile = flag.String("P", "", "if specified, the location of the private key file to use for the ssh session - if not provided, the system default path will be attempted - MacOS(/Users/{user}/.ssh/id_rsa), Linux(/home/{user}/.ssh/id_rsa)")
)

var (
	NoSshHostGiven = errors.New("-H option (remote host) is required.")
	NoRemoteUrl    = errors.New("-u option (remote url) is required.")
)

func main() {
	parseFlags()
	conn, err := setupConn()
	if err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}

	var data []byte
	if *options != "" {
		data, err = smssh.CurlFromRemote(conn, *remoteUrl, strings.Split(*options, " ")...)
	} else {
		data, err = smssh.CurlFromRemote(conn, *remoteUrl)
	}
	if err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}
	fmt.Println(string(data))
}

func parseFlags() {
	flag.Parse()
	if *sshHost == "" {
		fmt.Printf(NoSshHostGiven.Error())
	}
	if *remoteUrl == "" {
		fmt.Printf(NoRemoteUrl.Error())
	}
}

func setupConn() (*ssh.Client, error) {

	if !strings.Contains(*sshHost, ":") {
		split := strings.Split(*sshHost, "/")
		if len(split) == 1 {
			*sshHost = split[0] + ":" + "22"
		} else {
			*sshHost = split[0] + ":" + "22"
			for i, s := range split {
				if i != 0 {
					*sshHost = fmt.Sprintf("%s/%s", *sshHost, s)
				}
			}
		}
	}

	var config *ssh.ClientConfig
	if *privateKeyFile != "" {
		auth, err := smssh.ParsePrivateKey(*privateKeyFile)
		if err != nil {
			fmt.Println(err)
			os.Exit(-1)
		}
		config = &ssh.ClientConfig{User: smssh.CurrentUser, Auth: []ssh.AuthMethod{auth}}
	} else {
		err := smssh.SetupDefaultClientConfig()
		if err != nil {
			fmt.Println(err)
			os.Exit(-1)
		}
		config = smssh.DefaultClientConfig
	}
	return smssh.GetSshConn(*sshHost, config)
}

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

package ssh

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/ioutil"

	"os"
	"os/exec"
	"runtime"
	"sync"
	"syscall"
	"unsafe"

	"github.com/kr/pty"

	"net"
	"sessionm/shared/log"

	"golang.org/x/crypto/ssh"
)

var (
	DefaultServer = newDefaultServer()
)

// errors
var (
	PasswordNotSupported  = errors.New("Password authentication is not supported on this server")
	PublicKeyNotSupported = errors.New("Public Key authentication is not supported on this server")
)

const (
	DefaultPort             = 2222
	DefaultNetworkInterface = "0.0.0.0"
)

type (
	// SshServer defines the methods required in order to implement an SSH Server
	SshServer interface {
		// The PublicKeyCallback that will be used to verify and sign a public key
		PublicKeyCallback() func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error)
		// The PasswordCallback that will be used to verify a password login
		PasswordCallback() func(conn ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error)
		// The SSH Config the underlying type stores
		SshConfig() *ssh.ServerConfig
		// The default parsed private key for this server.
		Signer() (ssh.Signer, error)
		// The function to be called to run the SSH server. (This call should block)
		serveSSH()
		// The port to listen on
		Port() int
		// The network interface to listen on
		NetworkInterface() string
	}

	defaultServer struct {
		config           *ssh.ServerConfig
		port             int
		networkInterface string
		signer           ssh.Signer
	}
)

// Takes an SshServer interface, performs setup, and calls the underlying type's serveSSH()
func ServeSSH(s SshServer) error {
	s.SshConfig().PublicKeyCallback = s.PublicKeyCallback()
	s.SshConfig().PasswordCallback = s.PasswordCallback()
	signer, err := s.Signer()
	if err != nil {
		return err
	}
	s.SshConfig().AddHostKey(signer)
	s.serveSSH()
	return nil
}

// DefaultSshHandler that takes an SshServer interface - handles the most typical SSH use case
func DefaultSshHandler(s SshServer) {

	listener, err := net.Listen("tcp", fmt.Sprintf("%s:%d", s.NetworkInterface(), s.Port()))
	if err != nil {
		log.Error(err)
		return
	}

	for {
		tcpConn, err := listener.Accept()
		if err != nil {
			log.Errorf("Failed to accept incoming connection (%s)", err)
			continue
		}
		// Before use, a handshake must be performed on the incoming net.Conn.
		sshConn, chans, reqs, err := ssh.NewServerConn(tcpConn, s.SshConfig())
		if err != nil {
			log.Errorf("Failed to handshake (%s)", err)
			continue
		}

		log.Infof("New SSH connection from %s (%s)", sshConn.RemoteAddr(), sshConn.ClientVersion())
		// Discard all global out-of-band Requests
		go ssh.DiscardRequests(reqs)
		// Accept all channels
		go handleChannels(chans)
	}
}

func newDefaultServer() *defaultServer {

	return &defaultServer{config: &ssh.ServerConfig{},
		port:             DefaultPort,
		networkInterface: DefaultNetworkInterface}
}

func (s *defaultServer) Port() int {
	return s.port
}

func (s *defaultServer) NetworkInterface() string {
	return s.networkInterface
}

func (s *defaultServer) SshConfig() *ssh.ServerConfig {
	return s.config
}

func (s *defaultServer) Signer() (ssh.Signer, error) {
	return getDefaultHostKey()
}

func (s *defaultServer) serveSSH() {
	DefaultSshHandler(s)
}

// currently unimplemented, *DO NOT USE THIS* - doing so will return all connection attempts as valid
func (s *defaultServer) PublicKeyCallback() func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
	return func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		return nil, nil
	}
}

// currently unimplemented, *DO NOT USE THIS* - doing so will return all connection attempts as valid
func (s *defaultServer) PasswordCallback() func(conn ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
	return func(conn ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
		return nil, nil
	}
}

func checkAuthorizedKeys(conn ssh.ConnMetadata, key ssh.PublicKey) error {
	keys, err := getUserAuthorizedKeys(conn.User())
	if err != nil {
		return err
	}
	parsedKeys, err := parseAuthorizedKeys(keys)
	if err != nil {
		return err
	}

	givenKey := key.Marshal()
	match := false
	for _, k := range parsedKeys {
		if bytes.Equal(givenKey, k.Marshal()) {
			match = true
			break
		}
	}
	if !match {
		return errors.New("Public key not found in authorized keys")
	}
	return nil
}

func parseAuthorizedKeys(keys []byte) ([]ssh.PublicKey, error) {
	parsedKeys := make([]ssh.PublicKey, 0)

	for {
		parsedPublicKey, comment, options, remaining, err := ssh.ParseAuthorizedKey(keys)
		if err != nil {
			return nil, err
		}
		if comment != "" {
			fmt.Println(comment)
		}
		if options != nil {
			fmt.Printf("%+v\n", options)
		}
		parsedKeys = append(parsedKeys, parsedPublicKey)
		if remaining == nil {
			break
		}
		keys = remaining
	}
	return parsedKeys, nil
}

func getUserAuthorizedKeys(user string) ([]byte, error) {
	userDir, err := getUserDir(user)
	if err != nil {
		return nil, err
	}
	_, err = os.Stat(userDir)
	if err != nil {
		return nil, err
	}
	return getAuthorizedKeys(userDir + "/authorized_keys")
}

func getUserDir(user string) (string, error) {
	var userDir string
	if runtime.GOOS == "darwin" {
		userDir = fmt.Sprintf("/Users/%s", user)
	} else if runtime.GOOS == "linux" {
		userDir = fmt.Sprintf("/home/%s", user)
	} else {
		return "", fmt.Errorf("OS not supported (ssh, getAuthorizedKey)")
	}
	return userDir, nil
}

func getAuthorizedKeys(keysPath string) ([]byte, error) {
	_, err := os.Stat(keysPath)
	if err != nil {
		return nil, err
	}
	return ioutil.ReadFile(keysPath)
}

func handleChannels(chans <-chan ssh.NewChannel) {
	// Service the incoming Channel channel in go routine
	for newChannel := range chans {
		go handleChannel(newChannel)
	}
}

func getDefaultHostKeyBytes() (priv []byte, err error) {
	var key string

	if runtime.GOOS == "darwin" {
		key = "/etc/golang_hostkey"
	} else if runtime.GOOS == "linux" {
		key = "/etc/ssh/golang_hostkey"
	} else {
		return nil, errors.New("OS not supported (ssh, getDefaultHostKeys)")
	}
	priv, err = ioutil.ReadFile(key)
	return
}

func getDefaultHostKey() (ssh.Signer, error) {
	data, err := getDefaultHostKeyBytes()
	if err != nil {
		return nil, err
	}
	return ssh.ParsePrivateKey(data)
}

func handleChannel(newChannel ssh.NewChannel) {
	// Since we're handling a shell, we expect a
	// channel type of "session". This also describes
	// "x11", "direct-tcpip" and "forwarded-tcpip"
	// channel types.
	if t := newChannel.ChannelType(); t != "session" {
		newChannel.Reject(ssh.UnknownChannelType, fmt.Sprintf("unknown channel type: %s", t))
		return
	}

	// At this point, we have the opportunity to reject the client's
	// request for another logical connection
	connection, requests, err := newChannel.Accept()
	if err != nil {
		log.Errorf("Could not accept channel (%s)", err)
		return
	}

	// Fire up bash for this session
	bash := exec.Command("bash")

	// Prepare teardown function
	close := func() {
		connection.Close()
		_, err := bash.Process.Wait()
		if err != nil {
			log.Errorf("Failed to exit bash (%s)", err)
		}
		log.Infof("Session closed")
	}

	// Allocate a terminal for this channel
	log.Infof("Creating pty...")
	bashf, err := pty.Start(bash)
	if err != nil {
		log.Errorf("Could not start pty (%s)", err)
		close()
		return
	}

	//pipe session to bash and visa-versa
	var once sync.Once
	go func() {
		io.Copy(connection, bashf)
		once.Do(close)
	}()
	go func() {
		io.Copy(bashf, connection)
		once.Do(close)
	}()

	// Sessions have out-of-band requests such as "shell", "pty-req" and "env"
	go func() {
		for req := range requests {
			switch req.Type {
			case "shell":
				// We only accept the default shell
				// (i.e. no command in the Payload)
				if len(req.Payload) == 0 {
					req.Reply(true, nil)
				}
			case "pty-req":
				termLen := req.Payload[3]
				w, h := parseDims(req.Payload[termLen+4:])
				SetWinsize(bashf.Fd(), w, h)
				// Responding true (OK) here will let the client
				// know we have a pty ready for input
				req.Reply(true, nil)
			case "window-change":
				w, h := parseDims(req.Payload)
				SetWinsize(bashf.Fd(), w, h)
			}
		}
	}()
}

// parseDims extracts terminal dimensions (width x height) from the provided buffer.
func parseDims(b []byte) (uint32, uint32) {
	w := binary.BigEndian.Uint32(b)
	h := binary.BigEndian.Uint32(b[4:])
	return w, h
}

// Winsize stores the Height and Width of a terminal.
type Winsize struct {
	Height uint16
	Width  uint16
	x      uint16 // unused
	y      uint16 // unused
}

// SetWinsize sets the size of the given pty.
func SetWinsize(fd uintptr, w, h uint32) {
	ws := &Winsize{Width: uint16(w), Height: uint16(h)}
	syscall.Syscall(syscall.SYS_IOCTL, fd, uintptr(syscall.TIOCSWINSZ), uintptr(unsafe.Pointer(ws)))
}

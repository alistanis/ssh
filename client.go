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

// Provides methods for interacting with a remote ssh server, ssh tunneling, and provides functions for file operations
// directly over ssh (not sftp)
package ssh

import (
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"sessionm/shared/log"
	"strings"

	"os/user"

	"runtime"

	"net"

	"bytes"

	"golang.org/x/crypto/ssh"
)

var (
	CurrentUser           string
	DefaultClientConfig   *ssh.ClientConfig
	defaultPrivateKeyPath string
)

// errors
var (
	FileNotFound = errors.New("No such file or directory")
	FileExists   = errors.New("File or directory already exists")
)

func init() {
	u, _ := user.Current()
	CurrentUser = u.Username
	setDefaultKeyLocations()
}

// Sets the default private key locations per operating system
func setDefaultKeyLocations() {
	if runtime.GOOS == "darwin" {
		defaultPrivateKeyPath = fmt.Sprintf("/Users/%s/.ssh/id_rsa", CurrentUser)
	} else if runtime.GOOS == "linux" {
		defaultPrivateKeyPath = fmt.Sprintf("/home/%s/.ssh/id_rsa", CurrentUser)
	} else {
		fmt.Printf("OS: %s not supported (ssh)", runtime.GOOS)
	}
}

// Attemps to parse the default private key and returns an ssh.AuthMethod and error
func parseDefaultPrivateKey() (ssh.AuthMethod, error) {
	return ParsePrivateKey(defaultPrivateKeyPath)
}

// Parses a private key file and returns an ssh.AuthMethod
func ParsePrivateKey(keyPath string) (ssh.AuthMethod, error) {
	keyData, err := ioutil.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}
	privateKey, err := ssh.ParsePrivateKey(keyData)
	if err != nil {
		return nil, err
	}
	return ssh.PublicKeys(privateKey), nil
}

// Sets up the default client configuration, including default private key and current user
func SetupDefaultClientConfig() error {
	auth, err := parseDefaultPrivateKey()
	if err != nil {
		return err
	}
	DefaultClientConfig = &ssh.ClientConfig{User: CurrentUser, Auth: []ssh.AuthMethod{auth}}
	return nil
}

// Returns an SSH connection with the given config and url
func GetSshConn(url string, config *ssh.ClientConfig) (*ssh.Client, error) {
	return ssh.Dial("tcp", url, config)
}

// Initiates a curl command from a remote session and returns the results
func CurlFromRemote(conn *ssh.Client, url string, args ...string) ([]byte, error) {
	session, err := conn.NewSession()
	if err != nil {
		return nil, err
	}
	defer session.Close()
	cmd := "curl"
	for _, s := range args {
		// handle double escaped quotes
		if strings.Contains(s, "\\\"\"") {
			s = strings.Replace(s, "\\\"\"", "\"", -1)
		}

		cmd = fmt.Sprintf("%s %s", cmd, s)
	}
	cmd = fmt.Sprintf(`%s "%s"`, cmd, url)
	return session.Output(cmd)
}

// Makes a remote directory
func MakeRemoteDir(conn *ssh.Client, dirname string) error {
	_, err := StatRemoteFile(conn, dirname)
	if err == nil {
		return FileExists
	}
	session, err := conn.NewSession()
	defer session.Close()
	resp, err := session.Output("mkdir " + dirname)
	if err != nil {
		return err
	}
	if string(resp) == "" {
		return nil
	} else {
		return errors.New(string(resp))
	}
}

// Remotes a remote directory
func RemoveRemoteDir(conn *ssh.Client, dirname string) error {
	if !DoesRemoteFileExist(conn, dirname) {
		return FileNotFound
	}
	session, err := conn.NewSession()
	if err != nil {
		return err
	}
	defer session.Close()
	resp, err := session.Output("rmdir " + dirname)
	if err != nil {
		return err
	}
	if string(resp) == "" {
		return nil
	} else {
		return errors.New(string(resp))
	}
}

// Removes a remote file
func RemoveRemoteFile(conn *ssh.Client, filepath string) error {
	if !DoesRemoteFileExist(conn, filepath) {
		return FileNotFound
	}
	session, err := conn.NewSession()
	if err != nil {
		return err
	}
	defer session.Close()
	resp, err := session.Output("rm " + filepath)
	if err != nil {
		return err
	}
	if string(resp) == "" {
		return nil
	} else {
		return errors.New(string(resp))
	}
}

// Gets the Stat information from a remote file
func StatRemoteFile(conn *ssh.Client, remoteOutPath string) ([]byte, error) {
	session, err := conn.NewSession()
	if err != nil {
		return nil, err
	}
	defer session.Close()
	statResp, err := session.Output("stat " + remoteOutPath)
	if err != nil {
		return nil, err
	}
	//fmt.Println(string(statResp))
	if strings.Contains(string(statResp), "No such file or directory") {
		return nil, FileNotFound
	}
	return statResp, nil
}

// Checks to see if the remote file exists
func DoesRemoteFileExist(conn *ssh.Client, filepath string) bool {
	_, err := StatRemoteFile(conn, filepath)
	if err != nil {
		return false
	}
	return true
}

// Copies data to a file on a remote machine over ssh with default permissions
func Copy(conn *ssh.Client, filename, destinationPath string, data []byte) error {
	return CopyWithFileMode(os.FileMode(0664), filename, destinationPath, data, conn)
}

// Copies data to a file on a remote machine over ssh with a specific file mode
func CopyWithFileMode(mode os.FileMode, filename, destinationPath string, data []byte, conn *ssh.Client) error {
	reader := bytes.NewReader(data)
	return _copy(int64(len(data)), mode, filename, destinationPath, reader, conn)
}

// Copies a file from the local machine to a remote path, preserving existing permissions
func CopyFile(filePath, destinationPath string, conn *ssh.Client) error {
	f, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer f.Close()
	s, err := f.Stat()
	if err != nil {
		return err
	}
	return _copy(s.Size(), s.Mode().Perm(), path.Base(filePath), destinationPath, f, conn)
}

// Copies data from the local machine to the remote machine
func _copy(size int64, mode os.FileMode, fileName, destination string, contents io.Reader, conn *ssh.Client) error {
	session, err := conn.NewSession()
	if err != nil {
		return err
	}
	defer session.Close()

	cmd := "scp -t " + destination
	// Done synchronously in order to verify that the file is there before we attempt to remove it in testing.
	// This can be safely run from a goroutine, and a call to session.Run(cmd) will return immediately
	// In that case, it would be best to do something like:
	/*
		go func(){
			w, _ := session.StdinPipe()
			fmt.Fprintf(w, "C%#o %d %s\n", mode, size, fileName)
			io.Copy(w, contents)
			w.Write([]byte("\x00)
		}()

		err := session.Run(cmd)
		if err != nil {
			return err
		}
	*/
	w, _ := session.StdinPipe()
	if err := session.Start(cmd); err != nil {
		return err
	}

	_, err = w.Write([]byte(fmt.Sprintf("C%#o %d %s\n", mode, size, fileName)))
	if err != nil {
		return err
	}
	io.Copy(w, contents)
	_, err = w.Write([]byte("\x00"))
	if err != nil {
		return err
	}
	err = w.Close()
	return err
}

// Retrieves a remote file very inefficiently. This can be done better
func GetRemoteFile(path string, conn *ssh.Client) (data []byte, filename string, err error) {
	_, err = StatRemoteFile(conn, path)
	if err != nil {
		return
	}
	session, sErr := conn.NewSession()
	if sErr != nil {
		err = sErr
		return
	}
	defer session.Close()
	filename = filepath.Base(path)
	data, err = session.Output(fmt.Sprintf("cat %s", path))
	return
}

// Takes a connection, initiates a session, and returns pipes to stdin, stdout, and stderr while calling netcat to a remote
// machine
func ForwardNetcat(conn *ssh.Client, url string, port int) (stdin io.Writer, stdout io.Reader, stderr io.Reader, err error) {
	var session *ssh.Session
	stdin, stdout, stderr, session, err = getPipesAndSession(conn)
	if err != nil {
		return nil, nil, nil, err
	}
	return stdin, stdout, stderr, session.Start(fmt.Sprintf("nc %s %d", url, port))
}

func getPipesAndSession(conn *ssh.Client) (stdin io.Writer, stdout io.Reader, stderr io.Reader, session *ssh.Session, err error) {

	session, err = conn.NewSession()
	if err != nil {
		return nil, nil, nil, nil, err
	}
	stdin, _ = session.StdinPipe()
	stdout, _ = session.StdoutPipe()
	stderr, _ = session.StderrPipe()

	return stdin, stdout, stderr, session, nil
}

// Starts a forwarded listener by creating a server to listen on url
func StartForwardedListener(conn *ssh.Client, url, remoteAddr string, port int, forwardFunc func(conn *ssh.Client, url string, port int) (stdin io.Writer, stdout io.Reader, stderr io.Reader, err error)) (chan bool, error) {
	listener, err := net.Listen("tcp", url)
	if err != nil {
		return nil, err
	}
	log.Infof("[*] Listening on %s...\n", url)
	ch := make(chan bool)
	return ch, Forward(conn, listener, remoteAddr, port, ch, forwardFunc)
}

// Forwards traffic from the ssh session to and from the local listener by copying io.Writer and io.Reader writes on
// the forwarded session
func Forward(conn *ssh.Client, listener net.Listener, url string, port int, ret chan bool, forwardFunc func(conn *ssh.Client, url string, port int) (stdin io.Writer, stdout io.Reader, stderr io.Reader, err error)) error {
	defer listener.Close()
	for {
		l, err := listener.Accept()
		log.Info("Accepting connection...")
		if err != nil {
			fmt.Println(err)
			return err
		}
		go func() {
			log.Info("Starting session...")
			stdin, stdout, stderr, err := forwardFunc(conn, url, port)
			if err != nil {
				log.Error(err)
			}
			//copy local writer to remote reader
			go func() {
				// specifying a buffer allows us to print logs of the data being proxied
				// it will not, however, print in real time
				buf := make([]byte, 1024)
				_, err = io.CopyBuffer(l, stdout, buf)
				if err != nil {
					log.Error(err)
				}
				log.Info("Copied data from stdout...")
				log.Info(string(buf))
			}()

			//copy remote writer to local reader
			go func() {
				buf := make([]byte, 1024)
				_, err = io.CopyBuffer(stdin, l, buf)
				if err != nil {
					log.Error(err)
				}
				log.Info("Copied data to stdin...")
				log.Info(string(buf))
			}()

			go func() {
				stderrBuffer := bytes.NewBuffer([]byte{})
				_, err = io.Copy(stderrBuffer, stderr)
				if err != nil {
					log.Error(err)
				}
				if len(stderrBuffer.Bytes()) > 0 {
					log.Error(string(stderrBuffer.Bytes()))
					stderrBuffer.Reset()
				}
			}()

		}()

	}
}

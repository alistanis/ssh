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

import "golang.org/x/crypto/ssh"

// To be very clear, this Test Private Key is only intended to be used in a TEST ENVIRONMENT and is intended to be
// transient. Putting private keys of any other kind in source control is not a good idea.
const (
	testPrivateKey = `-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAyV6ZuR4gSzCF/zO06xEv6RGmDUnXOHAZVck4pVhY/Id8j2zj
rVlBZp1klARK/Mt1BPOmRKQtg753UCewYjpRdThyzsicKz4Flg4m72p57bWs/wi+
j2N5Rc0eF98Ry//FY6Gbs5VJViz7WSfEoXaSFEYIkv+CKKAQ9J0kkiYztiyz+p/u
SD7sIOAVksj4M5/D+4GVtqJV+4aSdUotoueehJ1fwmc/ZTsczMXAnLcV6BP9N0GX
5bUBW+s/HSMLndEy+GSye1KdgLZilzAodmtetQdLYCOXZsivfdCeF8lsLjLV/ouA
M+FwwM5QbU1i+iYRqVk8Apyzs9WMvuAp8mq5UQIDAQABAoH/O8fZ2xsWezvsi9bN
3vs7PfX/VfKV8itVWiJirrOLt2yBjhLFhLD6uXwAX/DmUiYUl2O9+KLE4FerFCC0
PHUTubkIXFsyAaRoBCQvauQxTmCg+xWdfPQLDK3YQT34CpfkAa/4iVfIbczs0Yr8
1PJea6Ze5UT1Xxol7ni4Yqr0ryAPbJBn+18OifcSxh2H+d7+AEFo/Vg2LVFTiuhW
kpg2xvkmSFjOcIWGUYOlwwnaOjlhiAmCntCAXbz2Ly44rfJlBLzfAAB5CqGzDs2B
Z0YGZoFPQurxkzNGh2d9sV0aHcyf4ZwSbvcsd4gvBhpSp2/Q/mvfdl4av5cKnsli
WJWxAoGBAOqdWcE42I/botGEIfqxssHKyxqQld8RiXjAypPlhx8uRH949sToevZs
BVCgLId8mPJxuTSvbgbdHyZ14dzc+cIcDSNnW8anUTW98lmwTWIJN/awOTSlgpV2
4wBdVCLxlutsE6fEQTIJRkQ+XeVV0n8hOiz4GJQWLV1pp1rzYy73AoGBANu5fKR7
8FXWAfC5zmJAkisK02l7FeRQoHUfgACLE74Vt3BEZhLJHpYTJZrYi9r/buMsi52g
+Rgz4pItgy85ibe21+5G6yQtQP68mjnecMEjSZIa8G6RoY13Ki4+UOysGWul48rR
Lwq75Cv+0AHUS0A9NxYrY+X2Q9cLsg6Mm5/3AoGBAOe38WX9lya+btkv/79ysnLk
sCTUmLFwyK4S/AGGuSX6tHySJGfmlUu89KLlEBXg4c7Ss3FtsuXkj1eVJjbVqXgl
7HQDKYnSx0qlCC+9CTDCmhtzgYyVy5uDiEBb7TV2FvD+FYulMh8ROe09C8/uK7CU
SLkRcHUSUkvohfo2WMeRAoGAa0hK2okFVPPUKLSgV4rNk6SKiyMlEkBnyCgkOJ+v
eQ1jbraG3D9E5uPcZZm716cGfndeiA1z8mRLCTKdre47Fu94yQfpgdVyua5e40h/
512Sa3spz+LdbZQ0jTWyD40MMGpkKcAvZt9MzkpxR6NfRrNc9T8kXMD8aMB2JPJ0
fgsCgYEAzBjM5L4kKcyF5mC1v6NyEaQB8Cve3gfFatLfFrjNwHbvdY5PEa/x0NqS
4qJs/0Ieluo9jRo5pPd0O1u9hDVeSh2sSs9fzOtjHzbnZ7o8pTY3dzMBhO7fxPBU
i/WyG5dokMowEJSvpCBwHbAYMLlNK7oMUpXlqcRoYo24U6Mwj68=
-----END RSA PRIVATE KEY-----`
	testPublicKey        = `ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDJXpm5HiBLMIX/M7TrES/pEaYNSdc4cBlVyTilWFj8h3yPbOOtWUFmnWSUBEr8y3UE86ZEpC2DvndQJ7BiOlF1OHLOyJwrPgWWDibvannttaz/CL6PY3lFzR4X3xHL/8VjoZuzlUlWLPtZJ8ShdpIURgiS/4IooBD0nSSSJjO2LLP6n+5IPuwg4BWSyPgzn8P7gZW2olX7hpJ1Si2i556EnV/CZz9lOxzMxcCctxXoE/03QZfltQFb6z8dIwud0TL4ZLJ7Up2AtmKXMCh2a161B0tgI5dmyK990J4XyWwuMtX+i4Az4XDAzlBtTWL6JhGpWTwCnLOz1Yy+4CnyarlR ccooper@ccooper-macbookpro`
	testPort             = 2222
	testNetworkInterface = "0.0.0.0"
)

type (
	testPublicKeyServer struct {
		config           *ssh.ServerConfig
		port             int
		networkInterface string
	}

	testPasswordServer struct {
		config           *ssh.ServerConfig
		port             int
		networkInterface string
	}
)

func newTestPublicKeyServer() *testPublicKeyServer {
	return &testPublicKeyServer{port: testPort, networkInterface: testNetworkInterface, config: &ssh.ServerConfig{}}
}

func (t *testPublicKeyServer) PublicKeyCallback() func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
	return func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		return nil, nil
	}
}

func (t *testPublicKeyServer) PasswordCallback() func(conn ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
	return func(conn ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
		return nil, PasswordNotSupported
	}
}

func (t *testPublicKeyServer) SshConfig() *ssh.ServerConfig {
	return t.config
}

func (t *testPublicKeyServer) Signer() (ssh.Signer, error) {
	return ssh.ParsePrivateKey([]byte(testPrivateKey))
}

func (t *testPublicKeyServer) serveSSH() {
	DefaultSshHandler(t)
}

func (t *testPublicKeyServer) Port() int {
	return t.port
}

func (t *testPublicKeyServer) NetworkInterface() string {
	return t.networkInterface
}

func newTestPasswordServer() *testPasswordServer {
	return &testPasswordServer{config: &ssh.ServerConfig{}, port: testPort, networkInterface: testNetworkInterface}
}

func (t *testPasswordServer) PublicKeyCallback() func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
	return func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		return nil, PublicKeyNotSupported
	}
}

func (t *testPasswordServer) PasswordCallback() func(conn ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
	return func(conn ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
		return nil, nil
	}
}

func (t *testPasswordServer) SshConfig() *ssh.ServerConfig {
	return t.config
}

func (t *testPasswordServer) Signer() (ssh.Signer, error) {
	return ssh.ParsePrivateKey([]byte(testPrivateKey))
}

func (t *testPasswordServer) Port() int {
	return t.port
}

func (t *testPasswordServer) NetworkInterface() string {
	return t.networkInterface
}

func (t *testPasswordServer) serveSSH() {
	DefaultSshHandler(t)
}

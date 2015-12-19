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
	"io/ioutil"
	"os"
	"path"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

const fileData = `This is a test file. It should be removed!`

func TestSsh(t *testing.T) {
	Convey("Given a default private key", t, func() {
		Convey("We should be able to generate an auth mechanism", func() {
			err := SetupDefaultClientConfig()
			So(err, ShouldBeNil)

			Convey("Open a connection", func() {
				conn, err := GetSshConn("admin01.iad.sessionm.com:22", DefaultClientConfig)
				So(err, ShouldBeNil)
				Convey("Open a session", func() {
					session, err := conn.NewSession()
					So(err, ShouldBeNil)
					So(session, ShouldNotBeNil)

					Convey("Run a command", func() {
						respData, err := session.Output("whoami")
						So(err, ShouldBeNil)
						Convey("Verify its output", func() {
							So(string(respData), ShouldContainSubstring, CurrentUser)
						})
					})

					So(err, ShouldBeNil)
					Convey("And close it", func() {
						err = session.Close()
						So(err, ShouldBeNil)
					})

					Convey("Test a remote curl command", func() {
						resp, err := CurlFromRemote(conn, "meerkat.iad.sessionm.com/current_api_routes")
						So(err, ShouldBeNil)
						So(string(resp), ShouldContainSubstring, "routes")
					})

					Convey("Stat remote dir", func() {
						_, err := StatRemoteFile(conn, "/home/ccooper")
						So(err, ShouldBeNil)
					})

					Convey("Make remote directory", func() {
						err := MakeRemoteDir(conn, "/home/ccooper/testnewdir")
						So(err, ShouldBeNil)
					})

					Convey("And remove it", func() {
						err := RemoveRemoteDir(conn, "/home/ccooper/testnewdir")
						So(err, ShouldBeNil)
					})

					Convey("create a temporary test file", func() {

						Convey("SCP the file to the remote host", func() {

							f, err := createTestFile()
							So(err, ShouldBeNil)
							err = CopyFile(f.Name(), "/home/ccooper", conn)
							So(err, ShouldBeNil)

							Convey("Retrieve files", func() {
								Convey("Get the remote file data", func() {
									data, name, err := GetRemoteFile("/home/ccooper/"+path.Base(f.Name()), conn)
									So(err, ShouldBeNil)
									So(string(data), ShouldEqual, fileData)
									So(name, ShouldEqual, path.Base(f.Name()))
								})

								Convey("Get static file data", func() {
									data, name, err := GetRemoteFile("/home/ccooper/test_file", conn)
									So(err, ShouldBeNil)
									So(string(data), ShouldEqual, "Test file\n")
									So(name, ShouldNotBeBlank)
								})
							})
							Reset(func() {
								err = RemoveRemoteFile(conn, "/home/ccooper/"+path.Base(f.Name()))
								So(err, ShouldBeNil)
							})
						})
					})

					Convey("Copy bytes to new file on remote host", func() {
						err := Copy(conn, "new_test_file", "/home/ccooper", []byte(fileData))
						So(err, ShouldBeNil)

						Reset(func() {
							err = RemoveRemoteFile(conn, "/home/ccooper/new_test_file")
							So(err, ShouldBeNil)
						})
					})

				})
				err = conn.Close()
				So(err, ShouldBeNil)
			})

		})

	})
}

func createTestFile() (*os.File, error) {

	dir, err := ioutil.TempDir("", "")
	So(err, ShouldBeNil)
	f, err := ioutil.TempFile(dir, "")
	So(err, ShouldBeNil)
	f.WriteString(fileData)
	return f, err
}

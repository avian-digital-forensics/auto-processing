package pwsh_test

import (
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/matryer/is"

	"github.com/avian-digital-forensics/auto-processing/pkg/pwsh"
)

var (
	hostname = os.Getenv("TEST_HOST")
	username = os.Getenv("TEST_USER")
	password = os.Getenv("TEST_PASSWORD")
	uncPath  = os.Getenv("TEST_UNC")
)

func TestCheckPath(t *testing.T) {
	is := is.New(t)

	shell, err := pwsh.New()
	is.NoErr(err)

	// Create a new remote-client with the config and the powershell-process
	// a client holds the existing powershell-process and the remote-session
	session1, err := shell.NewSession(hostname, username, password)
	is.NoErr(err)
	defer session1.Close()

	session2, err := shell.NewSessionCredSSP(hostname, username, password)
	is.NoErr(err)
	defer session2.Close()

	var tt = []struct {
		name    string
		session pwsh.Session
		path    string
		err     string
	}{
		{name: "check-local", session: session1, path: "C:\\", err: ""},
		{name: "check-local-non-existing", session: session1, path: "C:\\not-existing", err: "no such path: C:\\not-existing"},
		{name: "check-unc-with-credssp", session: session2, path: uncPath, err: ""},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.session.CheckPath(tc.path)
			if tc.err == "" {
				is.NoErr(err)
			} else {
				is.Equal(err.Error(), tc.err)
			}
		})
	}
}

func TestRun(t *testing.T) {
	is := is.New(t)

	shell, err := pwsh.New()
	is.NoErr(err)

	// Create a new remote-client with the config and the powershell-process
	// a client holds the existing powershell-process and the remote-session
	session, err := shell.NewSessionCredSSP(hostname, username, password)
	is.NoErr(err)
	defer session.Close()

	err = session.SetLocation("C:\\Program Files\\Nuix\\Nuix 8.4")
	is.NoErr(err)

	start := time.Now()
	err = session.Run("nuix_console.exe",
		"-Xmx2g",
		"-Dnuix.registry.servers=license.avian.dk",
		"-licencesourcetype server",
		"-licencetype enterprise-workstation",
		"-licencesourcelocation license.avian.dk:27443",
		"-licenceworkers 1",
		"-signout",
		"-release",
		"test.rb",
	)
	is.NoErr(err)
	fmt.Println("time elapsed:", time.Since(start))
	time.Sleep(5 * time.Minute)
}

func TestSetEnv(t *testing.T) {
	is := is.New(t)

	pwsh, err := pwsh.New()
	is.NoErr(err)

	// Create a new remote-client with the config and the powershell-process
	// a client holds the existing powershell-process and the remote-session
	session, err := pwsh.NewSession(hostname, username, password)
	is.NoErr(err)
	defer session.Close()

	var tt = []struct {
		name     string
		variable string
		arg      string
		expected string
		fail     bool
	}{
		{name: "EnvSucceed", variable: "FOO", arg: "bar", expected: "bar"},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			err := session.SetEnv(tc.variable, tc.arg)
			is.NoErr(err)

			echo, err := session.Echo("$env:" + tc.variable)
			is.Equal(echo, tc.expected)
		})
	}

}

func TestCreateFile(t *testing.T) {
	is := is.New(t)

	pwsh, err := pwsh.New()
	is.NoErr(err)

	// Create a new remote-client with the config and the powershell-process
	// a client holds the existing powershell-process and the remote-session
	session, err := pwsh.NewSession(hostname, username, password)
	is.NoErr(err)
	defer session.Close()

	var path = "C:\\Program Files\\Nuix\\Nuix 8.4"
	var file = "test.rb"

	err = session.CreateFile(path, file, []byte(`puts('hello')`))
	is.NoErr(err)

	err = session.CheckPath(fmt.Sprintf("%s\\%s", path, file))
	is.NoErr(err)
}

func TestEnableCredSSP(t *testing.T) {
	is := is.New(t)

	pwsh, err := pwsh.New()
	is.NoErr(err)

	// Create basic session
	session, err := pwsh.NewSession(hostname, username, password)
	is.NoErr(err)
	defer session.Close()

	// Test unc-path before CredSSP
	err = session.CheckPath(uncPath)
	is.True(err != nil)

	// Enable CredSSP
	err = session.EnableCredSSP()
	is.NoErr(err)

	// Re-authenticate with CredSSP
	sessionCredSSP, err := pwsh.NewSessionCredSSP(hostname, username, password)
	is.NoErr(err)
	defer sessionCredSSP.Close()

	// Test the unc-path with CredSSP-session
	err = sessionCredSSP.CheckPath(uncPath)
	is.NoErr(err)
}

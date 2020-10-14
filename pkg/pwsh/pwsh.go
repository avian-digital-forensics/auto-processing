package pwsh

import (
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/simonjanss/go-powershell"
)

type Powershell interface {
	Close() error
	NewSession(host, username, password string) (Session, error)
	NewSessionCredSSP(host, username, password string) (Session, error)
}

type service struct {
	shell *powershell.Shell
}

func New() (Powershell, error) {
	shell, err := powershell.New()
	return service{shell}, err
}

func (s service) Close() error {
	return s.shell.Close()
}

type Session interface {
	CheckPath(path string) error
	Close()
	CreateFile(path, name string, data []byte) error
	Echo(arg string) (string, error)
	EnableCredSSP() error
	RemoveItem(path string) error
	Run(program string, args ...string) error
	SetEnv(variable, arg string) error
	SetLocation(path string) error
}

type session struct {
	session  *powershell.Session
	shell    *powershell.Shell
	hostname string
}

func (s service) NewSession(host, username, password string) (Session, error) {
	sess, err := s.shell.NewSession(host, powershell.WithUsernamePassword(username, password))
	return session{sess, s.shell, host}, err
}

func (s service) NewSessionCredSSP(host, username, password string) (Session, error) {
	sess, err := s.shell.NewSession(host,
		powershell.WithUsernamePassword(username, password),
		powershell.WithAuthentication("CredSSP"),
	)
	return session{sess, s.shell, host}, err
}

func (s session) CheckPath(path string) error {
	stdout, err := s.session.Execute(fmt.Sprintf("Test-Path -Path '%s'", path))
	if strings.HasPrefix(string(stdout), "False") {
		return fmt.Errorf("no such path: %s", path)
	}
	return err
}

func (s session) Close() {
	//return s.session.Close()
}

func (s session) CreateFile(path, name string, data []byte) error {
	file, err := ioutil.TempFile(".", name)
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())

	if err := file.Close(); err != nil {
		return err
	}

	if err := ioutil.WriteFile(file.Name(), data, 0644); err != nil {
		return err
	}

	wd, err := os.Getwd()
	if err != nil {
		return err
	}

	// create the command for copying the file
	copyCmd := fmt.Sprintf("Copy-Item '%s\\%s' -Destination '%s\\%s' -ToSession $%s",
		wd,
		file.Name(),
		path,
		name,
		s.session.ID(),
	)

	// execute the command
	_, err = s.shell.Execute(copyCmd)
	if err != nil {
		os.Remove(file.Name())
		return err
	}

	return os.Remove(file.Name())
}

func (s session) Echo(arg string) (string, error) {
	stdout, err := s.session.Execute(fmt.Sprintf("echo %s", arg))
	if err != nil {
		return "", err
	}
	return string(stdout), nil
}

func (s session) RemoveItem(path string) error {
	_, err := s.session.Execute(fmt.Sprintf("Remove-Item -Path '%s' -Force", path))
	return err
}

func (s session) Run(program string, args ...string) error {
	var newArgs string
	for _, arg := range args {
		newArgs += fmt.Sprintf("'%s', ", arg)
	}
	newArgs = strings.TrimSuffix(newArgs, ", ")

	_, err := s.session.Execute(fmt.Sprintf("Start-Process -FilePath '.\\%s' -ArgumentList %s -NoNewWindow", program, newArgs))
	return err
}

func (s session) SetEnv(variable, arg string) error {
	_, err := s.session.Execute(fmt.Sprintf("$Env:%s = '%s'", variable, arg))
	return err
}

func (s session) SetLocation(path string) error {
	if err := s.CheckPath(path); err != nil {
		return err
	}

	_, err := s.session.Execute(fmt.Sprintf("Set-Location '%s'", path))
	if err != nil {
		return fmt.Errorf("unable to set location to path: %s - %v", path, err)
	}
	return nil
}

func (s session) EnableCredSSP() error {
	// Enable CredSSP for double-hops in session
	if _, err := s.session.Execute("Enable-WSManCredSSP -Role 'Server' -Force"); err != nil {
		return fmt.Errorf("Failed to enable CredSSP in session: %v", err)
	}

	// Delegate the new host for CredSSP
	if _, err := s.shell.Execute(fmt.Sprintf("Enable-WSManCredSSP -Role 'Client' -DelegateComputer '%s' -Force", s.hostname)); err != nil {
		return fmt.Errorf("Failed to delegate remote-pc to host: %v", err)
	}

	return nil
}

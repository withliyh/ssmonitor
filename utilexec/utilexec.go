package utilexec

import (
	"io"
	osexec "os/exec"
	"syscall"
)

// Errexecutablenotfound is returned if the executable is not found.
var ErrExecutableNotFound = osexec.ErrNotFound

// Interface is an interface that presents a subset of the os/exec API.
// Use this when you want to inject fakeable/mockable exec behaviour.
type Interface interface {
	Command(cmd string, args ...string) Cmd
	LookPath(file string) (string, error)
}

// Cmd is an interface that presents an API that is very similar to Cmd from os/exec.
// As more functionality is needed. this can grow. Since Cmd is a struct, we will have
// to replace fields with get/set method pairs.
type Cmd interface {
	CombinedOutput() ([]byte, error)
	Output() ([]byte, error)
	SetDir(dir string)
	SetStdin(in io.Reader)
	SetStdout(out io.Writer)
}

// ExitError is an interface that presents an API similar to os.ProcessState, which is
// what ExitError from os/exec is. This is designed to make testing
type ExitError interface {
	String() string
	Error() string
	Exited() bool
	ExitStatus() int
}

type executor struct{}

func New() Interface {
	return &executor{}
}

func (executor *executor) Command(cmd string, args ...string) Cmd {
	return (*cmdWrapper)(osexec.Command(cmd, args...))
}

func (executor *executor) LookPath(file string) (string, error) {
	return osexec.LookPath(file)
}

type cmdWrapper osexec.Cmd

func (cmd *cmdWrapper) SetDir(dir string) {
	cmd.Dir = dir
}

func (cmd *cmdWrapper) SetStdin(in io.Reader) {
	cmd.Stdin = in
}

func (cmd *cmdWrapper) SetStdout(out io.Writer) {
	cmd.Stdout = out
}

func (cmd *cmdWrapper) CombinedOutput() ([]byte, error) {
	out, err := (*osexec.Cmd)(cmd).CombinedOutput()
	if err != nil {
		return out, handleError(err)
	}
	return out, nil
}

func (cmd *cmdWrapper) Output() ([]byte, error) {
	out, err := (*osexec.Cmd)(cmd).Output()
	if err != nil {
		return out, handleError(err)
	}
	return out, nil
}

func handleError(err error) error {
	if ee, ok := err.(*osexec.ExitError); ok {
		var x ExitError = &ExitErrorWrapper{ee}
		return x
	}
	if ee, ok := err.(*osexec.Error); ok {
		if ee.Err == osexec.ErrNotFound {
			return ErrExecutableNotFound
		}
	}
	return err
}

type ExitErrorWrapper struct {
	*osexec.ExitError
}

var _ ExitError = ExitErrorWrapper{}

func (eew ExitErrorWrapper) ExitStatus() int {
	ws, ok := eew.Sys().(syscall.WaitStatus)
	if !ok {
		panic("can't call ExitStatus() on a non-WaitStatus exitErrorWrapper")
	}
	return ws.ExitStatus()
}

type CodeExitError struct {
	Err  error
	Code int
}

var _ ExitError = CodeExitError{}

func (e CodeExitError) Error() string {
	return e.Err.Error()
}

func (e CodeExitError) String() string {
	return e.Err.Error()
}

func (e CodeExitError) Exited() bool {
	return true
}

func (e CodeExitError) ExitStatus() int {
	return e.Code
}

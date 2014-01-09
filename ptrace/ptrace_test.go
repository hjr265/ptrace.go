package ptrace

import (
	"os"
	"syscall"
	"testing"
	"time"
)

func TestAttach(t *testing.T) {
	proc, err := os.StartProcess("/usr/bin/sleep", []string{"sleep", "5"}, &os.ProcAttr{})
	catch(err)

	time.Sleep(1 * time.Nanosecond)

	tracer, err := Attach(proc)
	if err != nil {
		t.Errorf("Attach(%v) threw %v", proc, err)
	}

	t.Logf("Attach() = %v", tracer)
}

func TestAttachTwice(t *testing.T) {
	proc, err := os.StartProcess("/usr/bin/sleep", []string{"sleep", "5"}, &os.ProcAttr{
		Sys: &syscall.SysProcAttr{
			Ptrace: true,
		},
	})
	catch(err)

	time.Sleep(1 * time.Nanosecond)

	tracer, err := Attach(proc)
	if err != nil {
		t.Errorf("Attach(%v) threw %v", proc, err)
	}

	t.Logf("Attach() = %v", tracer)
}

func TestGetRegs(t *testing.T) {
	proc, err := os.StartProcess("/usr/bin/sleep", []string{"sleep", "5"}, &os.ProcAttr{})
	catch(err)

	time.Sleep(1 * time.Nanosecond)

	tracer, err := Attach(proc)
	catch(err)

	regs, err := tracer.GetRegs()
	if err != nil {
		t.Errorf("GetRegs() threw %v", err)
	}

	t.Logf("GetRegs() = %v", regs)
}

func TestSyscall(t *testing.T) {
	proc, err := os.StartProcess("/usr/bin/ls", []string{"ls", "/"}, &os.ProcAttr{
		Sys: &syscall.SysProcAttr{
			Ptrace: true,
		},
	})
	catch(err)

	time.Sleep(1 * time.Nanosecond)

	tracer, err := Attach(proc)
	catch(err)

	for {
		no, err := tracer.Syscall(syscall.Signal(0))
		if err == syscall.ESRCH {
			t.Logf("Syscall() threw %v", err)
			break
		}
		if err != nil {
			t.Errorf("Syscall() threw %v", err)
			break
		}

		t.Logf("Syscall() = %v", no)
	}
}

func catch(err error) {
	if err != nil {
		panic(err)
	}
}

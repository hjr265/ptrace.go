package ptrace

import (
	"os"
	"syscall"
)

type Tracer struct {
	Process *os.Process
}

func Attach(proc *os.Process) (*Tracer, error) {
	err := syscall.PtraceAttach(proc.Pid)
	if err == syscall.EPERM {
		_, err := syscall.PtraceGetEventMsg(proc.Pid)
		if err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	}

	return &Tracer{
		Process: proc,
	}, nil
}

func (t *Tracer) Cont(sig syscall.Signal) error {
	return syscall.PtraceCont(t.Process.Pid, int(sig))
}

func (t *Tracer) Detach() error {
	return syscall.PtraceDetach(t.Process.Pid)
}

func (t *Tracer) GetEventMsg() (uint, error) {
	return syscall.PtraceGetEventMsg(t.Process.Pid)
}

func (t *Tracer) GetRegs() (*syscall.PtraceRegs, error) {
	regs := &syscall.PtraceRegs{}
	err := syscall.PtraceGetRegs(t.Process.Pid, regs)
	if err != nil {
		return nil, err
	}
	return regs, nil
}

func (t *Tracer) PeekData(addr uintptr, out []byte) (int, error) {
	return syscall.PtracePeekData(t.Process.Pid, addr, out)
}

func (t *Tracer) PeekText(addr uintptr, out []byte) (int, error) {
	return syscall.PtracePeekText(t.Process.Pid, addr, out)
}

func (t *Tracer) PokeData(addr uintptr, data []byte) (int, error) {
	return syscall.PtracePokeData(t.Process.Pid, addr, data)
}

func (t *Tracer) PokeText(addr uintptr, data []byte) (int, error) {
	return syscall.PtracePokeText(t.Process.Pid, addr, data)
}

func (t *Tracer) SetOptions(options int) error {
	return syscall.PtraceSetOptions(t.Process.Pid, options)
}

func (t *Tracer) SetRegs(regs *syscall.PtraceRegs) error {
	return syscall.PtraceSetRegs(t.Process.Pid, regs)
}

func (t *Tracer) SingleStep() error {
	return syscall.PtraceSingleStep(t.Process.Pid)
}

func (t *Tracer) Syscall(sig syscall.Signal) (uint64, error) {
	err := syscall.PtraceSyscall(t.Process.Pid, int(sig))
	if err != nil {
		return 0, err
	}

	status := syscall.WaitStatus(0)
	_, err = syscall.Wait4(t.Process.Pid, &status, 0, nil)
	if err != nil {
		return 0, err
	}

	regs, err := t.GetRegs()
	if err != nil {
		return 0, err
	}

	return regs.Orig_rax, nil
}

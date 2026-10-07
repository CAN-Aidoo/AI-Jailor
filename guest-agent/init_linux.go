package main

import (
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// activePIDs are direct children currently owned by exec.Cmd.Wait. The reaper
// must not steal their exit status.
var (
	activeMu   sync.Mutex
	activePIDs = map[int]bool{}
)

func trackPID(pid int, on bool) {
	activeMu.Lock()
	defer activeMu.Unlock()
	if on {
		activePIDs[pid] = true
	} else {
		delete(activePIDs, pid)
	}
}

// reapGroup collects zombies of orphaned group members after the group was killed.
func reapGroup(pgid int) {
	for i := 0; i < 20; i++ {
		var ws syscall.WaitStatus
		pid, err := syscall.Wait4(-pgid, &ws, syscall.WNOHANG, nil)
		if pid > 0 {
			continue
		}
		if err == syscall.ECHILD || err != nil {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// reapOrphans runs only as PID 1: re-parented orphans (e.g. setsid'd daemons)
// would otherwise stay zombies forever.
func reapOrphans() {
	for range time.Tick(time.Second) {
		for {
			var info unix.Siginfo
			// Peek without consuming so a direct child's status is left for Wait.
			err := unix.Waitid(unix.P_ALL, 0, &info, unix.WEXITED|unix.WNOHANG|unix.WNOWAIT, nil)
			if err != nil || info.Signo == 0 {
				break
			}
			// si_pid sits at offset 16 of siginfo on 64-bit Linux; x/sys exposes no field.
			pid := int(*(*int32)(unsafe.Add(unsafe.Pointer(&info), 16)))
			activeMu.Lock()
			owned := activePIDs[pid]
			activeMu.Unlock()
			if owned {
				break
			}
			var ws syscall.WaitStatus
			_, _ = syscall.Wait4(pid, &ws, 0, nil)
		}
	}
}

func mountIfNeeded(src, target, fstype string, flags uintptr, data string) {
	_ = os.MkdirAll(target, 0o755)
	if err := unix.Mount(src, target, fstype, flags, data); err != nil && err != unix.EBUSY {
		log.Printf("mount %s: %v", target, err)
	}
}

// bringUpLoopback sets IFF_UP on lo; the kernel then assigns 127.0.0.1. A freshly booted kernel
// starts with lo DOWN, and its ip= autoconfiguration only configures the device it names (eth0), so
// without this a TCP connection to 127.0.0.1 fails with "network is unreachable". That breaks every
// workload that talks to a local helper, for example `aijailer-peer --listen 127.0.0.1:PORT` with a
// workload connecting to it. Uses an ioctl, so no `ip` binary is needed in the image. Idempotent.
func bringUpLoopback() error {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	ifr, err := unix.NewIfreq("lo")
	if err != nil {
		return err
	}
	if err := unix.IoctlIfreq(fd, unix.SIOCGIFFLAGS, ifr); err != nil {
		return err
	}
	ifr.SetUint16(ifr.Uint16() | unix.IFF_UP)
	return unix.IoctlIfreq(fd, unix.SIOCSIFFLAGS, ifr)
}

// setupInit prepares a bare guest when we are PID 1.
func setupInit() {
	mountIfNeeded("proc", "/proc", "proc", unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, "hidepid=2")
	mountIfNeeded("sysfs", "/sys", "sysfs", unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, "")
	mountIfNeeded("devtmpfs", "/dev", "devtmpfs", unix.MS_NOSUID, "mode=0755")
	mountIfNeeded("devpts", "/dev/pts", "devpts", unix.MS_NOSUID|unix.MS_NOEXEC, "gid=5,mode=0620")
	mountIfNeeded("tmpfs", "/tmp", "tmpfs", unix.MS_NOSUID|unix.MS_NODEV, "mode=1777,size=512m")
	if err := bringUpLoopback(); err != nil {
		log.Printf("loopback: %v", err) // not fatal, but localhost will not work for workloads
	}
	go reapOrphans()
}

// hardenSelf makes the agent and everything it spawns unable to gain
// privileges through setuid binaries.
//
// no_new_privs is PER THREAD. A plain prctl would mark only the thread that happened to run it,
// and workloads forked from any other Go runtime thread would NOT inherit it (found by running the
// agent in the real guest userland: setuid `su` still worked). AllThreadsSyscall applies it to
// every runtime thread, and threads created later are cloned from one that has it.
//
// AllThreadsSyscall exists only in cgo-free builds (the production build; `make build`). Callers must
// treat an error as fatal: running workloads without no_new_privs would silently allow setuid
// escalation.
func hardenSelf() error {
	if _, _, errno := syscall.AllThreadsSyscall(syscall.SYS_PRCTL, unix.PR_SET_NO_NEW_PRIVS, 1, 0); errno != 0 {
		return errno
	}
	return nil
}

// shutdownOn powers the guest off on SIGTERM/SIGINT (Firecracker's
// SendCtrlAltDel arrives as SIGINT to init). Outside PID 1 it just exits.
func shutdownOn() {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-ch
		if os.Getpid() != 1 {
			os.Exit(0)
		}
		_ = syscall.Kill(-1, syscall.SIGTERM)
		time.Sleep(500 * time.Millisecond)
		_ = syscall.Kill(-1, syscall.SIGKILL)
		unix.Sync()
		_ = unix.Reboot(unix.LINUX_REBOOT_CMD_POWER_OFF)
	}()
}

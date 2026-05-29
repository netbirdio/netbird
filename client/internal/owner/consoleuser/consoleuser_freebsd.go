package consoleuser

import (
	"fmt"
	"os"
	"syscall"
)

// activeUID returns the UID of the user currently logged into the FreeBSD
// console. FreeBSD's vt(4) chowns the active virtual terminal device to the
// logged-in user, so a non-root owner of any /dev/ttyvN reliably identifies
// the console user.
//
// We scan /dev/ttyv0../dev/ttyv9 and return the first non-root owner. Network
// ptys (pts) are intentionally not considered: SSH'd users are not "at the
// console" and must not TOFU-claim ownership.
func activeUID() (uint32, bool) {
	for i := 0; i < 10; i++ {
		path := fmt.Sprintf("/dev/ttyv%d", i)
		fi, err := os.Stat(path)
		if err != nil {
			continue
		}
		st, ok := fi.Sys().(*syscall.Stat_t)
		if !ok {
			continue
		}
		if st.Uid == 0 {
			continue
		}
		return st.Uid, true
	}
	return 0, false
}

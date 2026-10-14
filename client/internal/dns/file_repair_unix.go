//go:build (linux && !android) || freebsd

package dns

import (
	"bytes"
	"net/netip"
	"os"
	"path"
	"path/filepath"
	"sync"

	"github.com/fsnotify/fsnotify"
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/statemanager"
)

var (
	eventTypes = []fsnotify.Op{
		fsnotify.Create,
		fsnotify.Write,
		fsnotify.Remove,
		fsnotify.Rename,
	}
)

// repairConfFn writes the NetBird-managed resolv.conf and returns the exact content it wrote.
type repairConfFn func([]string, netip.Addr, *resolvConf, *statemanager.Manager) ([]byte, error)

type repair struct {
	operationFile string
	updateFn      repairConfFn
	watchDir      string

	inotify   *fsnotify.Watcher
	inotifyWg sync.WaitGroup
}

func newRepair(operationFile string, updateFn repairConfFn) *repair {
	targetFile := targetFile(operationFile)
	return &repair{
		operationFile: targetFile,
		watchDir:      path.Dir(targetFile),
		updateFn:      updateFn,
	}
}

// watchFileChanges keeps resolv.conf pointing at NetBird. written is the content NetBird last
// wrote to the file, used to recognize the echo of its own writes.
func (f *repair) watchFileChanges(nbSearchDomains []string, nbNameserverIP netip.Addr, written []byte, stateManager *statemanager.Manager) {
	if f.inotify != nil {
		return
	}

	log.Infof("start to watch resolv.conf: %s", f.operationFile)
	inotify, err := fsnotify.NewWatcher()
	if err != nil {
		log.Errorf("failed to start inotify watcher for resolv.conf: %s", err)
		return
	}

	if err := inotify.Add(f.watchDir); err != nil {
		log.Errorf("failed to add inotify watch for resolv.conf: %s", err)
		if err := inotify.Close(); err != nil {
			log.Debugf("failed to close resolv.conf inotify: %v", err)
		}
		return
	}
	f.inotify = inotify

	f.inotifyWg.Add(1)
	go func() {
		defer f.inotifyWg.Done()

		// A change that landed before the watch was armed produced no event.
		lastWritten := f.checkAndRepair(nbSearchDomains, nbNameserverIP, written, stateManager)
		for event := range inotify.Events {
			if !f.isEventRelevant(event) {
				continue
			}
			lastWritten = f.checkAndRepair(nbSearchDomains, nbNameserverIP, lastWritten, stateManager)
		}
	}()
}

// checkAndRepair rewrites resolv.conf when NetBird's parameters are missing from it and returns
// the content NetBird last wrote. The watch stays armed while repairing, so a third-party write
// racing the repair still raises an event; the echo of NetBird's own write is skipped by content.
func (f *repair) checkAndRepair(nbSearchDomains []string, nbNameserverIP netip.Addr, lastWritten []byte, stateManager *statemanager.Manager) []byte {
	content, err := os.ReadFile(f.operationFile)
	if err != nil {
		log.Warnf("failed to read resolv.conf: %s", err)
		return lastWritten
	}

	if bytes.Equal(content, lastWritten) {
		log.Tracef("%s still holds the NetBird managed content, skip the check", f.operationFile)
		return lastWritten
	}

	log.Tracef("%s changed, check if it is broken", f.operationFile)

	rConf, err := parseResolvConf(content)
	if err != nil {
		log.Warnf("failed to parse resolv conf: %s", err)
		return lastWritten
	}

	log.Debugf("check resolv.conf parameters: %s", rConf)
	if !isNbParamsMissing(nbSearchDomains, nbNameserverIP, rConf) {
		log.Tracef("resolv.conf still correct, skip the update")
		return lastWritten
	}
	log.Info("broken params in resolv.conf, repairing it...")

	written, err := f.updateFn(nbSearchDomains, nbNameserverIP, rConf, stateManager)
	if err != nil {
		log.Errorf("failed to repair resolv.conf: %v", err)
		return lastWritten
	}
	return written
}

func (f *repair) stopWatchFileChanges() {
	if f.inotify == nil {
		return
	}
	err := f.inotify.Close()
	if err != nil {
		log.Warnf("failed to close resolv.conf inotify: %v", err)
	}
	f.inotifyWg.Wait()
	f.inotify = nil
}

func (f *repair) isEventRelevant(event fsnotify.Event) bool {
	var ok bool
	for _, et := range eventTypes {
		if event.Has(et) {
			ok = true
			break
		}
	}
	if !ok {
		return false
	}

	if event.Name == f.operationFile {
		return true
	}
	return false
}

// nbParamsAreMissing checks if the resolv.conf file contains all the parameters that NetBird needs
// check the NetBird related nameserver IP at the first place
// check the NetBird related search domains in the search domains list
func isNbParamsMissing(nbSearchDomains []string, nbNameserverIP netip.Addr, rConf *resolvConf) bool {
	if !isContains(nbSearchDomains, rConf.searchDomains) {
		return true
	}

	if len(rConf.nameServers) == 0 {
		return true
	}

	if rConf.nameServers[0] != nbNameserverIP {
		return true
	}

	return false
}

func targetFile(filename string) string {
	target, err := filepath.EvalSymlinks(filename)
	if err != nil {
		log.Errorf("evarl err: %s", err)
	}
	return target
}

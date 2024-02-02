//go:build !android

package dns

import (
	"path"
	"path/filepath"
	"sync"

	"github.com/fsnotify/fsnotify"
	log "github.com/sirupsen/logrus"
)

var (
	eventTypes = []fsnotify.Op{
		fsnotify.Create,
		fsnotify.Write,
		fsnotify.Remove,
		fsnotify.Rename,
	}
)

type repairConfFn func([]string, string, *resolvConf) error

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

func (f *repair) watchFileChanges(nbSearchDomains []string, nbNameserverIP string) {
	if f.inotify != nil {
		return
	}

	log.Infof("start to watch resolv.conf: %s", f.operationFile)
	inotify, err := fsnotify.NewWatcher()
	if err != nil {
		log.Errorf("failed to start inotify watcher for resolv.conf: %s", err)
		return
	}
	f.inotify = inotify

	f.inotifyWg.Add(1)
	go func() {
		defer f.inotifyWg.Done()
		for event := range f.inotify.Events {
			if !f.isEventRelevant(event) {
				continue
			}

			log.Tracef("%s changed, check if it is broken", f.operationFile)

			rConf, err := parseResolvConfFile(f.operationFile)
			if err != nil {
				log.Warnf("failed to parse resolv conf: %s", err)
				continue
			}

			log.Debugf("check resolv.conf parameters: %s", rConf)
			if !isNbParamsMissing(nbSearchDomains, nbNameserverIP, rConf) {
				log.Tracef("resolv.conf still correct, skip the update")
				continue
			}
			log.Info("broken params in resolv.conf, repairing it...")

			err = f.inotify.Remove(f.watchDir)
			if err != nil {
				log.Errorf("failed to rm inotify watch for resolv.conf: %s", err)
			}

			err = f.updateFn(nbSearchDomains, nbNameserverIP, rConf)
			if err != nil {
				log.Errorf("failed to repair resolv.conf: %v", err)
			}

			err = f.inotify.Add(f.watchDir)
			if err != nil {
				log.Errorf("failed to re-add inotify watch for resolv.conf: %s", err)
				return
			}
		}
	}()

	err = f.inotify.Add(f.watchDir)
	if err != nil {
		log.Errorf("failed to add inotify watch for resolv.conf: %s", err)
		return
	}
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
func isNbParamsMissing(nbSearchDomains []string, nbNameserverIP string, rConf *resolvConf) bool {
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

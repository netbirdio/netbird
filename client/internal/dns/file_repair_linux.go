package dns

import (
	"errors"
	"os"
	"sync"

	"github.com/illarion/gonotify"
	log "github.com/sirupsen/logrus"
)

const (
	eventTypes = gonotify.IN_CREATE |
		gonotify.IN_MODIFY |
		gonotify.IN_MOVE |
		gonotify.IN_CLOSE_WRITE |
		gonotify.IN_DELETE

	watchDir = "/etc"
)

type repairConfFn func([]string, string, *resolvConf) error

type repair struct {
	updateFn repairConfFn

	inotify   *gonotify.Inotify
	inotifyWg sync.WaitGroup
}

func newRepair(updateFn repairConfFn) *repair {
	return &repair{
		updateFn: updateFn,
	}
}

func (f *repair) watchFileChanges(nbSearchDomains []string, nbNameserverIP string) {
	if f.inotify != nil {
		return
	}

	inotify, err := gonotify.NewInotify()
	if err != nil {
		log.Errorf("failed to start inotify watcher for resolv.conf: %s", err)
		return
	}
	f.inotify = inotify

	err = f.inotify.AddWatch(watchDir, eventTypes)
	if err != nil {
		log.Errorf("failed to add inotify watch for resolv.conf: %s", err)
		return
	}
	f.inotifyWg.Add(1)
	go func() {
		defer f.inotifyWg.Done()
		for {
			events, err := f.inotify.Read()
			if err != nil {
				if errors.Is(err, os.ErrClosed) {
					log.Infof("inotify closed")
					return
				}

				log.Errorf("failed to read inotify %v", err)
				return
			}

			if !isEventRelevant(events) {
				continue
			}

			log.Debugf("resolv.conf changed, check if it is broken")

			rConf, err := parseDefaultResolvConf()
			if err != nil {
				log.Warnf("failed to parse resolv conf: %s", err)
				continue
			}

			log.Debugf("check resolv.conf parameters: %s", rConf)
			if !isNbParamsMissing(nbSearchDomains, nbNameserverIP, rConf) {
				log.Debugf("resolv.conf still correct, skip the update")
				continue
			}
			log.Info("broken params in resolv.conf, repair it...")

			err = f.inotify.RmWatch(watchDir)
			if err != nil {
				log.Errorf("failed to rm inotify watch for resolv.conf: %s", err)
			}

			err = f.updateFn(nbSearchDomains, nbNameserverIP, rConf)
			if err != nil {
				log.Errorf("failed to repair resolv.conf: %v", err)
			}

			err = f.inotify.AddWatch(watchDir, eventTypes)
			if err != nil {
				log.Errorf("failed to readd inotify watch for resolv.conf: %s", err)
				return
			}
		}
	}()
	return
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

func isEventRelevant(events []gonotify.InotifyEvent) bool {
	for _, ev := range events {
		if ev.Name == defaultResolvConfPath {
			return true
		}
	}
	return false
}

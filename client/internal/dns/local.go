package dns

import (
	"github.com/miekg/dns"
	nbdns "github.com/netbirdio/netbird/dns"
	log "github.com/sirupsen/logrus"
	"sync"
)

type localResolver struct {
	mux           sync.Mutex
	registeredMap registrationMap
	records       sync.Map
}

func (d *localResolver) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	log.Debugf("received question: %#v\n", r.Question[0])
	response := d.lookupRecord(r)
	if response == nil {
		log.Debugf("got empty response for question: %#v\n", r.Question[0])
		return
	}

	replyMessage := &dns.Msg{}
	replyMessage.SetReply(r)
	replyMessage.Answer = append(replyMessage.Answer, response)

	err := w.WriteMsg(replyMessage)
	if err != nil {
		log.Debugf("got an error while writing the local resolver response, error: %v", err)
	}
}

func (d *localResolver) lookupRecord(r *dns.Msg) dns.RR {
	record, found := d.records.Load(r.Question[0].Name)
	if !found {
		return nil
	}

	return record.(dns.RR)
}

func (d *localResolver) registerRecord(record nbdns.SimpleRecord) error {
	fullRecord, err := dns.NewRR(record.String())
	if err != nil {
		return err
	}

	d.records.Store(fullRecord.Header().Name, fullRecord)

	return nil
}

func (d *localResolver) deleteRecord(recordKey string) {
	d.records.Delete(dns.Fqdn(recordKey))
}

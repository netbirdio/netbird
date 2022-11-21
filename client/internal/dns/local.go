package dns

import (
	"fmt"
	"github.com/miekg/dns"
	nbdns "github.com/netbirdio/netbird/dns"
	log "github.com/sirupsen/logrus"
	"sync"
)

type localResolver struct {
	registeredMap registrationMap
	records       sync.Map
}

// ServeDNS handles a DNS request
func (d *localResolver) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	log.Debugf("received question: %#v\n", r.Question[0])
	replyMessage := &dns.Msg{}
	replyMessage.SetReply(r)
	replyMessage.RecursionAvailable = true
	replyMessage.Rcode = dns.RcodeSuccess

	response := d.lookupRecord(r)
	if response != nil {
		replyMessage.Answer = append(replyMessage.Answer, response)
	}

	err := w.WriteMsg(replyMessage)
	if err != nil {
		log.Debugf("got an error while writing the local resolver response, error: %v", err)
	}
}

func (d *localResolver) lookupRecord(r *dns.Msg) dns.RR {
	question := r.Question[0]
	record, found := d.records.Load(buildRecordKey(question.Name, question.Qclass, question.Qtype))
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

	fullRecord.Header().Rdlength = record.Len()

	header := fullRecord.Header()
	d.records.Store(buildRecordKey(header.Name, header.Class, header.Rrtype), fullRecord)

	return nil
}

func (d *localResolver) deleteRecord(recordKey string) {
	d.records.Delete(dns.Fqdn(recordKey))
}

func buildRecordKey(name string, class, qtype uint16) string {
	key := fmt.Sprintf("%s_%d_%d", name, class, qtype)
	log.Debugf("generated the following key: %s", key)
	return key
}

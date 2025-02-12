package dns

import (
	"fmt"
	"sync"

	"github.com/miekg/dns"
	log "github.com/sirupsen/logrus"

	nbdns "github.com/netbirdio/netbird/dns"
)

type registrationMap map[string]struct{}

type localResolver struct {
	registeredMap registrationMap
	records       sync.Map
}

func (d *localResolver) MatchSubdomains() bool {
	return true
}

func (d *localResolver) stop() {
}

// String returns a string representation of the local resolver
func (d *localResolver) String() string {
	return fmt.Sprintf("local resolver [%d records]", len(d.registeredMap))
}

// ID returns the unique handler ID
func (d *localResolver) id() handlerID {
	return "local-resolver"
}

// ServeDNS handles a DNS request
func (d *localResolver) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	if len(r.Question) > 0 {
		log.Tracef("received local question: domain=%s type=%v class=%v", r.Question[0].Name, r.Question[0].Qtype, r.Question[0].Qclass)
	}

	replyMessage := &dns.Msg{}
	replyMessage.SetReply(r)
	replyMessage.RecursionAvailable = true
	replyMessage.Rcode = dns.RcodeSuccess

	response := d.lookupRecord(r)
	if response != nil {
		replyMessage.Answer = append(replyMessage.Answer, response)
	} else {
		replyMessage.Rcode = dns.RcodeNameError
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
		return fmt.Errorf("register record: %w", err)
	}

	fullRecord.Header().Rdlength = record.Len()

	header := fullRecord.Header()
	d.records.Store(buildRecordKey(header.Name, header.Class, header.Rrtype), fullRecord)

	return nil
}

func (d *localResolver) deleteRecord(recordKey string) {
	d.records.Delete(dns.Fqdn(recordKey))
}

func buildRecordKey(name string, class, qType uint16) string {
	key := fmt.Sprintf("%s_%d_%d", name, class, qType)
	return key
}

func (d *localResolver) probeAvailability() {}

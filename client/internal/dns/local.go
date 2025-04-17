package dns

import (
	"fmt"
	"strings"
	"sync"

	"github.com/miekg/dns"
	log "github.com/sirupsen/logrus"

	nbdns "github.com/netbirdio/netbird/dns"
)

type registrationMap map[string]struct{}

type localResolver struct {
	registeredMap registrationMap
	records       sync.Map // key: string (domain_class_type), value: []dns.RR
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

	// lookup all records matching the question
	records := d.lookupRecords(r)
	if len(records) > 0 {
		replyMessage.Rcode = dns.RcodeSuccess
		replyMessage.Answer = append(replyMessage.Answer, records...)
	} else {
		replyMessage.Rcode = dns.RcodeNameError
	}

	err := w.WriteMsg(replyMessage)
	if err != nil {
		log.Debugf("got an error while writing the local resolver response, error: %v", err)
	}
}

// lookupRecords fetches *all* DNS records matching the first question in r.
func (d *localResolver) lookupRecords(r *dns.Msg) []dns.RR {
	if len(r.Question) == 0 {
		return nil
	}
	question := r.Question[0]
	question.Name = strings.ToLower(question.Name)
	key := buildRecordKey(question.Name, question.Qclass, question.Qtype)

	value, found := d.records.Load(key)
	if !found {
		// alternatively check if we have a cname
		if question.Qtype != dns.TypeCNAME {
			r.Question[0].Qtype = dns.TypeCNAME
			return d.lookupRecords(r)
		}

		return nil
	}

	records, ok := value.([]dns.RR)
	if !ok {
		log.Errorf("failed to cast records to []dns.RR, records: %v", value)
		return nil
	}

	// if there's more than one record, rotate them (round-robin)
	if len(records) > 1 {
		first := records[0]
		records = append(records[1:], first)
		d.records.Store(key, records)
	}

	return records
}

// registerRecord stores a new record by appending it to any existing list
func (d *localResolver) registerRecord(record nbdns.SimpleRecord) (string, error) {
	rr, err := dns.NewRR(record.String())
	if err != nil {
		return "", fmt.Errorf("register record: %w", err)
	}

	rr.Header().Rdlength = record.Len()
	header := rr.Header()
	key := buildRecordKey(header.Name, header.Class, header.Rrtype)

	// load any existing slice of records, then append
	existing, _ := d.records.LoadOrStore(key, []dns.RR{})
	records := existing.([]dns.RR)
	records = append(records, rr)

	// store updated slice
	d.records.Store(key, records)
	return key, nil
}

// deleteRecord removes *all* records under the recordKey.
func (d *localResolver) deleteRecord(recordKey string) {
	d.records.Delete(dns.Fqdn(recordKey))
}

// buildRecordKey consistently generates a key: name_class_type
func buildRecordKey(name string, class, qType uint16) string {
	return fmt.Sprintf("%s_%d_%d", dns.Fqdn(name), class, qType)
}

func (d *localResolver) probeAvailability() {}

package local

import (
	"fmt"
	"strings"
	"sync"

	"github.com/miekg/dns"
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/dns/types"
	nbdns "github.com/netbirdio/netbird/dns"
)

type Resolver struct {
	// TODO: decouple these from server tests and make them private
	RegisteredMap types.RegistrationMap
	Records       sync.Map // key: string (domain_class_type), value: []dns.RR
}

func NewResolver() *Resolver {
	return &Resolver{
		RegisteredMap: make(types.RegistrationMap),
	}
}

func (d *Resolver) MatchSubdomains() bool {
	return true
}

// String returns a string representation of the local resolver
func (d *Resolver) String() string {
	return fmt.Sprintf("local resolver [%d records]", len(d.RegisteredMap))
}

func (d *Resolver) Stop() {}

// ID returns the unique handler ID
func (d *Resolver) ID() types.HandlerID {
	return "local-resolver"
}

func (d *Resolver) ProbeAvailability() {}

// ServeDNS handles a DNS request
func (d *Resolver) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
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
func (d *Resolver) lookupRecords(r *dns.Msg) []dns.RR {
	if len(r.Question) == 0 {
		return nil
	}
	question := r.Question[0]
	question.Name = strings.ToLower(question.Name)
	key := types.BuildRecordKey(question.Name, question.Qclass, question.Qtype)

	value, found := d.Records.Load(key)
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
		d.Records.Store(key, records)
	}

	return records
}

func (d *Resolver) Update(update map[types.RecordKey][]nbdns.SimpleRecord) {
	// remove old records that are no longer present
	for key := range d.RegisteredMap {
		_, found := update[key]
		if !found {
			d.deleteRecord(key)
		}
	}

	updatedMap := make(types.RegistrationMap)
	for _, recs := range update {
		for _, rec := range recs {
			// convert the record to a dns.RR and register
			key, err := d.RegisterRecord(rec)
			if err != nil {
				log.Warnf("got an error while registering the record (%s), error: %v",
					rec.String(), err)
				continue
			}

			updatedMap[key] = struct{}{}
		}
	}

	d.RegisteredMap = updatedMap
}

// RegisterRecord stores a new record by appending it to any existing list
func (d *Resolver) RegisterRecord(record nbdns.SimpleRecord) (types.RecordKey, error) {
	rr, err := dns.NewRR(record.String())
	if err != nil {
		return "", fmt.Errorf("register record: %w", err)
	}

	rr.Header().Rdlength = record.Len()
	header := rr.Header()
	key := types.BuildRecordKey(header.Name, header.Class, header.Rrtype)

	// load any existing slice of records, then append
	existing, _ := d.Records.LoadOrStore(key, []dns.RR{})
	records := existing.([]dns.RR)
	records = append(records, rr)

	// store updated slice
	d.Records.Store(key, records)
	return key, nil
}

// deleteRecord removes *all* records under the recordKey.
func (d *Resolver) deleteRecord(recordKey types.RecordKey) {
	d.Records.Delete(dns.Fqdn(string(recordKey)))
}

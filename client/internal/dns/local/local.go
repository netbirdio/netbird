package local

import (
	"fmt"
	"slices"
	"strings"
	"sync"

	"github.com/miekg/dns"
	log "github.com/sirupsen/logrus"
	"golang.org/x/exp/maps"

	"github.com/netbirdio/netbird/client/internal/dns/types"
	nbdns "github.com/netbirdio/netbird/dns"
	"github.com/netbirdio/netbird/management/domain"
)

type Resolver struct {
	mu      sync.RWMutex
	records map[dns.Question][]dns.RR
	domains map[domain.Domain]struct{}
}

func NewResolver() *Resolver {
	return &Resolver{
		records: make(map[dns.Question][]dns.RR),
		domains: make(map[domain.Domain]struct{}),
	}
}

func (d *Resolver) MatchSubdomains() bool {
	return true
}

// String returns a string representation of the local resolver
func (d *Resolver) String() string {
	return fmt.Sprintf("LocalResolver [%d records]", len(d.records))
}

func (d *Resolver) Stop() {}

// ID returns the unique handler ID
func (d *Resolver) ID() types.HandlerID {
	return "local-resolver"
}

func (d *Resolver) ProbeAvailability() {}

// ServeDNS handles a DNS request
func (d *Resolver) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	if len(r.Question) == 0 {
		log.Debugf("received local resolver request with no question")
		return
	}
	question := r.Question[0]
	question.Name = strings.ToLower(dns.Fqdn(question.Name))

	log.Tracef("received local question: domain=%s type=%v class=%v", r.Question[0].Name, question.Qtype, question.Qclass)

	replyMessage := &dns.Msg{}
	replyMessage.SetReply(r)
	replyMessage.RecursionAvailable = true

	// lookup all records matching the question
	records := d.lookupRecords(question)
	if len(records) > 0 {
		replyMessage.Rcode = dns.RcodeSuccess
		replyMessage.Answer = append(replyMessage.Answer, records...)
	} else {
		// Check if we have any records for this domain name with different types
		if d.hasRecordsForDomain(domain.Domain(question.Name)) {
			replyMessage.Rcode = dns.RcodeSuccess // NOERROR with 0 records
		} else {
			replyMessage.Rcode = dns.RcodeNameError // NXDOMAIN
		}
	}

	if err := w.WriteMsg(replyMessage); err != nil {
		log.Warnf("failed to write the local resolver response: %v", err)
	}
}

// hasRecordsForDomain checks if any records exist for the given domain name regardless of type
func (d *Resolver) hasRecordsForDomain(domainName domain.Domain) bool {
	d.mu.RLock()
	defer d.mu.RUnlock()

	_, exists := d.domains[domainName]
	return exists
}

// lookupRecords fetches *all* DNS records matching the first question in r.
func (d *Resolver) lookupRecords(question dns.Question) []dns.RR {
	d.mu.RLock()
	records, found := d.records[question]

	if !found {
		d.mu.RUnlock()
		// alternatively check if we have a cname
		if question.Qtype != dns.TypeCNAME {
			question.Qtype = dns.TypeCNAME
			return d.lookupRecords(question)
		}
		return nil
	}

	recordsCopy := slices.Clone(records)
	d.mu.RUnlock()

	// if there's more than one record, rotate them (round-robin)
	if len(recordsCopy) > 1 {
		d.mu.Lock()
		records = d.records[question]
		if len(records) > 1 {
			first := records[0]
			records = append(records[1:], first)
			d.records[question] = records
		}
		d.mu.Unlock()
	}

	return recordsCopy
}

func (d *Resolver) Update(update []nbdns.SimpleRecord) {
	d.mu.Lock()
	defer d.mu.Unlock()

	maps.Clear(d.records)
	maps.Clear(d.domains)

	for _, rec := range update {
		if err := d.registerRecord(rec); err != nil {
			log.Warnf("failed to register the record (%s): %v", rec, err)
			continue
		}
	}
}

// RegisterRecord stores a new record by appending it to any existing list
func (d *Resolver) RegisterRecord(record nbdns.SimpleRecord) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	return d.registerRecord(record)
}

// registerRecord performs the registration with the lock already held
func (d *Resolver) registerRecord(record nbdns.SimpleRecord) error {
	rr, err := dns.NewRR(record.String())
	if err != nil {
		return fmt.Errorf("register record: %w", err)
	}

	rr.Header().Rdlength = record.Len()
	header := rr.Header()
	q := dns.Question{
		Name:   strings.ToLower(dns.Fqdn(header.Name)),
		Qtype:  header.Rrtype,
		Qclass: header.Class,
	}

	d.records[q] = append(d.records[q], rr)
	d.domains[domain.Domain(q.Name)] = struct{}{}

	return nil
}

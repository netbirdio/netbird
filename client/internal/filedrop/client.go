package filedrop

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"time"

	log "github.com/sirupsen/logrus"
)

const (
	defaultPollTimeout  = 60 * time.Second
	defaultOfferTimeout = DefaultOfferTTL
	uploadRetryDelay    = 2 * time.Second
	maxUploadAttempts   = 3
)

// DialFunc opens a connection to the receiving peer over the tunnel.
type DialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// Payload is one item to send; Open is called per attempt starting at an offset.
type Payload struct {
	Meta FileMeta
	Open func(offset int64) (io.ReadCloser, error)
}

// ProgressFunc reports staged bytes for one item as the upload streams.
type ProgressFunc func(index int, sent int64, total int64)

// ClientConfig configures the sending side.
type ClientConfig struct {
	Dial         DialFunc
	SenderName   string
	PollTimeout  time.Duration
	OfferTimeout time.Duration
}

type progressReader struct {
	r      io.Reader
	sent   int64
	total  int64
	report func(sent int64)
}

// Client sends offers and payloads to a peer's file drop service.
type Client struct {
	http         *http.Client
	senderName   string
	pollTimeout  time.Duration
	offerTimeout time.Duration
}

func (p *progressReader) Read(b []byte) (int, error) {
	n, err := p.r.Read(b)
	if n > 0 {
		p.sent += int64(n)
		p.report(p.sent)
	}
	return n, err
}

// NewClient builds a sending client over the given dialer.
func NewClient(cfg ClientConfig) (*Client, error) {
	if cfg.Dial == nil {
		return nil, errors.New("dial function is required")
	}

	pollTimeout := cfg.PollTimeout
	if pollTimeout <= 0 {
		pollTimeout = defaultPollTimeout
	}
	offerTimeout := cfg.OfferTimeout
	if offerTimeout <= 0 {
		offerTimeout = defaultOfferTimeout
	}

	transport := &http.Transport{
		DialContext:           func(ctx context.Context, network, addr string) (net.Conn, error) { return cfg.Dial(ctx, network, addr) },
		MaxIdleConnsPerHost:   2,
		ResponseHeaderTimeout: pollTimeout + 30*time.Second,
	}

	return &Client{
		http:         &http.Client{Transport: transport},
		senderName:   cfg.SenderName,
		pollTimeout:  pollTimeout,
		offerTimeout: offerTimeout,
	}, nil
}

// TextPayload builds an inline text payload, which is carried in the offer itself.
func TextPayload(name, text string) Payload {
	return Payload{
		Meta: FileMeta{
			Name:        name,
			Size:        int64(len(text)),
			ContentType: "text/plain",
			Kind:        KindText,
			Text:        text,
		},
	}
}

// Send offers the payloads to the peer at addr and uploads them once accepted.
func (c *Client) Send(ctx context.Context, addr netip.AddrPort, payloads []Payload, progress ProgressFunc) (OfferID, error) {
	id, decision, err := c.Offer(ctx, addr, payloads)
	if err != nil {
		return id, err
	}

	decision, err = c.AwaitDecision(ctx, addr, id, decision)
	if err != nil {
		return id, err
	}
	if err := decisionError(decision); err != nil {
		return id, err
	}

	return id, c.Upload(ctx, addr, id, payloads, progress)
}

// Offer announces the payloads and returns the offer ID with its initial decision.
func (c *Client) Offer(ctx context.Context, addr netip.AddrPort, payloads []Payload) (OfferID, Decision, error) {
	if len(payloads) == 0 {
		return "", DecisionPending, fmt.Errorf("%w: no payloads", ErrInvalidOffer)
	}
	return c.postOffer(ctx, baseURL(addr), payloads)
}

// AwaitDecision resolves a pending decision by long-polling the receiver.
func (c *Client) AwaitDecision(ctx context.Context, addr netip.AddrPort, id OfferID, decision Decision) (Decision, error) {
	if decision != DecisionPending {
		return decision, nil
	}
	return c.awaitDecision(ctx, baseURL(addr), id)
}

// Upload streams every non-inline payload of an accepted offer.
func (c *Client) Upload(ctx context.Context, addr netip.AddrPort, id OfferID, payloads []Payload, progress ProgressFunc) error {
	base := baseURL(addr)
	for i, p := range payloads {
		if p.Meta.Kind == KindText {
			continue
		}
		if err := c.uploadFile(ctx, base, id, i, p, progress); err != nil {
			return fmt.Errorf("upload %s: %w", p.Meta.Name, err)
		}
	}
	return nil
}

// Cancel withdraws an offer, taking the receiver's consent prompt with it.
func (c *Client) Cancel(ctx context.Context, addr netip.AddrPort, id OfferID) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, offerURL(baseURL(addr), id), nil)
	if err != nil {
		return fmt.Errorf("build cancel request: %w", err)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("send cancel: %w", err)
	}
	defer drainAndClose(resp)

	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusNotFound {
		return statusError(resp)
	}
	return nil
}

func (c *Client) postOffer(ctx context.Context, base string, payloads []Payload) (OfferID, Decision, error) {
	files := make([]FileMeta, len(payloads))
	for i, p := range payloads {
		files[i] = p.Meta
	}

	body, err := json.Marshal(OfferRequest{SenderName: c.senderName, Files: files})
	if err != nil {
		return "", DecisionPending, fmt.Errorf("encode offer: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+pathOffers, bytes.NewReader(body))
	if err != nil {
		return "", DecisionPending, fmt.Errorf("build offer request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return "", DecisionPending, fmt.Errorf("send offer: %w", err)
	}
	defer drainAndClose(resp)

	switch resp.StatusCode {
	case http.StatusCreated, http.StatusAccepted:
	case http.StatusForbidden:
		return "", DecisionPending, ErrRefused
	default:
		return "", DecisionPending, statusError(resp)
	}

	var offer OfferResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxOfferBodySize)).Decode(&offer); err != nil {
		return "", DecisionPending, fmt.Errorf("decode offer response: %w", err)
	}
	if offer.ID == "" {
		return "", DecisionPending, fmt.Errorf("%w: receiver returned no offer id", ErrInvalidOffer)
	}
	if !offer.Decision.valid() {
		return "", DecisionPending, fmt.Errorf("%w: receiver returned decision %s", ErrInvalidOffer, offer.Decision)
	}

	return offer.ID, offer.Decision, nil
}

func (c *Client) awaitDecision(ctx context.Context, base string, id OfferID) (Decision, error) {
	deadline := time.Now().Add(c.offerTimeout)

	for time.Now().Before(deadline) {
		decision, err := c.pollDecision(ctx, base, id)
		if err != nil {
			if ctx.Err() != nil {
				return DecisionPending, ctx.Err()
			}
			log.Debugf("poll file drop decision: %v", err)
			if !sleepCtx(ctx, uploadRetryDelay) {
				return DecisionPending, ctx.Err()
			}
			continue
		}
		if decision != DecisionPending {
			return decision, nil
		}
	}

	return DecisionExpired, nil
}

func (c *Client) pollDecision(ctx context.Context, base string, id OfferID) (Decision, error) {
	pollCtx, cancel := context.WithTimeout(ctx, c.pollTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(pollCtx, http.MethodGet, offerURL(base, id), nil)
	if err != nil {
		return DecisionPending, fmt.Errorf("build status request: %w", err)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return DecisionPending, fmt.Errorf("poll status: %w", err)
	}
	defer drainAndClose(resp)

	if resp.StatusCode == http.StatusNotFound {
		return DecisionPending, ErrOfferNotFound
	}
	if resp.StatusCode != http.StatusOK {
		return DecisionPending, statusError(resp)
	}

	var offer OfferResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxOfferBodySize)).Decode(&offer); err != nil {
		return DecisionPending, fmt.Errorf("decode status response: %w", err)
	}
	if !offer.Decision.valid() {
		return DecisionPending, fmt.Errorf("%w: receiver returned decision %s", ErrInvalidOffer, offer.Decision)
	}
	return offer.Decision, nil
}

func (c *Client) uploadFile(ctx context.Context, base string, id OfferID, index int, p Payload, progress ProgressFunc) error {
	var lastErr error

	for attempt := range maxUploadAttempts {
		offset := int64(0)
		if attempt > 0 {
			if !sleepCtx(ctx, uploadRetryDelay) {
				return ctx.Err()
			}
			confirmed, err := c.confirmedOffset(ctx, base, id, index)
			if err != nil {
				lastErr = err
				continue
			}
			offset = confirmed
		}

		if offset >= p.Meta.Size {
			return nil
		}

		if err := c.putFile(ctx, base, id, index, p, offset, progress); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			lastErr = err
			log.Debugf("upload attempt %d for %s: %v", attempt+1, p.Meta.Name, err)
			continue
		}
		return nil
	}

	return lastErr
}

func (c *Client) putFile(ctx context.Context, base string, id OfferID, index int, p Payload, offset int64, progress ProgressFunc) error {
	if p.Open == nil {
		return fmt.Errorf("payload %s has no reader", p.Meta.Name)
	}

	body, err := p.Open(offset)
	if err != nil {
		return fmt.Errorf("open payload: %w", err)
	}
	defer func() {
		if err := body.Close(); err != nil {
			log.Debugf("close payload reader: %v", err)
		}
	}()

	var reader io.Reader = body
	if progress != nil {
		reader = &progressReader{
			r:     body,
			sent:  offset,
			total: p.Meta.Size,
			report: func(sent int64) {
				progress(index, sent, p.Meta.Size)
			},
		}
	}

	url := fileURL(base, id, index) + "?offset=" + strconv.FormatInt(offset, 10)
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, url, reader)
	if err != nil {
		return fmt.Errorf("build upload request: %w", err)
	}
	req.ContentLength = p.Meta.Size - offset
	req.Header.Set("Content-Type", contentTypeOrDefault(p.Meta.ContentType))

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("send payload: %w", err)
	}
	defer drainAndClose(resp)

	if resp.StatusCode == http.StatusForbidden {
		return ErrNotAccepted
	}
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		return statusError(resp)
	}
	return nil
}

func (c *Client) confirmedOffset(ctx context.Context, base string, id OfferID, index int) (int64, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, fileURL(base, id, index), nil)
	if err != nil {
		return 0, fmt.Errorf("build probe request: %w", err)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return 0, fmt.Errorf("probe upload: %w", err)
	}
	defer drainAndClose(resp)

	if resp.StatusCode != http.StatusOK {
		return 0, statusError(resp)
	}

	raw := resp.Header.Get(HeaderReceivedBytes)
	if raw == "" {
		return 0, nil
	}
	offset, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || offset < 0 {
		return 0, fmt.Errorf("invalid %s header %q", HeaderReceivedBytes, raw)
	}
	return offset, nil
}

func baseURL(addr netip.AddrPort) string {
	return "http://" + net.JoinHostPort(addr.Addr().Unmap().String(), strconv.Itoa(int(addr.Port())))
}

func offerURL(base string, id OfferID) string {
	return base + pathOffersSlash + string(id)
}

func fileURL(base string, id OfferID, index int) string {
	return offerURL(base, id) + "/" + segmentFiles + "/" + strconv.Itoa(index)
}

func contentTypeOrDefault(ct string) string {
	if ct == "" {
		return "application/octet-stream"
	}
	return ct
}

func statusError(resp *http.Response) error {
	return fmt.Errorf("receiver returned %s", resp.Status)
}

func drainAndClose(resp *http.Response) {
	if _, err := io.Copy(io.Discard, io.LimitReader(resp.Body, maxOfferBodySize)); err != nil {
		log.Tracef("drain response body: %v", err)
	}
	if err := resp.Body.Close(); err != nil {
		log.Debugf("close response body: %v", err)
	}
}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()

	select {
	case <-timer.C:
		return true
	case <-ctx.Done():
		return false
	}
}

func decisionError(decision Decision) error {
	switch decision {
	case DecisionAccepted:
		return nil
	case DecisionDeclined:
		return ErrDeclined
	case DecisionExpired:
		return ErrExpired
	default:
		return fmt.Errorf("unexpected decision %s", decision)
	}
}

package udpmux

import (
	"encoding/binary"
	"time"

	"github.com/pion/stun/v3"
)

const (
	stunTransactionTTL  = time.Minute
	maxSTUNTransactions = 4096
)

type stunTransactionID [stun.TransactionIDSize]byte

type stunTransaction struct {
	id        stunTransactionID
	conn      *udpMuxedConn
	expiresAt time.Time
}

func (m *SingleSocketUDPMux) trackSTUNRequest(conn *udpMuxedConn, buf []byte) *stunTransaction {
	// RFC 8489 section 5 encodes the class in bits 8 and 4 of the type.
	if !stun.IsMessage(buf) || binary.BigEndian.Uint16(buf[:2])&0xc110 != 0 {
		return nil
	}
	length := int(binary.BigEndian.Uint16(buf[2:4]))
	if length%4 != 0 || length+20 != len(buf) {
		return nil
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if m.IsClosed() || conn.isClosed() ||
		(m.connsIPv4[conn.params.Key] != conn && m.connsIPv6[conn.params.Key] != conn) {
		return nil
	}

	now := time.Now()
	m.pruneSTUNTransactions(now)
	id := stunTransactionID(buf[8:20])
	if previous := m.transactions[id]; previous != nil {
		m.transactionOrder.Remove(previous)
		delete(m.transactions, id)
	}
	if len(m.transactions) == maxSTUNTransactions {
		oldest := m.transactionOrder.Front()
		delete(m.transactions, oldest.Value.(*stunTransaction).id)
		m.transactionOrder.Remove(oldest)
	}
	transaction := &stunTransaction{id: id, conn: conn, expiresAt: now.Add(stunTransactionTTL)}
	m.transactions[id] = m.transactionOrder.PushBack(transaction)
	return transaction
}

func (m *SingleSocketUDPMux) takeSTUNTransaction(id [stun.TransactionIDSize]byte) *udpMuxedConn {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pruneSTUNTransactions(time.Now())
	element := m.transactions[stunTransactionID(id)]
	if element == nil {
		return nil
	}
	transaction := element.Value.(*stunTransaction)
	delete(m.transactions, transaction.id)
	m.transactionOrder.Remove(element)
	if transaction.conn.isClosed() {
		return nil
	}
	return transaction.conn
}

func (m *SingleSocketUDPMux) removeSTUNTransaction(transaction *stunTransaction) {
	if transaction == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	element := m.transactions[transaction.id]
	// A send error must not remove a newer retransmission's registration.
	if element == nil || element.Value.(*stunTransaction) != transaction {
		return
	}
	delete(m.transactions, transaction.id)
	m.transactionOrder.Remove(element)
}

func (m *SingleSocketUDPMux) removeConnSTUNTransactions(conn *udpMuxedConn) {
	for id, element := range m.transactions {
		if element.Value.(*stunTransaction).conn == conn {
			delete(m.transactions, id)
			m.transactionOrder.Remove(element)
		}
	}
}

func (m *SingleSocketUDPMux) pruneSTUNTransactions(now time.Time) {
	for element := m.transactionOrder.Front(); element != nil; element = m.transactionOrder.Front() {
		transaction := element.Value.(*stunTransaction)
		if now.Before(transaction.expiresAt) {
			return
		}
		delete(m.transactions, transaction.id)
		m.transactionOrder.Remove(element)
	}
}

func (m *SingleSocketUDPMux) expireSTUNTransactions() {
	ticker := time.NewTicker(stunTransactionTTL)
	defer ticker.Stop()
	for {
		select {
		case now := <-ticker.C:
			m.mu.Lock()
			m.pruneSTUNTransactions(now)
			m.mu.Unlock()
		case <-m.closedChan:
			return
		}
	}
}

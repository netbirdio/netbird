package main

import (
	"bytes"
	"encoding/json"
	"net/http"

	log "github.com/sirupsen/logrus"
)

type PeerAddr struct {
	Address []string
}

type ClientPeerAddr struct {
	Address map[string]string
}

type Signal struct {
	AddressesChan     chan []string
	ClientAddressChan chan map[string]string
}

func NewSignalService() *Signal {
	return &Signal{
		AddressesChan:     make(chan []string, 0),
		ClientAddressChan: make(chan map[string]string, 0),
	}
}

func (rs *Signal) Listen(listenAdddr string) error {
	http.HandleFunc("/", rs.onNewAddresses)
	return http.ListenAndServe(listenAdddr, nil)
}

func (rs *Signal) onNewAddresses(w http.ResponseWriter, r *http.Request) {
	var msg PeerAddr
	err := json.NewDecoder(r.Body).Decode(&msg)
	if err != nil {
		log.Errorf("Error decoding message: %v", err)
	}

	log.Infof("received addresses: %v", msg.Address)
	rs.AddressesChan <- msg.Address
	clientAddresses := <-rs.ClientAddressChan
	log.Infof("Sending back addresses: %v", clientAddresses)

	respMsg := ClientPeerAddr{
		Address: clientAddresses,
	}
	data, err := json.Marshal(respMsg)
	if err != nil {
		log.Errorf("Error marshalling message: %v", err)
		return
	}

	_, err = w.Write(data)
	if err != nil {
		log.Errorf("Error writing response: %v", err)
	}
}

// "http://localhost:8080/address"
type SignalClient struct {
	SignalAddress string
}

func (ss SignalClient) SendAddress(addresses []string) (*ClientPeerAddr, error) {
	msg := PeerAddr{
		Address: addresses,
	}
	data, err := json.Marshal(msg)
	if err != nil {
		return nil, err
	}

	response, err := http.Post(ss.SignalAddress, "application/json", bytes.NewBuffer(data))
	if err != nil {
		return nil, err
	}

	defer response.Body.Close()

	log.Debugf("wait for signal response")
	var respPeerAddress ClientPeerAddr
	err = json.NewDecoder(response.Body).Decode(&respPeerAddress)
	if err != nil {
		return nil, err
	}
	return &respPeerAddress, nil
}

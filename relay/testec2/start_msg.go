//go:build linux || darwin

package main

import (
	"bytes"
	"encoding/gob"
	"time"

	log "github.com/sirupsen/logrus"
)

type StartIndication struct {
	Started      time.Time
	TransferSize int
}

func NewStartInidication(started time.Time, transferSize int) []byte {
	si := StartIndication{
		Started:      started,
		TransferSize: transferSize,
	}

	var data bytes.Buffer
	err := gob.NewEncoder(&data).Encode(si)
	if err != nil {
		log.Fatal("encode error:", err)
	}
	return data.Bytes()
}

func DecodeStartIndication(data []byte) StartIndication {
	var si StartIndication
	err := gob.NewDecoder(bytes.NewReader(data)).Decode(&si)
	if err != nil {
		log.Fatal("decode error:", err)
	}
	return si
}

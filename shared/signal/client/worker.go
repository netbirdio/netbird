package client

import (
	"context"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/shared/signal/proto"
)

type Worker struct {
	decryptMessage func(msg *proto.EncryptedMessage) (*proto.Message, error)
	handler        func(msg *proto.Message) error

	encryptedMsgPool chan *proto.EncryptedMessage
}

func NewWorker(decryptFn func(msg *proto.EncryptedMessage) (*proto.Message, error), handlerFn func(msg *proto.Message) error) *Worker {
	return &Worker{
		decryptMessage:   decryptFn,
		handler:          handlerFn,
		encryptedMsgPool: make(chan *proto.EncryptedMessage, 1),
	}
}

func (w *Worker) AddMsg(ctx context.Context, msg *proto.EncryptedMessage) error {
	// this is blocker because do not want to drop messages here
	select {
	case w.encryptedMsgPool <- msg:
	case <-ctx.Done():
	}
	return nil
}

func (w *Worker) Work(ctx context.Context) {
	for {
		select {
		case msg := <-w.encryptedMsgPool:
			decryptedMessage, err := w.decryptMessage(msg)
			if err != nil {
				log.Errorf("failed to decrypt message: %v", err)
				continue
			}

			if err := w.handler(decryptedMessage); err != nil {
				log.Errorf("failed to handle message: %v", err)
				continue
			}

		case <-ctx.Done():
			log.Debugf("Message worker stopping due to context cancellation")
			return
		}
	}
}

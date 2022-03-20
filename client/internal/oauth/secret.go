package oauth

import (
	"fmt"
	"github.com/99designs/keyring"
)

const ServiceName = "Wiretrustee"

func newSecretAPI() (keyring.Keyring, error) {
	return keyring.Open(keyring.Config{
		ServiceName: ServiceName,
		//KeychainName: ServiceName,
	})
}

func SetSecret(key string, value string) error {
	storeAPI, err := newSecretAPI()
	if err != nil {
		return fmt.Errorf("failed to create secret API for setting a secret, error: %v", err)
	}

	item := keyring.Item{
		Key:  key,
		Data: []byte(value),
	}

	err = storeAPI.Set(item)
	if err != nil {
		return fmt.Errorf("failed to set the secret, error: %v", err)
	}

	return nil
}
func GetSecret(key string) (string, error) {
	storeAPI, err := newSecretAPI()
	if err != nil {
		return "", fmt.Errorf("failed to create secret API for getting a secret, error: %v", err)
	}

	item, err := storeAPI.Get(key)
	if err != nil {
		return "", fmt.Errorf("failed to get secret, error: %v", err)
	}

	return string(item.Data), nil
}

func DeleteSecret(key string) error {
	storeAPI, err := newSecretAPI()
	if err != nil {
		return fmt.Errorf("failed to create secret API for deleting a secret, error: %v", err)
	}

	err = storeAPI.Remove(key)
	if err != nil {
		return fmt.Errorf("failed to delete secret, error: %v", err)
	}

	return nil
}

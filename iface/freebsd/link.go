package freebsd

import (
	"bytes"
	"errors"
	"fmt"
	"os/exec"
	"strconv"

	log "github.com/sirupsen/logrus"
)

const wgIFGroup = "wg"

// Link represents a network interface.
type Link struct {
	name string
}

func NewLink(name string) *Link {
	return &Link{
		name: name,
	}
}

// LinkByName retrieves a network interface by its name.
func LinkByName(name string) (*Link, error) {
	out, err := exec.Command("ifconfig", name).CombinedOutput()
	if err != nil {
		if pErr := parseError(out); pErr != nil {
			return nil, pErr
		}

		log.Debugf("ifconfig out: %s", out)

		return nil, fmt.Errorf("command run: %w", err)
	}

	i, err := parseIfconfigOutput(out)
	if err != nil {
		return nil, fmt.Errorf("parse ifconfig output: %w", err)
	}

	if i.Name != name {
		return nil, ErrNameDoesNotMatch
	}

	return &Link{name: i.Name}, nil
}

// Recreate - create new interface, remove current before create if it exists
func (l *Link) Recreate() error {
	ok, err := l.isExist()
	if err != nil {
		return fmt.Errorf("is exist: %w", err)
	}

	if ok {
		if err := l.del(l.name); err != nil {
			return fmt.Errorf("del: %w", err)
		}
	}

	return l.Add()
}

// Add creates a new network interface.
func (l *Link) Add() error {
	parsedName, err := l.create(wgIFGroup)
	if err != nil {
		return fmt.Errorf("create link: %w", err)
	}

	if parsedName == l.name {
		return nil
	}

	parsedName, err = l.rename(parsedName, l.name)
	if err != nil {
		errDel := l.del(parsedName)
		if errDel != nil {
			return fmt.Errorf("del on rename link: %w: %w", err, errDel)
		}

		return fmt.Errorf("rename link: %w", err)
	}

	return nil
}

// Del removes an existing network interface.
func (l *Link) Del() error {
	return l.del(l.name)
}

// SetMTU sets the MTU of the network interface.
func (l *Link) SetMTU(mtu int) error {
	return l.setMTU(mtu)
}

// AssignAddr assigns an IP address and netmask to the network interface.
func (l *Link) AssignAddr(ip, netmask string) error {
	return l.setAddr(ip, netmask)
}

func (l *Link) Up() error {
	return l.up(l.name)
}

func (l *Link) Down() error {
	return l.down(l.name)
}

func (l *Link) isExist() (bool, error) {
	_, err := LinkByName(l.name)
	if errors.Is(err, ErrDoesNotExist) {
		return false, nil
	}

	if err != nil {
		return false, fmt.Errorf("link by name: %w", err)
	}

	return true, nil
}

func (l *Link) create(groupName string) (string, error) {
	cmd := exec.Command("ifconfig", groupName, "create")

	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Debugf("ifconfig out: %s", output)

		return "", fmt.Errorf("create %s interface: %w", groupName, err)
	}

	interfaceName, err := parseIFName(output)
	if err != nil {
		return "", fmt.Errorf("parse interface name: %w", err)
	}

	return interfaceName, nil
}

func (l *Link) rename(oldName, newName string) (string, error) {
	cmd := exec.Command("ifconfig", oldName, "name", newName)

	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Debugf("ifconfig out: %s", output)

		return "", fmt.Errorf("change name %q -> %q: %w", oldName, newName, err)
	}

	interfaceName, err := parseIFName(output)
	if err != nil {
		return "", fmt.Errorf("parse new name: %w", err)
	}

	return interfaceName, nil
}

func (l *Link) del(name string) error {
	var stderr bytes.Buffer

	cmd := exec.Command("ifconfig", name, "destroy")
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		log.Debugf("ifconfig out: %s", stderr.String())

		return fmt.Errorf("destroy %s interface: %w", name, err)
	}

	return nil
}

func (l *Link) setMTU(mtu int) error {
	var stderr bytes.Buffer

	cmd := exec.Command("ifconfig", l.name, "mtu", strconv.Itoa(mtu))
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		log.Debugf("ifconfig out: %s", stderr.String())

		return fmt.Errorf("set interface mtu: %w", err)
	}

	return nil
}

func (l *Link) setAddr(ip, netmask string) error {
	var stderr bytes.Buffer

	cmd := exec.Command("ifconfig", l.name, "inet", ip, "netmask", netmask)
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		log.Debugf("ifconfig out: %s", stderr.String())

		return fmt.Errorf("set interface addr: %w", err)
	}

	return nil
}

func (l *Link) up(name string) error {
	var stderr bytes.Buffer

	cmd := exec.Command("ifconfig", name, "up")
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		log.Debugf("ifconfig out: %s", stderr.String())

		return fmt.Errorf("up %s interface: %w", name, err)
	}

	return nil
}

func (l *Link) down(name string) error {
	var stderr bytes.Buffer

	cmd := exec.Command("ifconfig", name, "down")
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		log.Debugf("ifconfig out: %s", stderr.String())

		return fmt.Errorf("down %s interface: %w", name, err)
	}

	return nil
}

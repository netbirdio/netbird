package freebsd

import(
    "fmt"
    "os/exec"
)

// Link represents a network interface.
type Link struct {
    Name string
}

// GetByName retrieves a network interface by its name.
func (l *Link) GetByName(name string) (*Link, error) {
    out, err := exec.Command("ifconfig", name).Output()
    if err != nil {
        return nil, fmt.Errorf("command run: %w", err)
    }

    iface, err = parseIfconfigOutput(out)
    if err != nil {
        return nil, fmt.Errorf("parse ifconfig output: %w", err)
    }


    return &Link{Name: name}, nil
}

// Add creates a new network interface.
func (l *Link) Add() error {
    cmd := exec.Command("ifconfig", l.Name, "create")
    return cmd.Run()
}

// Del removes an existing network interface.
func (l *Link) Del() error {
    cmd := exec.Command("ifconfig", l.Name, "destroy")
    return cmd.Run()
}

// SetMTU sets the MTU of the network interface.
func (l *Link) SetMTU(mtu int) error {
    cmd := exec.Command("ifconfig", l.Name, "mtu", fmt.Sprintf("%d", mtu))
    return cmd.Run()
}

// AssignAddr assigns an IP address and netmask to the network interface.
func (l *Link) AssignAddr(ip, netmask string) error {
    cmd := exec.Command("ifconfig", l.Name, "inet", ip, "netmask", netmask)
    return cmd.Run()
}


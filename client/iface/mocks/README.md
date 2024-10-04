## Mocks

To generate (or refresh) mocks from iface package interfaces please install [mockgen](https://github.com/golang/mock).
Run this command to update PacketFilter mock:
```bash
mockgen -destination iface/mocks/filter.go -package mocks github.com/netbirdio/netbird/iface PacketFilter
```

## Mocks

To generate (or refresh) mocks from acl package please install [mockgen](https://github.com/golang/mock).
Run this command from the `./client/internal/acl` folder to update iface mapper interface mock:
```bash
mockgen -destination mocks/iface_mapper.go -package mocks . IFaceMapper
```

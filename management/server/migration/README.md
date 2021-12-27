## Migration from Store v2 to Store v2

Previously Account.Id was an Auth0 user id.
Conversion moves user id to Account.CreatedBy and generates a new Account.Id using xid.
It also adds a User with id = old Account.Id with a role Admin.

To start a conversion simply run the command below providing your current Wiretrustee Management datadir (where store.json file is located)
and a new data directory location (where a converted store.js will be stored):
```shell
    ./migration --oldDir /var/wiretrustee/datadir --newDir /var/wiretrustee/newdatadir/  
```

Afterwards you can run the Management service providing ```/var/wiretrustee/newdatadir/ ``` as a datadir.
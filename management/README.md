# Wiretrustee Management Server

## Run Management service (Docker)

You can run service in 2 modes - with TLS or without (not recommended).

### Run with TLS (Let's Encrypt). 

The server where you are running a container has to have a public IP (for Let's Encrypt certificate challenge).
In the following example ```33073``` is a gRpc port, ```443``` is a port for Let's Encrypt challenge and HTTP API.

Replace <YOUR-DOMAIN> with your server's public domain (e.g. mydomain.com or subdomain sub.mydomain.com).

```bash
docker run -d --name wiretrustee-management \
-p 33073:33073  \
-p 443:443  \
-v /var/lib/wiretrustee/:/var/lib/wiretrustee/  \
-v /etc/wiretrustee/:/etc/wiretrustee/  \
wiretrustee/wiretrustee:management-v0.0.8-SNAPSHOT-079d35e-amd64  \
--port 33073  \
--config /etc/wiretrustee/management.json \
--letsencrypt-domain <YOUR-DOMAIN>  \
--log-level info
```

Trigger Let's encrypt certificate generation:
```bash
curl https://<YOUR-DOMAIN>
```

The certificate will be persisted in the ```datadir/letsencrypt/``` folder (e.g. ```/var/lib/wiretrustee/letsencrypt/```). Make sure that the ```datadir``` is mapped to some folder on a host machine.
Consequent restarts of the container will pick up previously generated certificate so there is no need to trigger certificate generation with the ```curl``` command on every restart.
The ``datadir`` is specified in the config file.

**Below are optional steps (some checks).**

Inspect ```datadir``` to see if the folder contains Let's Encrypt certificate:
```bash
ls /var/lib/wiretrustee/letsencrypt/
```

The output should be something similar to this:

```bash
root@wiretrustee-test-2:~# ls /var/lib/wiretrustee/letsencrypt/
acme_account+key  <YOUR-DOMAIN>  <YOUR-DOMAIN>+rsa
```

Check certificate:
```bash
echo | openssl s_client -showcerts -servername <YOUR-DOMAIN> -connect <YOUR-DOMAIN>:33073 2>/dev/null | openssl x509 -inform pem -noout -text
```

The output should be something similar to this:
```bash
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            04:07:7a:8e:f3:78:0d:bc:4d:f0:82:9b:1a:a3:c1:89:6c:ae
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: C = US, O = Let's Encrypt, CN = R3
        Validity
            Not Before: Jul 17 14:19:45 2021 GMT
            Not After : Oct 15 14:19:43 2021 GMT
        Subject: CN = <YOUR-DOMAIN>
        
        ...        
        
            Signature Algorithm: sha256WithRSAEncryption
         3a:a3:27:5c:aa:35:11:b0:9a:89:d4:da:03:30:16:bc:3e:01:
         9f:7a:14:0a:1c:f3:c3:1c:67:86:31:bd:63:0f:19:81:66:77:
         34:32:e8:ac:be:16:1d:55:5e:d5:71:73:d7:50:b4:fb:56:6d:
         14:b3:2f:ae:04:52:e5:f4:e2:86:dd:fe:b8:b0:bf:52:84:bf:
         5f:d2:56:9f:7b:70:6c:b8:f4:e8:c8:94:7f:89:e9:0d:37:55:
         c7:c7:6c:51:88:09:9a:40:4a:52:88:c6:8b:1b:9c:d4:a2:a5:
         4d:c7:23:4b:81:b8:4a:90:3f:a3:50:80:6e:bb:1f:1c:c2:19:
         99:d4:57:7b:82:07:f3:ca:71:6d:83:e8:5a:98:70:98:13:a1:
         64:81:0d:01:db:41:37:46:6f:a5:c6:e5:cf:7d:ba:f8:26:b1:
         53:58:fc:7d:48:2a:55:f3:14:e7:5e:7d:0f:3d:23:98:83:00:
         08:19:b0:62:93:a4:66:96:db:25:3f:e7:02:44:25:c1:62:4d:
         75:90:5b:b6:59:68:42:58:37:88:2f:84:c2:77:8f:9f:50:ed:
         b5:f7:b1:31:8a:b6:ca:9e:5a:90:e9:3f:5b:eb:d4:c3:f6:82:
         42:16:5f:f4:62:ed:51:9c:ac:b1:ba:4e:6f:ea:ec:ab:43:ba:
         d1:25:ab:28

```

### Run without TLS.

```bash
docker run -d --name wiretrustee-management \
-p 33073:33073  \
-v /var/lib/wiretrustee/:/var/lib/wiretrustee/  \
-v /etc/wiretrustee/:/etc/wiretrustee/  \
wiretrustee/wiretrustee:management-v0.0.8-SNAPSHOT-079d35e-amd64  \
--port 33073  \
--config /etc/wiretrustee/management.json \
--letsencrypt-domain app.wiretrustee.com  \
--log-level debug
```

### Config file example:

```json
{
    "Stuns": [
        {
            "Proto": 2,
            "Host": "stun.wiretrustee.com",
            "Port": 3468,
            "Username": "",
            "Password": null
        }
    ],
    "Turns": [
        {
            "Proto": 2,
            "Host": "stun.wiretrustee.com",
            "Port": 3468,
            "Username": "some_user",
            "Password": "c29tZV9wYXNzd29yZA=="
        }
    ],
    "Signal": {
        "Proto": 2,
        "Host": "signal.wiretrustee.com",
        "Port": 10000,
        "Username": "",
        "Password": null
    },
    "DataDir": "/var/lib/wiretrustee/datadir"
}
```

## For development purposes:

Install golang gRpc tools:
```bash
#!/bin/bash
go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.26
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.1
```

Generate gRpc code:

```bash
#!/bin/bash
protoc -I proto/ proto/management.proto --go_out=. --go-grpc_out=.
```


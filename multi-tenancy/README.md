# Netbird Multi-Tenant Documentation

This documentation provides a step-by-step guide for setting up the Netbird Multi-Tenant solution, which supports multiple fully independent tenants.

## Setup

### 1. Environment

Create an independent VM and set up a dedicated Docker network for Netbird. Also, create the root directory for the orchestration.

```bash
docker network create netbird
mkdir /opt/ZTNA
mkdir /opt/ZTNA/instances
mkdir /opt/ZTNA/caddy
```
Additionally, we recommend following the setup instructions recommended by Netbird for Selfhosted solutions, which can be found at https://docs.netbird.io/selfhosted/selfhosted-quickstart.


### 2. Caddy
Set up a centralized Caddy server to handle communication with all tenants.

```bash
cd /opt/ZTNA/caddy
# Import the Caddyfile and docker-compose.yml into this directory
docker-compose up -d
```

### 3. Orchestrator (API)
Configure a web server that handles incoming APIs to initialize or remove a tenant.

> [!WARNING]
> Edit the API key in the main.py file, and it is recommended to store it in an .env file.

```bash
apt install python3-pip
# Copy the `main.py` and `requirements.txt` files to /opt/ZTNA, and import the `netbird_api.service` file into /etc/systemd/system/
pip install -r requirements.txt
systemctl enable --now netbird_api
```

### 4. Worker 
The worker script is responsible for automatic tenant creation.

> [!IMPORTANT]
> Line 497 of this script contains a webhook that notifies the third-party application when the deployment is complete and saves the AuthKey for later authentication.

```bash
# Copy the `init.sh` file to /opt/ZTNA/
```

### 5. Summary
After completing the setup, your folder structure should look like this:

```
/opt/ZTNA/
├── instances/
├── caddy/
│   ├── Caddyfile
│   └── docker-compose.yml
├── init.sh
└── main.py
/etc/systemd/system/
└── netbird_api.service
```

## Usage
In the setup, it's assumed that a third-party platform handles API queries to initialize or remove tenants.

> [!IMPORTANT]
> Interaction with your DNS manager is **REQUIRED** for creating a DNS record like <INSTANCE_ID>.yourDomain.com during tenant creation and deletion.

### Tenant creation
Create a tenant with Instance ID: **123e4567-e89b-12d3-a456-426614174000**.

```bash
curl -X POST \
  -H "Content-Type: application/json" \
  -H "X-API-Key: XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX" \
  -d '{"id": "123e4567-e89b-12d3-a456-426614174000"}' \
  http://xxx.yourDomain.com/init
```
In 2 to 3 minutes, the Netbird dashboard will be available at: **123e4567-e89b-12d3-a456-426614174000.yourDomain.com**.

### Tenant removal
Remove the tenant with Instance ID: **123e4567-e89b-12d3-a456-426614174000**

```bash
curl -X POST \
  -H "Content-Type: application/json" \
  -H "X-API-Key: XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX" \
  -d '{"id": "123e4567-e89b-12d3-a456-426614174000"}' \
  http://xxx.yourDomain.com/remove
```
The tenant will be removed in about 15 seconds.

## Post Tenant Creation - Using API to Interact with Netbird

### Obtaining the AuthKey

After creating a tenant with ID: 123e4567-e89b-12d3-a456-426614174000, you can interact with it. You need the AuthKey to authenticate to Zitadel and obtain a JWT Token.

If you haven't received the webhook or haven't prepared the automation, you can obtain the AuthKey in two ways:

1. Run the following command:

   ```bash
    cat /opt/ZTNA/instances/<INSTANCE_ID>/.env | grep AuthKey= | sed 's/AuthKey=//'
    ```

2. Run the following command: 
    ```bash
    cat /opt/ZTNA/instances/<INSTANCE_ID>/management.json | jq -r '.IdpManagerConfig.ClientConfig.ClientID + ":" + .IdpManagerConfig.ClientConfig.ClientSecret' | tr -d '\n' | base64 | tr -d '[:space:]' && echo
    ```

### Obtaining our JWT Token

After obtaining the base64-encoded AuthKey, you can proceed to obtain the JWT Token:

```bash
curl --request POST \
 --url http://<INSTANCE_ID>.yourDomain.com/oauth/v2/token \
 --header 'Content-Type: application/x-www-form-urlencoded' \
 --header 'Authorization: Basic <AUTH-KEY>' \
 --data grant_type=client_credentials \
 --data scope=openid
```
*Response:*

```json
{
   "access_token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
   "token_type":"Bearer",
   "expires_in":43199
}
```

### Interact with Netbird APIs
You can interact with Netbird by making API requests. For example, to get users:

```bash
curl -X GET https://<INSTANCE_ID>.yourDomain.com/api/users \
-H 'Accept: application/json' \
-H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c' 
```
*Response:*

```json
[
   {
      "auto_groups":[],
      "email":"netbird-service-account",
      "id":"XXXXXXXXXXXXXXXXXXX",
      "is_blocked":false,
      "is_current":true,
      "is_service_user":false,
      "last_login":"0001-01-01T00:00:00Z",
      "name":"netbird-service-account",
      "role":"admin",
      "status":"active"
   },
]
```

From here you can proceed with full interaction to Netbird through the classic API (https://docs.netbird.io/api) for create setup-keys, peers, network, etc...
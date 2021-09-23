### Self-hosting
Wiretrustee is an open-source platform that can be self-hosted on your servers.

It relies on components developed by Wiretrustee Authors [Management Service](https://github.com/wiretrustee/wiretrustee/tree/main/management), [Management UI Dashboard](https://github.com/wiretrustee/wiretrustee-dashboard), [Signal Service](https://github.com/wiretrustee/wiretrustee/tree/main/signal), 3rd party STUN/TURN service [Coturn](https://github.com/coturn/coturn) and 3rd party service [Auth0](https://auth0.com/).

All the components can be self-hosted except for the Auth0 service.
We chose Auth0 to "outsource" the user management part of the platform because we believe that implementing a proper user auth requires significant amount of time to make it right. 
We focused on connectivity instead.

If you would like to learn more about the architecture please refer to the [Wiretrustee Architecture section](architecture.md).

### Prerequisites

- Virtual machine offered by any cloud provider (e.g., AWS, DigitalOcean, Hetzner, Google Cloud, Azure ...) 
- Min Ubuntu 20.04
- Docker Compose installed (see [Install Docker Compose](https://docs.docker.com/compose/install/))
- Public IP address
- Maybe a cup of coffee or tea :)

### Step-by-step guide

1. Create Auth0 account at [auth0.com](https://auth0.com/).
2. Login to your server and clone the repository and proceed to the wiretrustee folder:
   
   ```bash 
   git clone https://github.com/wiretrustee/wiretrustee.git wiretrustee/
   ```
   
   and switch to the ```wiretrustee/infrastructure_files/``` folder:
   
   ```bash 
   cd wiretrustee/infrastructure_files/
   ```
2. Configure Wiretrustee Auth0 integration:
    * running Wiretrustee UI Dashboard requires the following Auth0 environmental variables to be set in the [docker-compose.yml](https://github.com/wiretrustee/wiretrustee/blob/main/infrastructure_files/docker-compose.yml) file:

      ```AUTH0_DOMAIN``` ```AUTH0_CLIENT_ID``` ```AUTH0_AUDIENCE```
      
    To obtain these, please use [Auth0 React SDK Guide](https://auth0.com/docs/quickstart/spa/react/01-login#configure-auth0) up until "Configure Allowed Web Origins"
   * set the variables in the ```docker-compose.yml``` file. Replace ```REPLACE WITH ...``` with the proper values:
        ```bash 
        sed -i 's/<YOUR AUTH0 DOMAIN>/REPLACE WITH AUTH0_AUDIENCE/g' docker-compose.yml  \
        sed -i 's/<YOUR AUTH0 CLIENT ID>/REPLACE WITH AUTH0_AUDIENCEg' docker-compose.yml  \
        sed -i 's/<YOUR AUTH0 AUDIENCE>/REPLACE WITH AUTH0_AUDIENCE/g' docker-compose.yml
        ```
   * check [Auth0 Golang API Guide](https://auth0.com/docs/quickstart/backend/golang) to obtain ```AuthIssuer```, ```AuthAudience```, and ```AuthKeysLocation```
   * set the properties in the ```management.json``` file:
        ```bash 
        # AuthIssuer is something like https://<YOUR AUTH0 DOMAIN>.eu.auth0.com/
        sed -i 's/<YOUR AUTH0 ISSUER>/REPLACE WITH AUTH0 ISSUER/g' management.json  \ 
        sed -i 's/<YOUR AUTH0 AUDIENCE>/REPLACE WITH AUTH0_AUDIENCE/g' management.json  \
        # AuthKeysLocation is something like https://<YOUR AUTH0 DOMAIN>.eu.auth0.com/.well-known/jwks.json
        sed -i 's/<YOUR AUTH0 PUBLIC JWT KEYS>/REPLACE WITH JWT KEYS LOCATION/g' management.json
        ```
3. Wiretrustee UI Dashboard uses Wiretrustee Management Service HTTP API, so setting ```WIRETRUSTEE_MGMT_API_ENDPOINT``` is required. Most likely it will be ```http://localhost:33071``` if you are hosting Management API on the same server.
4.

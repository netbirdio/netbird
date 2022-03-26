### Self-hosting
Netbird is an open-source platform that can be self-hosted on your servers.

It relies on components developed by Netbird Authors [Management Service](https://github.com/netbirdio/netbird/tree/main/management), [Management UI Dashboard](https://github.com/netbirdio/dashboard), [Signal Service](https://github.com/netbirdio/netbird/tree/main/signal), 
a 3rd party open-source STUN/TURN service [Coturn](https://github.com/coturn/coturn) and a 3rd party service [Auth0](https://auth0.com/).

All the components can be self-hosted except for the Auth0 service.
We chose Auth0 to "outsource" the user management part of the platform because we believe that implementing a proper user auth requires significant amount of time to make it right. 
We focused on connectivity instead. It also offers an always free plan that should be ok for most users as its limits are high enough for most teams.

If you would like to learn more about the architecture please refer to the [Netbird Architecture section](architecture.md).

### Step-by-step video guide on YouTube:

[![IMAGE ALT TEXT](https://img.youtube.com/vi/Ofpgx5WhT0k/0.jpg)](https://youtu.be/Ofpgx5WhT0k "Netbird Self-Hosting Guide")

### Requirements

- Virtual machine offered by any cloud provider (e.g., AWS, DigitalOcean, Hetzner, Google Cloud, Azure ...). 
- Any Unix OS.
- Docker Compose installed (see [Install Docker Compose](https://docs.docker.com/compose/install/)).
- Domain name pointing to the public IP address of your server.
- Netbird Open ports ```443, 33071, 33073, 10000``` (Dashboard, Management HTTP API, Management gRpc API, Signal gRpc) on your server. 
- Coturn is used for relay using the STUN/TURN protocols. It requires a listening port, ```UDP 3478```,  and range of ports,```UDP 49152-65535```, for dynamic relay connections. These are set as defaults in [setup file](https://github.com/netbirdio/netbird/blob/main/infrastructure_files/setup.env#L34), but can be configured to your requirements. 
- Maybe a cup of coffee or tea :)

### Step-by-step guide

For this tutorial we will be using domain ```test.netbird.io``` which points to our Ubuntu 20.04 machine hosted at Hetzner.

1. Create Auth0 account at [auth0.com](https://auth0.com/).
2. Login to your server, clone Netbird repository:
   
   ```bash 
   git clone https://github.com/netbirdio/netbird.git netbird/
   ```
   
   and switch to the ```netbird/infrastructure_files/``` folder that contains docker compose file:
   
   ```bash 
   cd netbird/infrastructure_files/
   ```
3. Prepare configuration files.
   
   To simplify the setup we have prepared a script to substitute required properties in the [turnserver.conf.tmpl](../infrastructure_files/turnserver.conf.tmpl),[docker-compose.yml.tmpl](../infrastructure_files/docker-compose.yml.tmpl) and [management.json.tmpl](../infrastructure_files/management.json.tmpl) files.
   
   The [setup.env](../infrastructure_files/setup.env) file contains the following properties that have to be filled:
   
   ```bash
   # e.g. app.mydomain.com
   WIRETRUSTEE_DOMAIN=""
   # e.g. dev-24vkclam.us.auth0.com
   WIRETRUSTEE_AUTH0_DOMAIN=""
   # e.g. 61u3JMXRO0oOevc7gCkZLCwePQvT4lL0
   WIRETRUSTEE_AUTH0_CLIENT_ID=""
   # e.g. https://app.mydomain.com/
   WIRETRUSTEE_AUTH0_AUDIENCE=""
   # e.g. hello@mydomain.com
   WIRETRUSTEE_LETSENCRYPT_EMAIL=""
   ```
   > Other options are available, but they are automatically updated.
   
   Please follow the steps to get the values. 

4. Configure ```WIRETRUSTEE_AUTH0_DOMAIN``` ```WIRETRUSTEE_AUTH0_CLIENT_ID``` ```WIRETRUSTEE_AUTH0_AUDIENCE``` properties.          
   
   * To obtain these, please use [Auth0 React SDK Guide](https://auth0.com/docs/quickstart/spa/react/01-login#configure-auth0) up until "Install the Auth0 React SDK".
   
      :grey_exclamation: Use ```https://YOUR DOMAIN``` as ````Allowed Callback URLs````, ```Allowed Logout URLs```, ```Allowed Web Origins``` and ```Allowed Origins (CORS)```
   * set the variables in the ```setup.env```
5. Configure ```WIRETRUSTEE_AUTH0_AUDIENCE``` property. 
   
   * Check [Auth0 Golang API Guide](https://auth0.com/docs/quickstart/backend/golang) to obtain AuthAudience.
   * set the property in the ```setup.env``` file.
6. Configure ```WIRETRUSTEE_LETSENCRYPT_EMAIL``` property.
   
   This can be any email address. [Let's Encrypt](https://letsencrypt.org/) will create an account while generating a new certificate.    

7. Make sure all the properties set in the ```setup.env``` file and run: 
   
    ```bash
    ./configure.sh
    ```
   
   This will export all the properties as environment variables and generate ```docker-compose.yml``` and ```management.json``` files substituting required variables.

8. Run docker compose:

   ```bash
   docker-compose up -d
   ```
9. Optionally check the logs by running: 
        
    ```bash
    docker-compose logs signal
    docker-compose logs management
    docker-compose logs coturn
    docker-compose logs dashboard

10. Once the server is running, you can access the dashboard by https://$WIRETRUSTEE_DOMAIN
11. Adding a peer will require you to enter the management URL by following the steps in the page https://$WIRETRUSTEE_DOMAIN/add-peer and in the 3rd step:
```shell
sudo wiretrustee up --setup-key <PASTE-SETUP-KEY> --management-url https://$WIRETRUSTEE_DOMAIN:33073
```

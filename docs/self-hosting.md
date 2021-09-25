### Self-hosting
Wiretrustee is an open-source platform that can be self-hosted on your servers.

It relies on components developed by Wiretrustee Authors [Management Service](https://github.com/wiretrustee/wiretrustee/tree/main/management), [Management UI Dashboard](https://github.com/wiretrustee/wiretrustee-dashboard), [Signal Service](https://github.com/wiretrustee/wiretrustee/tree/main/signal), 
a 3rd party open-source STUN/TURN service [Coturn](https://github.com/coturn/coturn) and a 3rd party service [Auth0](https://auth0.com/).

All the components can be self-hosted except for the Auth0 service.
We chose Auth0 to "outsource" the user management part of the platform because we believe that implementing a proper user auth requires significant amount of time to make it right. 
We focused on connectivity instead.

If you would like to learn more about the architecture please refer to the [Wiretrustee Architecture section](architecture.md).

### Requirement

- Virtual machine offered by any cloud provider (e.g., AWS, DigitalOcean, Hetzner, Google Cloud, Azure ...). 
- Ubuntu 20.04 or later.
- Docker Compose installed (see [Install Docker Compose](https://docs.docker.com/compose/install/)).
- Domain name pointing to the public IP address of your server.
- Maybe a cup of coffee or tea :)

### Step-by-step guide

For this tutorial we will be using domain ```test.wiretrustee.com``` which points to our Ubuntu 20.04 machine hosted at Hetzner.

1. Create Auth0 account at [auth0.com](https://auth0.com/).
2. Login to your server, clone Wiretrustee repository:
   
   ```bash 
   git clone https://github.com/wiretrustee/wiretrustee.git wiretrustee/
   ```
   
   and switch to the ```wiretrustee/infrastructure_files/``` folder that contains docker compose file:
   
   ```bash 
   cd wiretrustee/infrastructure_files/
   ```
3. Prepare configuration files.
   
   To simplify the setup we have prepared a script to substitute required properties in the [docker-compose.yml.tmpl](https://github.com/wiretrustee/wiretrustee/blob/main/infrastructure_files/docker-compose.yml.tmpl) and [management.json.tmpl](https://github.com/wiretrustee/wiretrustee/blob/main/infrastructure_files/management.json.tmpl) files.
   
   The [setup.env](https://github.com/wiretrustee/wiretrustee/blob/main/infrastructure_files/setup.env) file contains the following properties that have to be filled:
   
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
   
   Please follow the steps to get the values.

2. Configure ```WIRETRUSTEE_AUTH0_DOMAIN``` ```WIRETRUSTEE_AUTH0_CLIENT_ID``` ```WIRETRUSTEE_AUTH0_AUDIENCE``` properties.          
   
   * To obtain these, please use [Auth0 React SDK Guide](https://auth0.com/docs/quickstart/spa/react/01-login#configure-auth0) up until "Install the Auth0 React SDK".
   
      :grey_exclamation: Use ```https://YOUR DOMAIN``` as ````Allowed Callback URLs````, ```Allowed Logout URLs```, ```Allowed Web Origins``` and ```Allowed Origins (CORS)```
   * set the variables in the ```setup.env```
3. Configure ```WIRETRUSTEE_AUTH0_AUDIENCE``` property. 
   
   * Check [Auth0 Golang API Guide](https://auth0.com/docs/quickstart/backend/golang) to obtain AuthAudience.
   * set the property in the ```setup.env``` file.
4. Configure ```WIRETRUSTEE_LETSENCRYPT_EMAIL``` property.
   
   This can be any email address. [Let's Encrypt](https://letsencrypt.org/) will create an account while creating a new domain.    

5. Make sure all the properties set in the ```setup.env``` file and run: 
   
    ```bash
    ./configure.sh
    ```
   
   This will export all the properties as environment variables and generate ```docker-compose.yml``` and ```management.json``` files substituting required variables.

6. Run docker compose:

   ```bash
   docker-compose up -d
   ```
5. Optionally check the logs by running: 
        
    ```bash
    docker-compose logs signal
    docker-compose logs management
    docker-compose logs coturn
    docker-compose logs dashboard
    ```
    

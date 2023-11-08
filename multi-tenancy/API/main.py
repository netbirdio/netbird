from fastapi import FastAPI, HTTPException, Security
from fastapi.security.api_key import APIKeyHeader
import subprocess
from pydantic import BaseModel

app = FastAPI()

#You should put this in a .env file
API_KEY = "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX" 
api_key_header = APIKeyHeader(name="X-API-Key")

class Instance(BaseModel):
    id: str 

def get_api_key(api_key_header: str = Security(api_key_header)) -> str:
    if api_key_header == API_KEY:
        return api_key_header
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or missing API Key",
    )

@app.post("/init")
async def init(instance: Instance, api_key: str = Security(get_api_key)):
    command = f"/opt/ZTNA/init.sh {instance.id}"
    subprocess.Popen(command.split(), stdin=None, stdout=None, stderr=None)

    content = f"""
{instance.id}.ephe.st:80, {instance.id}.ephe.st:443 {{ #{instance.id}
import security_headers #{instance.id}
reverse_proxy /signalexchange.SignalExchange/* h2c://signal{instance.id}:10000 #{instance.id}
reverse_proxy /api/* management{instance.id}:80 #{instance.id}
reverse_proxy /management.ManagementService/* h2c://management{instance.id}:80 #{instance.id}
reverse_proxy /zitadel.admin.v1.AdminService/* h2c://zitadel{instance.id}:8080 #{instance.id}
reverse_proxy /admin/v1/* h2c://zitadel{instance.id}:8080 #{instance.id}
reverse_proxy /zitadel.auth.v1.AuthService/* h2c://zitadel{instance.id}:8080 #{instance.id}
reverse_proxy /auth/v1/* h2c://zitadel{instance.id}:8080 #{instance.id}
reverse_proxy /zitadel.management.v1.ManagementService/* h2c://zitadel{instance.id}:8080 #{instance.id}
reverse_proxy /management/v1/* h2c://zitadel{instance.id}:8080 #{instance.id}
reverse_proxy /zitadel.system.v1.SystemService/* h2c://zitadel{instance.id}:8080 #{instance.id}
reverse_proxy /system/v1/* h2c://zitadel{instance.id}:8080 #{instance.id}
reverse_proxy /assets/v1/* h2c://zitadel{instance.id}:8080 #{instance.id}
reverse_proxy /ui/* h2c://zitadel{instance.id}:8080 #{instance.id}
reverse_proxy /oidc/v1/* h2c://zitadel{instance.id}:8080 #{instance.id}
reverse_proxy /saml/v2/* h2c://zitadel{instance.id}:8080 #{instance.id}
reverse_proxy /oauth/v2/* h2c://zitadel{instance.id}:8080 #{instance.id}
reverse_proxy /.well-known/openid-configuration h2c://zitadel{instance.id}:8080 #{instance.id}
reverse_proxy /openapi/* h2c://zitadel{instance.id}:8080 #{instance.id}
reverse_proxy /debug/* h2c://zitadel{instance.id}:8080 #{instance.id}
reverse_proxy /* dashboard{instance.id}:80 #{instance.id}
}} #{instance.id}
"""
    with open("/opt/ZTNA/caddy/Caddyfile", 'a') as file:
        file.write(content)

    reloadCaddy = "/usr/bin/docker-compose exec -T -w /etc/caddy caddy caddy reload"
    subprocess.Popen(reloadCaddy.split(), stdin=None, stdout=None, stderr=None, cwd='/opt/ZTNA/caddy')

    return {'status': 'ok'}


@app.post("/remove")
async def remove(instance: Instance, api_key: str = Security(get_api_key)):
    command = f"/usr/bin/docker-compose down --volumes && rm -Rf /opt/ZTNA/{instance.id}"
    subprocess.Popen(command, stdin=None, stdout=None, stderr=None, cwd=f"/opt/ZTNA/{instance.id}", shell=True)

    with open('/opt/ZTNA/caddy/Caddyfile', 'r') as file:
        linee = file.readlines()

    with open('/opt/ZTNA/caddy/Caddyfile', 'w') as file:
        for linea in linee:
            if f"#{instance.id}" not in linea:
                file.write(linea)

    reloadCaddy = "/usr/bin/docker-compose exec -T -w /etc/caddy caddy caddy reload"
    subprocess.Popen(reloadCaddy.split(), stdin=None, stdout=None, stderr=None, cwd='/opt/ZTNA/caddy')

    return {'status': 'ok'}

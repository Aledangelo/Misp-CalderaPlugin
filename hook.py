from aiohttp_jinja2 import template
from app.service.auth_svc import check_authorization

name = "misp"
description = "Plugin to load event from MISP to Caldera"
address = "/plugin/misp/gui"

def enable(services):
    app = services.get('app_svc').application
    misp = MispLoader(services)
    app.router.add_route('*', '/plugin/misp/gui', misp.splash)
    app.router.add_route('POST', '/plugin/misp/start', misp.start)


class MispLoader:
    def __init__(self, services):
        self.services = services
        self.auth_svc = services.get('auth_svc')

    @check_authorization
    @template('misp.html')
    async def splash(self, request):
        return(dict())

    @check_authorization
    async def start(self, request):
        data = await request.json()
        

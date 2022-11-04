from aiohttp_jinja2 import template, web
from app.service.auth_svc import check_authorization

name = "misp"
description = "Plugin to load event from MISP to Caldera"
address = '/plugin/misp/gui'

async def enable(services):
    app = services.get('app_svc').application
    fetcher = AbilityFetcher(services)
    app.router.add_route('*', '/get/abilities', fetcher.get_abilities)
    app.router.add_route('*', '/plugin/misp/gui', fetcher.splash)

class AbilityFetcher:
    def __init__(self, services):
        self.services = services
        self.auth_svc = services.get('auth_svc')

    async def get_abilities(self, request):
        abilities = await self.services.get('data_svc').locate('abilities')
        return web.json_response(dict(abilities=[a.display for a in abilities]))

    @check_authorization
    @template('misp.html')
    async def splash(self, request):
        abilities = await self.services.get('data_svc').locate('abilities')
        return(dict(abilities=[a.display for a in abilities]))
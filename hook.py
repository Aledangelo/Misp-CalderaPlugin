from app.utility.base_world import BaseWorld
from plugins.misp.app.misp_gui import MispGUI
from plugins.misp.app.misp_api import MispAPI

name = 'Misp'
description = 'Plugin to load event from MISP to Caldera'
address = '/plugin/misp/gui'
access = BaseWorld.Access.RED


async def enable(services):
    app = services.get('app_svc').application
    misp_gui = MispGUI(services, name=name, description=description)
    app.router.add_static('/misp', 'plugins/misp/static/', append_version=True)
    app.router.add_route('GET', '/plugin/misp/gui', misp_gui.splash)

    misp_api = MispAPI(services)
    # Add API routes here
    app.router.add_route('POST', '/plugin/misp/mirror', misp_api.mirror)
    app.router.add_route('POST', '/plugin/misp/start', misp_gui.start)


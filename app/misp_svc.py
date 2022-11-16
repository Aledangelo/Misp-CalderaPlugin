import logging
import json
import re
import os
from pymisp import PyMISP
from app.objects.c_adversary import Adversary
from app.objects.c_operation import Operation
from app.objects.secondclass.c_fact import Fact
from app.objects.c_source import Source

class MispService:
    def __init__(self, services):
        self.services = services
        self.file_svc = services.get('file_svc')
        self.data_svc = services.get('data_svc')
        self.log = logging.getLogger('misp_svc')
        self.misp_dir = os.path.join('plugins', 'misp')
        self.data_dir = os.path.join(self.misp_dir, 'data')

    async def foo(self):
        return 'bar'

    async def search_event(self, event_id, misp_base_url, misp_api_key):
        misp = PyMISP(misp_base_url, misp_api_key, False)
        self.log.info("[Misp Plugin] Get event from MISP")
        return misp.get_event(event_id)

    async def load_abilities(self):
        abilities = await self.services.get('data_svc').locate('abilities')
        return abilities

    

    async def save_operation(self, event, adv_description, abilities):
        self.log.info("[Misp Plugin] Saving Adversary Profile...")
        adversary = Adversary(name=event['Event']['info'] + "_Adv", description=adv_description, atomic_ordering=abilities)
        await self.data_svc.store(adversary)

        facts = self.get_facts(attributes=event['Event']['Attribute'])
        source = Source(name=event['Event']['info'] + "_Src", facts=facts)
        await self.data_svc.store(source)

        operation = Operation(adversary=adversary.display, name=event['Event']['info'] + "_Op", source=source)
        await self.data_svc.store(operation)
        return operation

    def checkPlatform(self, ability, platform):
        for executor in ability["executors"]:
            if str(executor["platform"]) == str(platform):
                return True

        return False    

    def findAbility(self, technique_id, tactics, abilities, platform, my_abilities, added_default):
        def_ab = open("plugins/misp/conf/default_abilities.json", "r")
        default_abilities = json.load(def_ab)

        multi = False
        if len(tactics) > 1:
            multi = True

        gFind = False
        for tactic in tactics:
            for ab in abilities:
                ability = ab.display
                if str(ability["technique_id"]) == str(technique_id):
                    if str(ability["tactic"]) == str(tactic):
                        if self.checkPlatform(ability=ability, platform=platform):
                            my_abilities.append(ability)
                            gFind = True
                            break

        if not gFind and multi:
            for ab in abilities:
                ability = ab.display
                if str(ability["technique_id"]) == str(technique_id):
                    if str(ability["tactic"]) == "multiple":
                        if self.checkPlatform(ability=ability, platform=platform):
                            my_abilities.append(ability)
                            gFind = True
                            break

        if not gFind and '.' in str(technique_id):
            temp = str(technique_id).split(".")
            new_id = temp[0]
            for tactic in tactics:
                for ab in abilities:
                    ability = ab.display
                    if str(ability["technique_id"]) == new_id:
                        if str(ability["tactic"]) == str(tactic):
                            if self.checkPlatform(ability=ability, platform=platform):
                                my_abilities.append(ability)
                                gFind = True
                                break


        if not gFind:
            added = False
            for tactic in tactics:
                if str(tactic) in added_default:
                    break
                for default in default_abilities[str(tactic)]:
                    for ab in abilities:
                        ability = ab.display
                        if str(ability["name"]) == default:
                            if self.checkPlatform(ability=ability, platform=platform):
                                my_abilities.append(ability)
                                gFind = True
                                break
                if added:
                    added_default.append(str(tactic))

        return my_abilities, added_default

    def order_ability(self, attributes):
        ordered = []
        for attribute in attributes:
            try:
                if len(attribute['Tag']) > 0:
                    for tag in attribute['Tag']:
                        if "attack-flow" in tag['name']:
                            temp = str(tag['name']).split(":")
                            n = temp[1]
                            for galaxy in attribute['Galaxy']:
                                for cluster in galaxy['GalaxyCluster']:
                                    if cluster['type'] == "mitre-attack-pattern":
                                        v = str(cluster['value']).split("-")
                                        i = 1
                                        while True:
                                            try:
                                                t_id = str(v[i]).replace(" ", "")
                                            except Exception as e:
                                                quit(1)
                                            if re.search("^T[1234567890]+\.*[1234567890]*", t_id):
                                                break
                                            i += 1
                                        ordered.append((int(n), t_id))
            except Exception:
                pass

        ordered.sort()
        return ordered

    def get_facts(self, attributes):
        facts = []
        for attribute in attributes:
            try:
                if len(attribute['Tag']) > 0:
                    for tag in attribute['Tag']:
                        if "fact-source" in tag['name']:
                            if '|' in str(attribute['type']) and '|' in attribute['value']:
                                att_types = str(attribute['type']).split("|")
                                att_values = str(attribute['value']).split("|")

                                if len(att_types) == len(att_values):
                                    for i in range(0, len(att_types)):
                                        fact_name = str(att_types[i]) + '.' + str(attribute['id'])
                                        fact = Fact(trait=fact_name, value=att_values[i])
                                        facts.append(fact)
                                else:
                                    fact_name = str(attribute['type']) + '.' + str(attribute['id'])
                                    fact = Fact(trait=fact_name, value=attribute['value'])
                                    facts.append(fact)
                            
                            else:
                                fact_name = str(attribute['type']) + '.' + str(attribute['id'])
                                fact = Fact(trait=fact_name, value=attribute['value'])
                                facts.append(fact)
            except Exception:
                pass

        return facts

    async def analyze_galaxies(self, event, platform, abilities):
        galaxy = event["Event"]["Galaxy"]
        ordered = self.order_ability(event['Event']['Attribute'])
        self.log.info(ordered)

        my_abilities = []
        added_default = []

        for g in galaxy:
            if g["type"] == "mitre-attack-pattern":
                galaxyCluster = g["GalaxyCluster"]
                for cluster in galaxyCluster:
                    actual_value = str(cluster["value"]).split("-")
                    
                    i = 1
                    while True:
                        try:
                            t_id = str(actual_value[i]).replace(" ", "")
                        except Exception as e:
                            self.log.error(e)
                            return
                        if re.search("^T[1234567890]+\.*[1234567890]*", t_id):
                            break
                        i += 1

                    tactics = []
                    kill_chain = cluster["meta"]["kill_chain"]
                    for k_chain in kill_chain:
                        k = str(k_chain).split(":")
                        tactics.append(str(k[1]).replace(" ", ""))
                    
                    my_abilities, added_default = self.findAbility(technique_id=t_id, tactics=tactics, abilities=abilities, platform=platform, my_abilities=my_abilities, added_default=added_default)
                break

        ordered_abilities = []
        for o in ordered:
            for a in my_abilities:
                if str(a['technique_id']) in str(o[1]):
                    ordered_abilities.append(a["ability_id"])
                    my_abilities.remove(a)

        if len(my_abilities) > 0:
            for a in my_abilities:
                ordered_abilities.append(a["ability_id"])

        return ordered_abilities
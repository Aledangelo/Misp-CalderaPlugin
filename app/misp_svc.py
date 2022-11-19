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

    

    async def save_operation(self, event, adv_description, abilities, platform):
        self.log.info("[Misp Plugin] Saving Adversary Profile...")
        adversary = Adversary(name=event['Event']['info'] + "_Adv", description=adv_description, atomic_ordering=abilities)
        await self.data_svc.store(adversary)

        facts = await self.get_facts(attributes=event['Event']['Attribute'], ability_ids=abilities, platform=platform)
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

        filtered_by_platform = []
        

        multi = False
        if len(tactics) > 1:
            multi = True

        for ab in abilities:
            ability = ab.display
            if str(ability['technique_id']) in str(technique_id) and self.checkPlatform(ability=ability, platform=platform):
                filtered_by_platform.append(ability)

        filtered_by_tactic = []
        for ok in filtered_by_platform:
            if ok['tactic'] in tactics:
                filtered_by_tactic.append(ok)

        if len(filtered_by_tactic) == 0 and multi:
            for ok in filtered_by_platform:
                if ok['tactic'] == "multiple":
                    filtered_by_tactic.append(ok)

        filtered_by_id = []
        for t in filtered_by_tactic:
            if str(t['technique_id']) == str(technique_id):
                filtered_by_id.append(t)

        if len(filtered_by_id) == 0  and '.' in str(technique_id):
            splitted_id = str(technique_id).split(".")
            tech_id = splitted_id[0]
            for t in filtered_by_tactic:
                if str(t['technique_id']) == str(tech_id):
                    filtered_by_id.append(t)
                
        if len(filtered_by_id) > 0:
            my_abilities.append(filtered_by_id[0])
        else:
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

    def is_ability(self, ability, abilities):
        for a in abilities:
            if str(a) == str(ability):
                return True
        return False

    async def get_facts(self, attributes, ability_ids, platform):
        facts = []
        abilities = await self.data_svc.locate("abilities")
        for attribute in attributes:
            try:
                if len(attribute['Tag']) > 0:
                    for tag in attribute['Tag']:
                        if "fact-source" in tag['name']:
                            att_value = attribute['value']
                            for galaxy in attribute['Galaxy']:
                                for cluster in galaxy['GalaxyCluster']:
                                    if cluster['type'] == "mitre-attack-pattern":
                                        ability_to_check = str(cluster['value']).split("-")
                                        i = 1
                                        while True:
                                            try:
                                                t_id = str(ability_to_check[i]).replace(" ", "")
                                            except Exception:
                                                return
                                            if re.search("^T[1234567890]+\.*[1234567890]*", t_id):
                                                break
                                            i += 1
                                        break
                            
                            for ability in abilities:
                                ab = ability.display
                                if str(ab['technique_id']) in str(t_id) and self.is_ability(ability=ab['ability_id'], abilities=ability_ids):
                                    if self.checkPlatform(ability=ab, platform=platform):
                                        for executor in ab['executors']:
                                            if re.search("#{.+}", str(executor['command'])):
                                                temp_command = str(executor['command']).split("#{")
                                                att_value_split = str(att_value).split("|")
                                                value_split_len = len(att_value_split)
                                                count_len = 0
                                                perv_fact_name = ""
                                                for i in range(0, len(temp_command)):
                                                    try:
                                                        if re.search("}", str(temp_command[i + 1])):
                                                            t = str(temp_command[i + 1]).split("}")
                                                            fact_name = t[0]
                                                            if str(fact_name) != str(perv_fact_name):
                                                                fact = Fact(trait=fact_name, value=att_value_split[count_len])
                                                                facts.append(fact)
                                                                perv_fact_name = fact_name
                                                                if count_len + 1 < value_split_len:
                                                                    count_len += 1
                                                    except Exception:
                                                        pass
            except Exception:
                pass

        return facts

    async def analyze_galaxies(self, event, platform, abilities):
        galaxy = event["Event"]["Galaxy"]
        ordered = self.order_ability(event['Event']['Attribute'])

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
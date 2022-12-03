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

        self.log.info("[Misp Plugin] Saving Fact Sources...")
        facts = await self.get_facts(attributes=event['Event']['Attribute'], ability_ids=abilities, platform=platform)
        sources = await self.data_svc.locate("sources")
        for source in sources:
            for fact in source.facts:
                facts.append(fact)

        src = Source(name=event['Event']['info'] + "_Src", facts=facts)
        await self.data_svc.store(src)

        planners = await self.data_svc.locate('planners')
        for p in planners:
            if p.name == "atomic":
                planner = p
        
        self.log.info("[Misp Plugin] Saving Operation...")
        operation = Operation(adversary=adversary.display, name=event['Event']['info'] + "_Op", source=src, planner=planner)
        await self.data_svc.store(operation)
        return operation

    def checkPlatform(self, ability, platform):
        for executor in ability["executors"]:
            if str(executor["platform"]) == str(platform):
                return True

        return False    

    def findAbility(self, technique_id, tactics, abilities, platform, my_abilities, added_default, out, in_fact, in_ref):
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

        filtered_by_parsers = []
        if out:
            for tac in filtered_by_tactic:
                for executor in tac['executors']:
                    if len(executor['parsers']) > 0:
                        filtered_by_parsers.append(tac)
                        break
        else:
            filtered_by_parsers = filtered_by_tactic

        filtered_by_command = []
        if in_fact:
            if in_ref == "":
                for p in filtered_by_parsers:
                    for executor in p['executors']:
                        if re.search("#{.+}", str(executor['command'])):
                            filtered_by_command.append(p)
                            break
            else:
                for p in filtered_by_parsers:
                    for executor in p['executors']:
                        if "#{" + str(in_ref) + "}" in executor['command']:
                            filtered_by_command.append(p)
                            break
        else:
            filtered_by_command = filtered_by_parsers

        filtered_by_id = []
        for t in filtered_by_command:
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
            if out:
                return my_abilities, added_default, str(filtered_by_id[0]['executors'][0]['parsers'][0]['parserconfigs'][0]['source'])
        else:
            def_ab = open("plugins/misp/conf/default_abilities.json", "r")
            default_abilities = json.load(def_ab)
            added = False
            for tactic in tactics:
                if str(tactic) in added_default:
                    break
                for default in default_abilities[str(tactic)]:
                    for ab in abilities:
                        ability = ab.display
                        if str(ability["name"]) == default:
                            if self.checkPlatform(ability=ability, platform=platform):
                                added = True
                                my_abilities.append(ability)
                                break
                if added:
                    added_default.append(str(tactic))
        
        return my_abilities, added_default, ""

    def order_ability(self, attributes):
        ordered = []
        preliminary = []
        post = []
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
                                                self.log.error(e)
                                                quit(1)
                                            if re.search("^T[1234567890]+\.*[1234567890]*", t_id):
                                                break
                                            i += 1
                                        ordered.append((int(n), t_id))
                        elif tag['name'] == "preliminary" or tag['name'] == "post":
                            for galaxy in attribute['Galaxy']:
                                for cluster in galaxy['GalaxyCluster']:
                                    if cluster ['type'] == "mitre-attack-pattern":
                                        val = str(cluster['value']).split("-")
                                        index = 1
                                        while True:
                                            try:
                                                tech_id = str(val[1]).replace(" ", "")
                                            except Exception as e:
                                                self.log.error(e)
                                                quit(1)
                                            if re.search("^T[1234567890]+\.*[1234567890]*", tech_id):
                                                break
                                            index += 1
                                        if tag['name'] == "preliminary":
                                            preliminary.append(tech_id)
                                        elif tag['name'] == "post":
                                            post.append(tech_id)
            except Exception:
                pass

        ordered.sort()

        return ordered, preliminary, post

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
                            
                            c = 0
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
                                            else:
                                                fact = Fact(trait="Fact-" + str(c), value=att_value)
                                                c += 1
                                                facts.append(fact)
            except Exception:
                pass

        return facts

    async def analyze_galaxies(self, event, platform, abilities):
        galaxy = event["Event"]["Galaxy"]
        ordered, preliminary, post = self.order_ability(event['Event']['Attribute'])

        my_abilities = []
        added_default = []
        out_id = []
        in_id = []

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

                    check_out, out_ref = self.is_out(attributes=event['Event']['Attribute'], technique=t_id)
                    check_in, in_ref = self.is_in(attributes=event['Event']['Attribute'], technique=t_id)
                    fact_check = self.has_fact(attributes=event['Event']['Attribute'], technique=t_id)
                    if check_out or check_in:
                        if check_out:
                            out_id.append((out_ref, t_id, tactics))
                        if check_in:
                            in_id.append((in_ref, t_id, tactics))
                    elif fact_check:
                        my_abilities, added_default, not_used = self.findAbility(technique_id=t_id, tactics=tactics, abilities=abilities, platform=platform, my_abilities=my_abilities, added_default=added_default, out=False, in_fact=True, in_ref="")
                    else:
                        my_abilities, added_default, not_used = self.findAbility(technique_id=t_id, tactics=tactics, abilities=abilities, platform=platform, my_abilities=my_abilities, added_default=added_default, out=False, in_fact=False, in_ref=None)
                break

        out_id.sort()
        in_id.sort()
        

        saved_output = []

        while len(out_id) > 0 and len(in_id) > 0:
            out_to_remove = []
            in_to_remove = []
            for o in out_id:
                is_input = False
                for k in in_id:
                    if o[1] == k[1]:
                        is_input = True
                if is_input == False:
                    my_abilities, added_default, source_out = self.findAbility(technique_id=o[1], tactics=o[2], abilities=abilities, platform=platform, my_abilities=my_abilities, added_default=added_default, out=True, in_fact=False, in_ref=None)
                    saved_output.append((o[0], source_out))
                    out_to_remove.append(o)
                else:
                    for s in saved_output:
                        for inp in in_id:
                            if s[0] == inp[0]:
                                my_abilities, added_default, source_out = self.findAbility(technique_id=o[1], tactics=o[2], abilities=abilities, platform=platform, my_abilities=my_abilities, added_default=added_default, out=True, in_fact=True, in_ref=s[1])
                                saved_output.append((o[0], source_out))
                                saved_output.remove(s)
                                out_to_remove.append(o)
                                in_to_remove.append(inp)
                                break

            for otr in out_to_remove:
                out_id.remove(otr)

            for itr in in_to_remove:
                in_id.remove(itr)

            in_to_remove = []
            for inp in in_id:
                for s in saved_output:
                    if s[0] == inp[0]:
                        my_abilities, added_default, not_used = self.findAbility(technique_id=inp[1], tactics=inp[2], abilities=abilities, platform=platform, my_abilities=my_abilities, added_default=added_default, out=False,  in_fact=True, in_ref=s[1])
                        saved_output.remove(s)
                        in_to_remove.append(inp)
                        break

            for it in in_to_remove:
                in_id.remove(it)

        ordered_abilities = []
        for pre in preliminary:
            for a in my_abilities:
                if str(a['technique_id']) in str(pre):
                    ordered_abilities.append(a['ability_id'])
                    my_abilities.remove(a)

        for o in ordered:
            for a in my_abilities:
                if str(a['technique_id']) in str(o[1]):
                    ordered_abilities.append(a["ability_id"])
                    my_abilities.remove(a)

        for p in post:
            for a in my_abilities:
                if str(a['technique_id']) in str(p):
                    ordered_abilities.append(a['ability_id'])
                    my_abilities.remove(a)

        if len(my_abilities) > 0:
            for a in my_abilities:
                ordered_abilities.append(a["ability_id"])

        return ordered_abilities

    def is_out(self, attributes, technique):
        for attribute in attributes:
            try:
                if len(attribute['Tag']) > 0:
                    for tag in attribute['Tag']:
                        if "out-to-fact" in tag['name']:
                            split_name = str(tag['name']).split(":")
                            out_id = split_name[1]
                            for galaxy in attribute['Galaxy']:
                                if galaxy['type'] == "mitre-attack-pattern":
                                    for cluster in galaxy['GalaxyCluster']:
                                        if cluster['type'] == "mitre-attack-pattern":
                                            if str(technique) in str(cluster['value']):
                                                return True, out_id
            except Exception:
                pass
        return False, ""

    def has_fact(self, attributes, technique):
        for attribute in attributes:
            try:
                if len(attribute['Tag']) > 0:
                    for tag in attribute['Tag']:
                        if "fact-source" in tag['name']:
                            for galaxy in attribute['Galaxy']:
                                if galaxy['type'] == "mitre-attack-pattern":
                                    for cluster in galaxy['GalaxyCluster']:
                                        if cluster['type'] == "mitre-attack-pattern":
                                            if str(technique) in cluster['value']:
                                                return True
            except Exception:
                pass
        return False

    def is_in(self, attributes, technique):
        for attribute in attributes:
            try:
                if len(attribute['Tag']) > 0:
                    for tag in attribute['Tag']:
                        if "fact-to-in" in str(tag['name']):
                            split_name = str(tag['name']).split(":")
                            in_id = split_name[1]
                            for galaxy in attribute['Galaxy']:
                                if galaxy['type'] == "mitre-attack-pattern":
                                    for cluster in galaxy['GalaxyCluster']:
                                        if cluster['type'] == "mitre-attack-pattern":
                                            if str(technique) in str(cluster['value']):
                                                return True, in_id
            except Exception:
                pass
        return False, ""
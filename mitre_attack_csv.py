#!/usr/bin/python3 

import csv
import json
import requests


url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
outfile = "enterprise-attack.csv"

print("Fetching latest enterprise-attack.json ...")
d = requests.get(url)
assert (d.status_code==200),"Failure fetching url"

print("Parsing file ...")
j = d.json()
assert ('spec_version' in j), "Failure reading version info in JSON file"
assert ('objects' in j), "Failure reading objects in JSON file"
assert (j['spec_version'] == '2.0'), "Unsupported STIX version"

o = {}	# dict objects
for i in j['objects']:
	assert ('type' in i), f"type information is missing in entry {i}"
	assert ('id' in i), f"id field is missing in entry {i}"

	# skip revoked or deprecated items
	if ('revoked' in i and i['revoked']==True) or ('x_mitre_deprecated' in i and i['x_mitre_deprecated']==True):
		continue

	id = i['id']
	t = i['type']

	if t not in o: o[t] = {}
	o[t][id] = i

print("Generating list of tactics ...")

# Generate a list of tactics
tactics = {}
for t in o['x-mitre-tactic']:
	short_name = o['x-mitre-tactic'][t]["x_mitre_shortname"]
	name = o['x-mitre-tactic'][t]["name"]
	id = o['x-mitre-tactic'][t]['external_references'][0]["external_id"]
	url = o['x-mitre-tactic'][t]['external_references'][0]["url"]

	tactics[short_name] = name

# minature markdown
import re
def minimd(s,fmt="text"):

	code = re.compile('<code>(?P<codeblock>.*?)</code>')

	bold = re.compile('\*\*(.*?)\*\*')
	link = re.compile('\[([^[]*?)\]\((.*?)\)')
	header = re.compile('(?:^|\n)#+([^\n]*)')

	if fmt=="html":
		s = code.sub(lambda x: '<code>{}</code>'.format(x.group('codeblock').replace('<','&lt;')), s)
		s = bold.sub(r'<b>\1</b>',s)
		s = link.sub(r'<a href="\2">\1</a>', s)
		s = header.sub(r'<b><u>\1</u></b><br/>',s)

		# rewrite links to mitre page to this one (mitre to internal link)
		mtil = re.compile('"https://attack.mitre.org/techniques/(?P<technique>.*?)"')
		s = mtil.sub(lambda x: '"#{}"'.format(x.group('technique').replace('/','.')), s)

		s = s.replace('\n','<br/>')

	elif fmt=="text":
		# tidy headers
		s = header.sub(r'# \1 #\n',s)
	
		# neaten code
		s = code.sub(lambda x: '`{}`'.format(x.group('codeblock')), s)

		# rewrite links to mitre page to plaintext
		mtil = re.compile('https://attack.mitre.org/(techniques|tactics|software)/(?P<technique>[^\])"]+)')
		s = mtil.sub(lambda x: '{}'.format(x.group('technique').replace('/','.')), s)

		# remove <br>
		s = s.replace('<br>','\n')
		

	return s

print("Generating list of techniques ...")
# Generate a list of techniques
tech = {}
for tn in o['attack-pattern']:
	t = o['attack-pattern'][tn]

	mitre_id = ""
	mitre_url = ""
	if 'external_references' in t:
		for r in t['external_references']:
			if 'source_name' in r and r['source_name'] == 'mitre-attack':
				mitre_id = r['external_id']
				mitre_url = r['url']
	assert mitre_id!="",f"Didn't find a mitre id for {t}"

	name = t['name'] if 'name' in t else ""
	platforms = t['x_mitre_platforms'] if 'x_mitre_platforms' in t else []
	kill_chain_phases = t['kill_chain_phases'] if 'kill_chain_phases' in t else []
	kill_chain_phases = [tactics[x['phase_name']] for x in kill_chain_phases if x['kill_chain_name']=="mitre-attack"]
	data_sources = t['x_mitre_data_sources'] if 'x_mitre_data_sources' in t else [] 
	description = t['description'] if 'description' in t else ""
	description = minimd(description)
	detection = t['x_mitre_detection'] if 'x_mitre_detection' in t else ""
	detection = minimd(detection)

	tech[mitre_id] = (name, tn, mitre_url, platforms, kill_chain_phases, data_sources, detection, description)

print("Generating CSV file ...")
with open(outfile,'w',newline='\n') as out:
	writer = csv.DictWriter(out, ['name', 'id', 'url', 'platforms', 'kill chain phases', 'description', 'data sources', 'detection'], quoting=csv.QUOTE_ALL)
	writer.writeheader()	

	for tid in sorted(tech.keys()):
		t = tech[tid]
	 
		name = t[0]
		tn = t[1]
		mitre_url = t[2]
		platforms = ', '.join(t[3])
		kill_chain_phases = ', '.join(t[4])
		data_sources = ', '.join(t[5])
		detection = t[6]
		description = t[7]

		writer.writerow({'name':name, 'id':tid, 'url':mitre_url, 'platforms':platforms, 'kill chain phases':kill_chain_phases, 'description':description, 'data sources':data_sources, 'detection':detection})

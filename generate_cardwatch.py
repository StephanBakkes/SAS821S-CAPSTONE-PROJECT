#!/usr/bin/env python3
"""Reproducible, entirely synthetic CardWatch teaching dataset. Python stdlib only."""
import argparse, csv, hashlib, json, random, zipfile
from collections import Counter
from datetime import datetime, timedelta
from pathlib import Path

SEED=82119
START=datetime(2026,6,13)
END=datetime(2026,9,25)
ANALYSIS=datetime(2026,6,27)
# Region and locality names follow the Namibian government's local authority lists.
# A few localities are officially classified as villages; the branch still has a real place name.
LOCATIONS=(
 ('Khomas','KHO','Windhoek','WDH','municipality'),
 ('Erongo','ERG','Walvis Bay','WVB','municipality'),
 ('Erongo','ERG','Swakopmund','SWK','municipality'),
 ('Oshana','OSA','Oshakati','OSK','town'),
 ('Kavango East','KVE','Rundu','RUN','town'),
 ('Otjozondjupa','OTJ','Otjiwarongo','OTW','municipality'),
 ('//Kharas','KHA','Keetmanshoop','KTM','municipality'),
 ('Zambezi','ZAM','Katima Mulilo','KTM','town'),
 ('Oshikoto','OSI','Tsumeb','TSU','municipality'),
 ('Omaheke','OME','Gobabis','GOB','municipality'),
 ('Hardap','HAR','Rehoboth','REH','town'),
 ('Oshana','OSA','Ondangwa','OND','town'),
 ('Kavango West','KVW','Nkurenkuru','NKR','town'),
 ('Ohangwena','OHA','Eenhana','EEN','town'),
 ('Omusati','OMU','Outapi','OUT','town'),
 ('Kunene','KUN','Opuwo','OPU','town'),
 ('Erongo','ERG','Karibib','KRB','town'),
 ('Erongo','ERG','Omaruru','OMR','municipality'),
 ('Erongo','ERG','Arandis','ARA','town'),
 ('Erongo','ERG','Henties Bay','HEN','municipality'),
 ('Erongo','ERG','Usakos','USA','town'),
 ('Otjozondjupa','OTJ','Okahandja','OKH','municipality'),
 ('Otjozondjupa','OTJ','Grootfontein','GRF','municipality'),
 ('Otjozondjupa','OTJ','Otavi','OTA','town'),
 ('Otjozondjupa','OTJ','Okakarara','OKR','town'),
 ('Kavango East','KVE','Divundu','DIV','village'),
 ('Zambezi','ZAM','Bukalo','BUK','village'),
 ('Ohangwena','OHA','Helao Nafidi','HNF','town'),
 ('Ohangwena','OHA','Okongo','OKO','village'),
 ('Oshana','OSA','Ongwediva','ONG','town'),
 ('Oshikoto','OSI','Oniipa','ONI','town'),
 ('Oshikoto','OSI','Omuthiya','OMT','town'),
 ('Omusati','OMU','Oshikuku','OSU','town'),
 ('Omusati','OMU','Okahao','OKA','town'),
 ('Omusati','OMU','Ruacana','RUA','town'),
 ('Kunene','KUN','Outjo','OTJ','municipality'),
 ('Kunene','KUN','Khorixas','KHX','town'),
 ('Hardap','HAR','Mariental','MAR','municipality'),
 ('Hardap','HAR','Aranos','ARN','town'),
 ('//Kharas','KHA','Luderitz','LUD','town'),
 ('//Kharas','KHA','Oranjemund','ORJ','town'),
 ('Omaheke','OME','Otjinene','OTN','village'),
)
COLUMNS={
 'branches.csv':'branch_id,branch_name,region,region_code,town,town_code,locality_type,profile,analysis_scope,trading_open,trading_close,pos_subnet,server_subnet,admin_subnet,staff_count',
 'devices.csv':'device_id,branch_id,device_type,ip_address,subnet,os_name,os_version,managed,analysis_scope',
 'shifts.csv':'shift_id,branch_id,operator_id,shift_start,shift_end,role',
 'pos_events.csv':'event_id,timestamp,branch_id,terminal_id,operator_id,shift_id,event_type,txn_ref,tender_type,amount,status_code,supervisor_override',
 'payment_auth.csv':'auth_id,auth_timestamp,branch_id,terminal_id,txn_ref,card_token,card_surrogate,amount,response_code,entry_mode,dispute_flag,dispute_date',
 'inventory_exceptions.csv':'exception_id,timestamp,branch_id,terminal_id,event_type,item_count,value,supervisor_override',
 'edr_events.csv':'edr_id,timestamp,branch_id,host_id,process_name,process_hash,parent_process,command_line,user_context,persistence_key,module_load,network_connect',
 'network_flows.csv':'flow_id,timestamp,branch_id,src_device_id,src_ip,dst_ip,dst_port,protocol,bytes_out,bytes_in,duration_seconds,action,url_host,src_port',
 'dns_logs.csv':'dns_id,timestamp,branch_id,device_id,src_ip,resolver_ip,query_name,query_type,response_code,answer_ip,query_length',
 'authentication_logs.csv':'auth_event_id,timestamp,branch_id,device_id,account_id,username,account_role,auth_source,source_ip,source_device_id,result,event_id,shift_id,session_id',
 'system_logs.csv':'system_event_id,timestamp,branch_id,device_id,provider,event_id,level,message,process_name',
 'soc_tickets.csv':'ticket_id,opened_at,branch_id,terminal_id,source,narrative_text,resolution_text',
 'ground_truth_private.csv':'terminal_id,branch_id,compromise_start,compromise_end,entry_vector,parent_device_id,vpn_session_id,first_exfiltration,notes',
}

def write_csv(path,name,rows):
 with (path/name).open('w',newline='',encoding='utf-8') as f:
  w=csv.DictWriter(f,fieldnames=COLUMNS[name].split(','),extrasaction='ignore'); w.writeheader(); w.writerows(rows)

def ts(t):return t.strftime('%Y-%m-%dT%H:%M:%S')
def h(s):return hashlib.sha256(s.encode()).hexdigest()
def token(i):return 'CT_'+h('CardWatch-only-'+str(i))[:20]
def event_time(day,hour,minute=0):return day+timedelta(hours=hour,minutes=minute)

def main(out,seed):
 rng=random.Random(seed); out.mkdir(parents=True,exist_ok=True)
 rows={k:[] for k in COLUMNS}; count=Counter()
 def add(name,**kw):
  count[name]+=1
  if name=='authentication_logs.csv':
   kw.setdefault('username',kw['account_id'])
  prefix={'pos_events.csv':'PE','payment_auth.csv':'PA','inventory_exceptions.csv':'IE','edr_events.csv':'ED','network_flows.csv':'NF','dns_logs.csv':'DN','authentication_logs.csv':'AU','system_logs.csv':'SY','soc_tickets.csv':'TK'}.get(name)
  if prefix:
   id_field=COLUMNS[name].split(',')[0]; kw[id_field]=f'{prefix}{count[name]:08d}'
  rows[name].append(kw)
 branches={};devices={}; terminals=[]; analyzed=[]
 for i,(region,region_code,town,town_code,locality_type) in enumerate(LOCATIONS,1):
  bid=f'NRG-{region_code}-{town_code}-{i:03d}'
  profile='urban' if i<=12 else ('medium' if i<=30 else 'rural')
  npos=(5 if i<=6 else 4) if i<=12 else (5 if i<=18 else (4 if i<=30 else 3))
  subnet=f'10.{40+i}.10.0/24';servernet=f'10.{40+i}.20.0/24';adminnet=f'10.{40+i}.30.0/24'
  scope=i<=12;open_h=7 if profile=='urban' else 8; close_h=21 if profile=='urban' else 19
  rows['branches.csv'].append(dict(branch_id=bid,branch_name=f'{town} Branch',region=region,region_code=region_code,town=town,town_code=town_code,locality_type=locality_type,profile=profile,analysis_scope=int(scope),trading_open=f'{open_h:02d}:00',trading_close=f'{close_h:02d}:00',pos_subnet=subnet,server_subnet=servernet,admin_subnet=adminnet,staff_count=npos*3))
  branches[bid]={'i':i,'profile':profile,'open':open_h,'close':close_h,'scope':scope,'npos':npos}
  for typ,num,ip,subnet_,os,ver in [('STORE',0,f'10.{40+i}.20.10',servernet,'Windows Server','2022'),('ADM',0,f'10.{40+i}.30.10',adminnet,'Windows 11 Enterprise','23H2')]:
   did=f'{bid}-{typ}-01';d=dict(device_id=did,branch_id=bid,device_type=typ,ip_address=ip,subnet=subnet_,os_name=os,os_version=ver,managed=1,analysis_scope=int(scope));rows['devices.csv'].append(d);devices[did]=d
  for j in range(1,npos+1):
   did=f'{bid}-POS-{j:02d}';d=dict(device_id=did,branch_id=bid,device_type='POS',ip_address=f'10.{40+i}.10.{20+j}',subnet=subnet,os_name='Windows 10 IoT Enterprise LTSC',os_version='2021',managed=1,analysis_scope=int(scope));rows['devices.csv'].append(d);devices[did]=d;terminals.append(d)
   if scope:analyzed.append(d)
 # Exactly 168 terminals: 6*5 + 6*4 + 6*5 + 12*4 + 12*3.
 bad_ids=[analyzed[i]['device_id'] for i in (1,7,16,25,36,47)]
 infections={t:datetime(2026,8,12,9,15)+timedelta(days=idx*3) for idx,t in enumerate(bad_ids)}
 # One successful VPN compromise, followed by five recorded cross-branch pivots.
 first=bad_ids[0]; first_branch=devices[first]['branch_id']; gateway=f'{first_branch}-ADM-01'
 vpn_session='VPN-INITIAL-20260812'
 for attempt in range(10):
  when=infections[first]-timedelta(minutes=35-2*attempt)
  add('authentication_logs.csv',timestamp=ts(when),branch_id=first_branch,device_id=gateway,
      account_id='ADMIN-DEPLOY',username='johannes.muutota',account_role='privileged_admin',auth_source='vpn',
      source_ip='203.0.113.77',source_device_id='',result='failed',event_id=4625,shift_id='',session_id=vpn_session)
 add('authentication_logs.csv',timestamp=ts(infections[first]-timedelta(minutes=15)),branch_id=first_branch,device_id=gateway,
     account_id='ADMIN-DEPLOY',username='johannes.muutota',account_role='privileged_admin',auth_source='vpn',
     source_ip='203.0.113.77',source_device_id='',result='success',event_id=4624,shift_id='',session_id=vpn_session)
 add('authentication_logs.csv',timestamp=ts(infections[first]-timedelta(minutes=11)),branch_id=first_branch,device_id=first,
     account_id='ADMIN-DEPLOY',username='johannes.muutota',account_role='privileged_admin',auth_source='windows_remote',
     source_ip=devices[gateway]['ip_address'],source_device_id=gateway,result='success',event_id=4624,shift_id='',session_id=vpn_session)
 for idx,t in enumerate(bad_ids[1:],1):
  prev=bad_ids[idx-1]; when=infections[t]-timedelta(minutes=12);branch=devices[t]['branch_id']
  session=f'PIVOT-{idx:02d}-{when:%Y%m%d}'
  add('authentication_logs.csv',timestamp=ts(when),branch_id=branch,device_id=t,
      account_id='ADMIN-DEPLOY',username='johannes.muutota',account_role='privileged_admin',auth_source='windows_remote',
      source_ip=devices[prev]['ip_address'],source_device_id=prev,result='success',event_id=4624,shift_id='',session_id=session)
  add('network_flows.csv',timestamp=ts(when),branch_id=devices[prev]['branch_id'],src_device_id=prev,
      src_ip=devices[prev]['ip_address'],dst_ip=devices[t]['ip_address'],dst_port=445,protocol='TCP',
      bytes_out=8542,bytes_in=1294,duration_seconds=74,action='allow',url_host='',src_port=50000+idx,scenario_tag='lateral_movement')
 for idx,t in enumerate(bad_ids):
  start=infections[t];rows['ground_truth_private.csv'].append(dict(terminal_id=t,branch_id=devices[t]['branch_id'],compromise_start=ts(start),compromise_end=ts(END),entry_vector='vpn_brute_force' if idx==0 else 'cross_branch_lateral_movement',parent_device_id=gateway if idx==0 else bad_ids[idx-1],vpn_session_id=vpn_session if idx==0 else '',first_exfiltration='',notes='Synthetic injected ground truth; exclude from training features'))
 # Scope: 14 baseline days + 90 analysis days; timestamps prior to 27 June are baseline only.
 for day_i in range((END-START).days):
  day=START+timedelta(days=day_i)
  for d in analyzed:
   did=d['device_id'];bid=d['branch_id'];b=branches[bid];ip=d['ip_address'];bad=did in infections and day>=infections[did].replace(hour=0,minute=0)
   # Shift roster and matching Windows interactive authentication.
   first_names=('selma','anna','ndapewa','petrus','martha','nela','paulus','elina')
   last_names=('shikongo','hamutenya','amadhila','nuugulu','kavari','haufiku','mbeha','nakale')
   operator=f'{first_names[(b["i"]-1)%8]}.{last_names[(b["i"]+int(did[-2:]))%8]}.{b["i"]:03d}{did[-2:]}'; shift_start=event_time(day,b['open']);shift_end=event_time(day,b['close']);shift_id=f'SH-{bid}-{day:%Y%m%d}-{did[-2:]}'
   rows['shifts.csv'].append(dict(shift_id=shift_id,branch_id=bid,operator_id=operator,shift_start=ts(shift_start),shift_end=ts(shift_end),role='till_operator'))
   add('authentication_logs.csv',timestamp=ts(shift_start+timedelta(minutes=2)),branch_id=bid,device_id=did,account_id=operator,account_role='till_operator',auth_source='windows_interactive',source_ip=ip,source_device_id=did,result='success',event_id=4624,shift_id=shift_id,session_id=f'S-{day_i}-{did}',scenario_tag='routine')
   # Terminal day transactions share transaction reference and card token across POS and payment records.
   n_sales={'urban':8,'medium':6,'rural':4}[b['profile']]+rng.randrange(4)
   for j in range(n_sales):
    minute=rng.randrange((b['close']-b['open'])*60);tm=shift_start+timedelta(minutes=minute)
    ref=f'TX-{day:%Y%m%d}-{b["i"]:03d}-{did[-2:]}-{j:03d}';amount=round(rng.uniform(18,1100),2)
    card=rng.randrange(1,2400); cardtok=token(card)
    # Disputes arise later for a subset of cards used at compromised terminals, including repeat visits.
    disputed=bad and rng.random()<0.025 and (END-day).days>=7
    add('pos_events.csv',timestamp=ts(tm),branch_id=bid,terminal_id=did,operator_id=operator,shift_id=shift_id,event_type='sale',txn_ref=ref,tender_type='card',amount=amount,status_code='approved',supervisor_override=0)
    add('payment_auth.csv',auth_timestamp=ts(tm+timedelta(seconds=2)),branch_id=bid,terminal_id=did,txn_ref=ref,card_token=cardtok,card_surrogate=f'SYN-{card:08d}-INVALID',amount=amount,response_code='00',entry_mode='chip',dispute_flag=int(disputed),dispute_date=ts(min(END-timedelta(days=1),tm+timedelta(days=rng.randrange(5,16))))[:10] if disputed else '')
   if rng.random()<0.16:
    tm=shift_start+timedelta(hours=2,minutes=rng.randrange(40));typ=rng.choice(['void','refund','no_sale'])
    add('pos_events.csv',timestamp=ts(tm),branch_id=bid,terminal_id=did,operator_id=operator,shift_id=shift_id,event_type=typ,txn_ref='',tender_type='',amount=0,status_code='approved',supervisor_override=int(typ=='refund'))
    add('inventory_exceptions.csv',timestamp=ts(tm),branch_id=bid,terminal_id=did,event_type=typ,item_count=1,value=0,supervisor_override=int(typ=='refund'))
   # Legitimate flows and DNS, including noisy benign updater and a maintenance exception.
   for purpose,host,dest,port,q in [('payment','gateway.nrg-payments.com.na','192.0.2.20',443,3),('updates','updates.nashipili-retail.com.na','192.0.2.44',443,1),('management','store.nrg.internal',f'10.{40+b["i"]}.20.10',445,1)]:
    for _ in range(q):
     tm=event_time(day,b['open']+rng.randrange(b['close']-b['open']),rng.randrange(60));outbytes=rng.randrange(200,4500);inbytes=rng.randrange(500,12000)
     add('network_flows.csv',timestamp=ts(tm),branch_id=bid,src_device_id=did,src_ip=ip,dst_ip=dest,dst_port=port,protocol='TCP',bytes_out=outbytes,bytes_in=inbytes,duration_seconds=rng.randrange(1,80),action='allow',url_host=host,src_port=rng.randrange(49152,65535),scenario_tag=purpose)
     add('dns_logs.csv',timestamp=ts(tm-timedelta(seconds=1)),branch_id=bid,device_id=did,src_ip=ip,resolver_ip=f'10.{40+b["i"]}.20.10',query_name=host,query_type='A',response_code='NOERROR',answer_ip=dest,query_length=len(host),scenario_tag=purpose)
   if rng.random()<0.06:
    tm=event_time(day,2,rng.randrange(60));add('network_flows.csv',timestamp=ts(tm),branch_id=bid,src_device_id=did,src_ip=ip,dst_ip='192.0.2.44',dst_port=443,protocol='TCP',bytes_out=450,bytes_in=6500,duration_seconds=170,action='allow',url_host='updates.nashipili-retail.com.na',src_port=55001,scenario_tag='benign_off_hours_updater')
   if day.day==3 and day.weekday()<5:
    tm=event_time(day,10);add('edr_events.csv',timestamp=ts(tm),branch_id=bid,host_id=did,process_name='VendorUpdater.exe',process_hash=h('approved-updater'),parent_process='services.exe',command_line='VendorUpdater.exe /scheduled',user_context='SYSTEM',persistence_key='',module_load='',network_connect=1)
   if bad:
    start=infections[did]
    if day.date()==start.date():
     add('edr_events.csv',timestamp=ts(start),branch_id=bid,host_id=did,process_name='possvc.exe',process_hash=h('synthetic-malware-build-'+str(b['i'])),parent_process='posapp.exe',command_line='possvc.exe /service',user_context='SYSTEM',persistence_key='HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\PosSvc',module_load='posapp.exe',network_connect=1)
     add('system_logs.csv',timestamp=ts(start+timedelta(minutes=1)),branch_id=bid,device_id=did,provider='Service Control Manager',event_id=7045,level='Information',message='Unapproved PosSvc service installed; simulated telemetry only',process_name='possvc.exe',scenario_tag='compromise')
     add('soc_tickets.csv',opened_at=ts(start+timedelta(days=2)),branch_id=bid,terminal_id=did,source='SOC',narrative_text='Unexpected POS child process and after-hours outbound sessions; correlate VPN authentication and cross-branch Windows remote access, then investigate scraping and DNS staging.',resolution_text='Pending analyst review')
    if day.date()>=start.date():
     dest=f'198.51.100.{70+bad_ids.index(did)}';host=f'pos-support-{bad_ids.index(did)}.nrg-sync.com.na';dns_host='telemetry.nrg-sync.com.na'
     for hour in (1,5,9,13,17,21):
      tm=event_time(day,hour,rng.randrange(0,5));
      if tm<start:continue
      add('network_flows.csv',timestamp=ts(tm),branch_id=bid,src_device_id=did,src_ip=ip,dst_ip=dest,dst_port=443,protocol='TCP',bytes_out=rng.randrange(12000,27000),bytes_in=rng.randrange(150,1100),duration_seconds=rng.randrange(30,95),action='allow',url_host=host,src_port=rng.randrange(49152,65535),scenario_tag='beacon_exfil')
      label=h(f'{did}-{tm}')[:46];query=f'{label}.{dns_host}'
      add('dns_logs.csv',timestamp=ts(tm+timedelta(seconds=1)),branch_id=bid,device_id=did,src_ip=ip,resolver_ip=f'10.{40+b["i"]}.20.10',query_name=query,query_type='TXT',response_code='NOERROR',answer_ip='',query_length=len(query),scenario_tag='dns_staging')
      add('network_flows.csv',timestamp=ts(tm+timedelta(seconds=1)),branch_id=bid,src_device_id=did,src_ip=ip,dst_ip=f'10.{40+b["i"]}.20.10',dst_port=53,protocol='UDP',bytes_out=len(query)+65,bytes_in=105,duration_seconds=1,action='allow',url_host=query,src_port=rng.randrange(49152,65535),scenario_tag='dns_staging')
     if day_i%7==0:
      tm=event_time(day,1,12)
      if tm>=start:
       add('system_logs.csv',timestamp=ts(tm+timedelta(minutes=3)),branch_id=bid,device_id=did,provider='Microsoft-Windows-Security-Auditing',event_id=4688,level='Information',message='Simulated process activity following established compromise',process_name='possvc.exe',scenario_tag='compromise')
   elif rng.random()<0.015:
    tm=event_time(day,2,20);add('authentication_logs.csv',timestamp=ts(tm),branch_id=bid,device_id=f'{bid}-ADM-01',account_id='ADM-'+bid,username=f'branch.support.{b["i"]:03d}',account_role='privileged_admin',auth_source='vpn',source_ip='203.0.113.20',source_device_id='',result='success',event_id=4624,shift_id='',session_id=f'MAINT-{day_i}-{did}',scenario_tag='benign_approved_maintenance')
   if rng.random()<0.015:
    tm=event_time(day,3,30);add('system_logs.csv',timestamp=ts(tm),branch_id=bid,device_id=did,provider='Microsoft-Windows-WindowsUpdateClient',event_id=19,level='Information',message='Approved Windows update installed',process_name='svchost.exe',scenario_tag='routine')
 # Structured output with stable sort, preserving repeatable IDs.
 for entry in rows['ground_truth_private.csv']:
  events=[x['timestamp'] for x in rows['network_flows.csv'] if x['src_device_id']==entry['terminal_id'] and x.get('scenario_tag')=='beacon_exfil']
  entry['first_exfiltration']=min(events) if events else ''
 for name,rr in rows.items():
  if name not in ('branches.csv','devices.csv','ground_truth_private.csv'):
   key='timestamp' if 'timestamp' in COLUMNS[name].split(',') else ('auth_timestamp' if name=='payment_auth.csv' else ('opened_at' if name=='soc_tickets.csv' else 'shift_start'))
   rr.sort(key=lambda x:(x[key],next(iter(x.values()))))
  write_csv(out,name,rr)
 manifest={'seed':seed,'window_start_inclusive':ts(START),'analysis_start_inclusive':ts(ANALYSIS),'window_end_exclusive':ts(END),'baseline_days':14,'analysis_days':90,'synthetic':True,'counts':{k:len(v) for k,v in rows.items()},'sha256':{k:hashlib.sha256((out/k).read_bytes()).hexdigest() for k in rows},'ground_truth_is_private':'ground_truth_private.csv; exclude from ingestion and model features'}
 (out/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
 readme=f'''# CardWatch synthetic teaching dataset\n\nGenerated with `python generate_cardwatch.py --out data --seed {seed}`. All organisations, branches, devices, usernames and events are invented. Region and town names identify real Namibian places; they do not represent actual retail sites. Any coincidental match between the invented .com.na domains or usernames and a real entity is unintended and does not imply any activity by that entity. Do not resolve or contact these illustrative domain names. TCP/TLS and DNS patterns are inspired by the supplied Backoff CSV, but no source record, real address or malware payload is reused. This is a flow summary, not PCAP.\n\nCoverage: 42 branches in all 14 Namibian regions, {len(terminals)} POS terminals in the inventory; 12 analysed branches and {len(analyzed)} analysed terminals. From {START:%Y-%m-%d} to {END:%Y-%m-%d} exclusive: first 14 days are baseline-only; following 90 are the analysis period. All timestamps are local synthetic wall times without DST. IDs are stable across files. Branch IDs follow `NRG-<REGION_CODE>-<TOWN_CODE>-<NNN>`, e.g. `NRG-KHO-WDH-001`; for branch N, POS `10.<40+N>.10.0/24`, store server `10.<40+N>.20.0/24`, admin `10.<40+N>.30.0/24`. The second octet is unique because N ranges 1–42. The analysis subset is branches 001–012. The `locality_type` column distinguishes towns, municipalities and villages; \"town\" here is a general place label, not a claim about every local authority's formal classification. `//Kharas` follows the government spelling and is also styled `ǁKaras`.\n\nRelationships: devices.branch_id -> branches.branch_id; terminal_id/host_id/src_device_id/device_id -> devices.device_id; POS and payment records join on txn_ref; shifts join on shift_id; authentication sessions on session_id; events on device and timestamp. The POS and payment tables contain the same sale references. Non-sale events have an empty txn_ref. Payment tokens are synthetic stable opaque identifiers; card_surrogate is marked INVALID and is not a PAN or Luhn-like value.\n\nThe incident begins with exactly 10 failed VPN logins to a branch administrative host, followed by one successful VPN login for the same privileged account and source address. The session is linked to remote Windows access on the first POS. Five later POS infections follow recorded cross-branch Windows remote logons and TCP/445 connections originating from the preceding compromised terminal. `ground_truth_private.csv` contains labels, parent devices and first observed exfiltration times. Keep it out of feature engineering and training, open it only at evaluation. Exact domains, fixed cadence and paths are intentionally too easy: diversify them for robust evaluation. Dispute dates are simulated and may be later than transaction dates. Counts and file hashes are in manifest.json. The small event rates are deliberately below charter volume estimates; they preserve join and analysis structure but cannot validate volume-scale performance or statistical benchmarks from the charter.\n\nFiles: branches.csv, devices.csv, shifts.csv, pos_events.csv, payment_auth.csv, inventory_exceptions.csv, edr_events.csv, network_flows.csv, dns_logs.csv, authentication_logs.csv, system_logs.csv, soc_tickets.csv, ground_truth_private.csv. Text-report corpora and a source-cited IOC register are separate future tasks; SOC tickets here provide only a small narrative input. `network_flows.csv` summaries aggregate sessions; bytes_out/in are from the POS perspective. All IP addresses use documentation or private address space; invented Namibia-themed hostnames use the .com.na suffix. The external VPN source addresses are documentation ranges too. No live network access is required.\n\nGeographic reference: Namibia Statistics Agency, National Statistics System, list of 14 regions (https://nsa.org.na/nss/?page_id=13754); Ministry of Urban and Rural Development, local authorities by region (https://murd.gov.na/en/sub-national-governments). Locality spellings use the ministry lists with standard Luderitz spelling without the umlaut for ASCII identifiers. Account IDs are synthetic identifiers; the authentication log also contains stable fictional `username` values. The till operator username matches the operator ID in POS and shift records.\n\nUse cases: time-filter to analysis period; build terminal-day features; establish per-terminal and peer baselines; correlate the 10 VPN failures and success by username/source/session, then follow the remote logon and lateral-movement edges to each POS; compare beacon cadence and byte asymmetry; inspect high-entropy DNS subdomains; join disputes to transactions; evaluate on held-out terminals/dates. Avoid leaking ground truth, arbitrary event IDs, branch-specific malware destination, or post-event dispute_flag into a model intended for early detection.\n\nCharter note: the final-documentation template says due 25 September 2026, but the charter work plan extends into November. Confirm the actual lecturer milestone dates before relying on either schedule.\n'''
 (out/'README.md').write_text(readme)
 print(json.dumps({'branches':len(branches),'terminals':len(terminals),'analyzed':len(analyzed),'counts':manifest['counts']},indent=2))

if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--out',type=Path,default=Path('cardwatch_data'));p.add_argument('--seed',type=int,default=SEED);a=p.parse_args();main(a.out,a.seed)

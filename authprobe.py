#!/usr/bin/env python3
import subprocess, os
os.makedirs('out2',exist_ok=True)
UA='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36'
out=[]
ip=subprocess.run(['curl','-sS','-m','10','https://api.ipify.org'],capture_output=True,text=True).stdout.strip()
out.append('RUNNER_IP='+ip)
urls=[('api_root','https://api.redbiller.com/'),
 ('api_health','https://api.redbiller.com/health'),
 ('api_docs','https://api.redbiller.com/docs'),
 ('api_openapi','https://api.redbiller.com/openapi.json'),
 ('web_root','https://web.redbiller.com/'),
 ('apex_root','https://redbiller.com/')]
for name,u in urls:
    cmd=['curl','-sS','-k','-A',UA,'-H','Accept: application/json, text/plain, */*','-o','out2/b_'+name,'-D','out2/h_'+name,'--max-time','25','-w','code=%{http_code} len=%{size_download} ct=%{content_type} ip=%{remote_ip}',u]
    r=subprocess.run(cmd,capture_output=True,text=True)
    try: body=open('out2/b_'+name,'rb').read(300).decode('utf-8','replace').replace('\n',' ')
    except Exception: body=''
    try: hdr=open('out2/h_'+name,errors='replace').read()
    except Exception: hdr=''
    srv=[l.strip() for l in hdr.split('\n') if l.lower().startswith(('server:','cf-ray:','x-amz-cf-pop:'))]
    out.append('%s | %s | %s | hdrs=%s | %s'%(name,u,(r.stdout or r.stderr).strip(),';'.join(srv)[:200],body[:200]))
open('out2/summary.txt','w').write('\n'.join(out)+'\n')
print('\n'.join(out))

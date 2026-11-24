import os, json, re, base64, urllib.request, urllib.parse, urllib.error, getpass, secrets, webbrowser
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
ROOT=Path(__file__).resolve().parent
sid='ACa10e24d2f4d823af86a68b1a5561a524'
sender='+16592007342'
secret=os.environ.get('TWILIO_AUTH_TOKEN','').strip()
password=os.environ.get('NAV_PASSWORD','')
origin=(os.environ.get('NAV_ORIGIN') or os.environ.get('RENDER_EXTERNAL_URL') or '').rstrip('/')
if len(password)<16 or not origin.startswith('https://'): raise SystemExit('Configure NAV_PASSWORD (16 caracteres minimo) y NAV_ORIGIN (HTTPS).')
import hmac
hidden_path=Path(os.environ.get('NAV_DATA','./data'))/'hidden-sms.json'
def hidden_ids():
 if not hidden_path.exists(): return set()
 return set(json.loads(hidden_path.read_text(encoding='utf-8')))
key=hmac.new(password.encode(), ('nav-virtual:csrf:v2:'+origin).encode(), 'sha256').hexdigest()
class Handler(BaseHTTPRequestHandler):
 def reply(self,code,obj):
  data=json.dumps(obj,ensure_ascii=False).encode(); self.send_response(code); self.send_header('Content-Type','application/json; charset=utf-8'); self.send_header('Cache-Control','no-store'); self.end_headers(); self.wfile.write(data)
 def authorized(self):
  expected='Basic '+base64.b64encode(('nav:'+password).encode()).decode()
  if hmac.compare_digest(self.headers.get('Authorization',''),expected): return True
  self.send_response(401); self.send_header('WWW-Authenticate','Basic realm="Nav.Virtual"'); self.send_header('Cache-Control','no-store'); self.end_headers(); return False
 def do_GET(self):
  self.path=urllib.parse.urlsplit(self.path).path
  if self.path=='/healthz':
   self.reply(200,{'status':'ok'}); return
  if not self.authorized(): return
  if self.path=='/session-token':
   self.reply(200,{'token':key}); return
  assets={'/':('index.html','text/html; charset=utf-8'),'/manifest.json':('manifest.json','application/manifest+json'),'/icon-192.png':('icon-192.png','image/png'),'/icon-512.png':('icon-512.png','image/png')}
  if self.path not in assets: self.send_error(404); return
  name,typ=assets[self.path]; data=(ROOT/name).read_bytes()
  if self.path=='/': data=data.replace(b'__LOCAL_TOKEN__',key.encode())
  self.send_response(200); self.send_header('Content-Type',typ); self.send_header('Cache-Control','no-store'); self.send_header('X-Content-Type-Options','nosniff'); self.end_headers(); self.wfile.write(data)
 def do_POST(self):
  if not self.authorized(): return
  if self.path not in ('/sms','/chat','/hide-chat'):
   self.reply(404,{'error':'Acción desconocida'}); return
  supplied_origin=self.headers.get('Origin')
  if (supplied_origin is not None and supplied_origin!=origin) or self.headers.get('Sec-Fetch-Site')=='cross-site':
   self.reply(403,{'error':'Origen web no autorizado','code':'origin_mismatch'}); return
  if not hmac.compare_digest(self.headers.get('X-Local-Token',''),key):
   self.reply(403,{'error':'Sesión del chat caducada. Actualice la página.','code':'session_expired'}); return
  try:
   size=int(self.headers.get('Content-Length','0'))
   if not 0<size<16000: raise ValueError('Solicitud demasiado grande')
   p=json.loads(self.rfile.read(size)); to=p['to']; body=p['body'];
   if not re.fullmatch(r'\+[1-9]\d{7,14}',to): raise ValueError('Numero internacional invalido')
   if self.path=='/hide-chat':
    ids=p.get('ids',[])
    if not isinstance(ids,list) or not 1<=len(ids)<=200 or not all(isinstance(i,str) and re.fullmatch(r'(?:SM|MM)[0-9a-fA-F]{32}',i) for i in ids): raise ValueError('Identificadores de mensajes invalidos')
    hidden=hidden_ids().union(ids)
    hidden_path.parent.mkdir(parents=True,exist_ok=True)
    tmp=hidden_path.with_suffix('.tmp'); tmp.write_text(json.dumps(sorted(hidden)),encoding='utf-8'); tmp.replace(hidden_path)
    self.reply(200,{'ok':True}); return
   if self.path=='/chat':
    if not secret: raise ValueError('Configure el token Twilio')
    messages=[]
    for source,target in ((sender,to),(to,sender)):
     url='https://api.twilio.com/2010-04-01/Accounts/'+sid+'/Messages.json?'+urllib.parse.urlencode({'From':source,'To':target,'PageSize':100})
     req=urllib.request.Request(url,headers={'Authorization':'Basic '+base64.b64encode((sid+':'+secret).encode()).decode()})
     with urllib.request.urlopen(req,timeout=15) as r: result=json.load(r)
     for m in result.get('messages',[]):
      messages.append({'sid':m.get('sid'),'body':m.get('body'),'outgoing':source==sender,'date':m.get('date_sent') or m.get('date_created'),'status':m.get('status')})
    hidden=hidden_ids(); self.reply(200,{'messages':[m for m in messages if m['sid'] not in hidden]}); return
   if not isinstance(body,str) or len(body)>1200: raise ValueError('Mensaje demasiado largo')
   if not re.fullmatch(r'AC[0-9a-fA-F]{32}',sid) or not secret or not re.fullmatch(r'\+[1-9]\d{7,14}',sender): raise ValueError('Configure las credenciales y el numero Twilio al abrir el programa')
   body=body+'\nPosición virtual generada por Nav.Virtual v9'
   req=urllib.request.Request('https://api.twilio.com/2010-04-01/Accounts/'+sid+'/Messages.json',data=urllib.parse.urlencode({'To':to,'From':sender,'Body':body}).encode(),headers={'Authorization':'Basic '+base64.b64encode((sid+':'+secret).encode()).decode()},method='POST')
   with urllib.request.urlopen(req,timeout=20) as r: result=json.load(r)
   self.reply(200,{'status':result.get('status','accepted'),'sid':result.get('sid')})
  except urllib.error.HTTPError as e:
   try: msg=json.loads(e.read()).get('message','Error del proveedor')
   except Exception: msg='Error del proveedor'
   self.reply(502,{'error':msg})
  except Exception as e: self.reply(400,{'error':str(e)})
port=int(os.environ.get('PORT','8080'))
server=HTTPServer(('0.0.0.0',port),Handler)
print(f'Nav.Virtual: servidor en puerto {port}',flush=True)
server.serve_forever()

"""Vivian Web 2.0: same-origin Discord OAuth and read-only profile API."""
import os,secrets,time,threading
from pathlib import Path
from urllib.parse import urlencode
from flask import Flask,redirect,request,jsonify,send_from_directory,make_response
import httpx

SITE=Path(__file__).resolve().parents[1]/'site'
app=Flask(__name__,static_folder=None)
CLIENT_ID=os.environ.get('DISCORD_CLIENT_ID','')
CLIENT_SECRET=os.environ.get('DISCORD_CLIENT_SECRET','')
BASE_URL=os.environ.get('PUBLIC_BASE_URL','https://vivian.lat').rstrip('/')
COOKIE_SECURE=os.environ.get('LOCAL_DEV')!='1'
SESSIONS={}; LOCK=threading.Lock(); TTL=60*60*12

def prune():
 now=time.time()
 with LOCK:
  for k,v in list(SESSIONS.items()):
   if v['expires']<now: SESSIONS.pop(k,None)

def session():
 prune(); sid=request.cookies.get('vivian_session','')
 with LOCK:return SESSIONS.get(sid)

def set_cookie(resp,sid):
 resp.set_cookie('vivian_session',sid,httponly=True,secure=COOKIE_SECURE,samesite='Lax',max_age=TTL,path='/');return resp

@app.get('/auth/discord')
def login():
 if not CLIENT_ID or not CLIENT_SECRET:return jsonify(error='OAuth credentials not configured'),503
 sid=secrets.token_urlsafe(32); state=secrets.token_urlsafe(32)
 with LOCK:SESSIONS[sid]={'state':state,'expires':time.time()+600}
 query=urlencode({'client_id':CLIENT_ID,'response_type':'code','redirect_uri':BASE_URL+'/auth/callback','scope':'identify','state':state,'prompt':'consent'})
 return set_cookie(redirect('https://discord.com/oauth2/authorize?'+query),sid)

@app.get('/auth/callback')
def callback():
 sid=request.cookies.get('vivian_session','');state=request.args.get('state','')
 with LOCK: s=SESSIONS.get(sid)
 if not s or not state or not secrets.compare_digest(state,s.get('state','')):return jsonify(error='Invalid OAuth state'),400
 with LOCK: SESSIONS.pop(sid,None)
 if not request.args.get('code'):return jsonify(error='Missing authorization code'),400
 try:
  with httpx.Client(timeout=10) as client:
   token=client.post('https://discord.com/api/oauth2/token',data={'client_id':CLIENT_ID,'client_secret':CLIENT_SECRET,'grant_type':'authorization_code','code':request.args['code'],'redirect_uri':BASE_URL+'/auth/callback'});token.raise_for_status()
   user=client.get('https://discord.com/api/users/@me',headers={'Authorization':'Bearer '+token.json()['access_token']});user.raise_for_status();u=user.json()
  if not str(u.get('id','')).isdigit():raise ValueError('Invalid user ID')
 except (httpx.HTTPError,KeyError,ValueError):return jsonify(error='Discord OAuth failed'),502
 new_sid=secrets.token_urlsafe(32)
 with LOCK:SESSIONS[new_sid]={'user':{'id':str(u['id']),'username':u.get('global_name') or u.get('username') or 'Discord user','avatar':u.get('avatar')},'expires':time.time()+TTL}
 return set_cookie(redirect('/dashboard.html'),new_sid)

@app.get('/auth/logout')
def logout():
 sid=request.cookies.get('vivian_session','')
 with LOCK:SESSIONS.pop(sid,None)
 resp=redirect('/');resp.delete_cookie('vivian_session',path='/');return resp

def database_query(sql,params=()):
 import psycopg
 url=os.getenv('DATABASE_URL')
 if not url:return None
 with psycopg.connect(url,connect_timeout=5,options='-c statement_timeout=5000') as conn:
  with conn.cursor() as cur:cur.execute(sql,params);return cur.fetchone()

@app.get('/api/me')
def me():
 s=session()
 if not s or 'user' not in s:return jsonify(error='Authentication required'),401
 u=s['user']; result={'id':u['id'],'username':u['username'],'avatar_url': f"https://cdn.discordapp.com/avatars/{u['id']}/{u['avatar']}.png" if u['avatar'] else None,'xp':None,'level':None,'rank':None}
 try:
  row=database_query('SELECT xp, level, (SELECT count(*)+1 FROM public.user_xp other WHERE other.xp > member.xp) FROM public.user_xp member WHERE user_id=%s',(int(u['id']),))
  if row:result.update(xp=row[0],level=row[1],rank=row[2])
 except Exception: app.logger.exception('Profile query failed');return jsonify(error='Profile temporarily unavailable'),503
 resp=jsonify(result);resp.headers['Cache-Control']='no-store';return resp

@app.get('/api/public/stats')
def stats():
 data={'guild_count':None,'xp_profiles':None,'top_level':None}
 try:
  row=database_query('SELECT count(*),max(level) FROM public.user_xp')
  if row:data.update(xp_profiles=row[0],top_level=row[1])
 except Exception:app.logger.exception('Public stats query failed')
 # For live guild count, configure the bot's optional /api/public/stats endpoint.
 url=os.getenv('BOT_PUBLIC_STATS_URL','')
 if url:
  try:
   r=httpx.get(url,timeout=4);r.raise_for_status();count=r.json().get('guild_count')
   if isinstance(count,int) and count>=0:data['guild_count']=count
  except (httpx.HTTPError,ValueError):pass
 resp=jsonify(data);resp.headers['Cache-Control']='no-store';return resp

@app.get('/healthz')
def health():return jsonify(status='ok')

@app.get('/')
def index():return send_from_directory(SITE,'index.html')

@app.get('/<path:filename>')
def static(filename):
 if filename.startswith('.') or '/' in filename:return 'Not found',404
 if not (SITE/filename).is_file():return 'Not found',404
 return send_from_directory(SITE,filename)

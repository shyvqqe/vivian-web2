"""Vivian Web 2.0: Discord OAuth, persistent PostgreSQL sessions and read-only profile API.

Apply sql/001_web_security.sql before deploying. No schema changes run automatically.
"""
import hashlib
import ipaddress
import os
import secrets
import time
from pathlib import Path
from urllib.parse import urlencode

import httpx
import psycopg
from flask import Flask, abort, jsonify, redirect, request, send_from_directory

SITE = Path(__file__).resolve().parents[1] / 'site'
app = Flask(__name__, static_folder=None)
CLIENT_ID = os.getenv('DISCORD_CLIENT_ID', '')
CLIENT_SECRET = os.getenv('DISCORD_CLIENT_SECRET', '')
BASE_URL = os.getenv('PUBLIC_BASE_URL', 'https://vivian.lat').rstrip('/')
COOKIE_SECURE = os.getenv('LOCAL_DEV') != '1'
SESSION_TTL = 60 * 60 * 12
PENDING_TTL = 600
COOKIE_NAME = 'vivian_session'


def db(sql, params=(), *, fetch='one'):
    url = os.getenv('DATABASE_URL')
    if not url:
        raise RuntimeError('DATABASE_URL is missing')
    with psycopg.connect(url, connect_timeout=5, options='-c statement_timeout=5000') as conn:
        with conn.cursor() as cur:
            cur.execute(sql, params)
            if fetch == 'one':
                return cur.fetchone()
            if fetch == 'all':
                return cur.fetchall()
            return None


def digest(value):
    return hashlib.sha256(value.encode('utf-8')).hexdigest()


def cookie(response, sid):
    response.set_cookie(COOKIE_NAME, sid, httponly=True, secure=COOKIE_SECURE,
                        samesite='Lax', max_age=SESSION_TTL, path='/')
    response.headers['Cache-Control'] = 'no-store'
    return response


def current_session():
    sid = request.cookies.get(COOKIE_NAME, '')
    if not sid:
        return None
    row = db('''SELECT discord_id, username, avatar
                FROM vivian_web.sessions
                WHERE session_hash=%s AND kind='user' AND expires_at > now()''',
             (digest(sid),))
    if not row:
        return None
    return {'id': str(row[0]), 'username': row[1], 'avatar': row[2]}


def peer_key():
    # Trust REMOTE_ADDR, not a user-supplied X-Forwarded-For chain.
    # Configure a trusted proxy normalization layer separately if needed.
    raw = request.remote_addr or '0.0.0.0'
    try:
        return str(ipaddress.ip_address(raw))
    except ValueError:
        return 'unknown'


def rate_limit(bucket, limit, period):
    """Atomic, shared PostgreSQL fixed-window rate limit. Fail closed on DB errors."""
    key = digest(peer_key() + ':' + bucket)
    window = int(time.time() // period)
    row = db('''INSERT INTO vivian_web.rate_windows (bucket, key_hash, window_start, hits)
                 VALUES (%s,%s,%s,1)
                 ON CONFLICT (bucket,key_hash,window_start)
                 DO UPDATE SET hits = vivian_web.rate_windows.hits + 1
                   WHERE vivian_web.rate_windows.hits < %s
                 RETURNING hits''', (bucket, key, window, limit))
    return row is not None


@app.before_request
def guard_api():
    path = request.path
    if not (path.startswith('/api/') or path.startswith('/auth/')):
        return None
    if path.startswith('/auth/'):
        bucket, limit, period = 'auth', 15, 300
    elif path == '/api/me':
        bucket, limit, period = 'profile', 120, 60
    else:
        bucket, limit, period = 'public-api', 120, 60
    try:
        if not rate_limit(bucket, limit, period):
            response = jsonify(error='Too many requests')
            response.status_code = 429
            response.headers['Retry-After'] = str(period)
            return response
    except (psycopg.Error, RuntimeError):
        app.logger.exception('Rate limit database unavailable')
        return jsonify(error='Service temporarily unavailable'), 503
    return None


def origin_valid():
    # For browser-initiated state changes, insist on an exact same-origin Origin/Referer.
    origin = request.headers.get('Origin')
    if origin:
        return origin.rstrip('/') == BASE_URL
    ref = request.headers.get('Referer', '')
    return ref.startswith(BASE_URL + '/')


@app.get('/auth/discord')
def login():
    if not CLIENT_ID or not CLIENT_SECRET:
        return jsonify(error='OAuth credentials not configured'), 503
    sid, state = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
    try:
        db('''INSERT INTO vivian_web.sessions
              (session_hash, kind, oauth_state_hash, expires_at)
              VALUES (%s,'pending',%s,now()+ interval '10 minutes')''',
           (digest(sid), digest(state)), fetch='none')
    except psycopg.Error:
        app.logger.exception('Cannot create OAuth state')
        return jsonify(error='Login temporarily unavailable'), 503
    query = urlencode({'client_id': CLIENT_ID, 'response_type': 'code',
                       'redirect_uri': BASE_URL + '/auth/callback',
                       'scope': 'identify', 'state': state, 'prompt': 'consent'})
    return cookie(redirect('https://discord.com/oauth2/authorize?' + query), sid)


@app.get('/auth/callback')
def callback():
    sid = request.cookies.get(COOKIE_NAME, '')
    state = request.args.get('state', '')
    if not sid or not state or len(state) > 256:
        return jsonify(error='Invalid OAuth state'), 400
    # Consumes pending state exactly once, before code exchange.
    try:
        row = db('''DELETE FROM vivian_web.sessions
                    WHERE session_hash=%s AND kind='pending' AND oauth_state_hash=%s
                      AND expires_at>now() RETURNING session_hash''',
                 (digest(sid), digest(state)))
    except psycopg.Error:
        app.logger.exception('OAuth state database unavailable')
        return jsonify(error='Login temporarily unavailable'), 503
    if not row:
        return jsonify(error='Invalid OAuth state'), 400
    code = request.args.get('code')
    if not code:
        return jsonify(error='Missing authorization code'), 400
    try:
        with httpx.Client(timeout=10) as client:
            token = client.post('https://discord.com/api/oauth2/token', data={
                'client_id': CLIENT_ID, 'client_secret': CLIENT_SECRET,
                'grant_type': 'authorization_code', 'code': code,
                'redirect_uri': BASE_URL + '/auth/callback'})
            token.raise_for_status()
            access_token = token.json()['access_token']
            user = client.get('https://discord.com/api/users/@me',
                              headers={'Authorization': 'Bearer ' + access_token})
            user.raise_for_status()
            u = user.json()
        if not str(u.get('id', '')).isdigit():
            raise ValueError('Invalid Discord user ID')
    except (httpx.HTTPError, KeyError, ValueError):
        app.logger.warning('Discord OAuth exchange failed')
        return jsonify(error='Discord OAuth failed'), 502
    new_sid = secrets.token_urlsafe(32)
    try:
        db('''INSERT INTO vivian_web.sessions
              (session_hash,kind,discord_id,username,avatar,expires_at)
              VALUES (%s,'user',%s,%s,%s,now()+interval '12 hours')''',
           (digest(new_sid), int(u['id']),
            (u.get('global_name') or u.get('username') or 'Discord user')[:150],
            u.get('avatar'),), fetch='none')
    except psycopg.Error:
        app.logger.exception('Cannot save login session')
        return jsonify(error='Login temporarily unavailable'), 503
    return cookie(redirect('/dashboard.html'), new_sid)


@app.post('/auth/logout')
def logout():
    if not origin_valid():
        return jsonify(error='Invalid request origin'), 403
    sid = request.cookies.get(COOKIE_NAME, '')
    if sid:
        try:
            db('DELETE FROM vivian_web.sessions WHERE session_hash=%s',
               (digest(sid),), fetch='none')
        except psycopg.Error:
            app.logger.exception('Logout database unavailable')
            return jsonify(error='Logout temporarily unavailable'), 503
    response = jsonify(ok=True)
    response.delete_cookie(COOKIE_NAME, path='/', secure=COOKIE_SECURE,
                           httponly=True, samesite='Lax')
    response.headers['Cache-Control'] = 'no-store'
    return response


@app.get('/api/me')
def me():
    try:
        u = current_session()
    except psycopg.Error:
        app.logger.exception('Session lookup failed')
        return jsonify(error='Service temporarily unavailable'), 503
    if not u:
        return jsonify(error='Authentication required'), 401
    result = {'id': u['id'], 'username': u['username'],
              'avatar_url': (f"https://cdn.discordapp.com/avatars/{u['id']}/{u['avatar']}.png"
                             if u['avatar'] else None),
              'xp': None, 'level': None, 'rank': None}
    try:
        row = db('''SELECT xp, level,
                    (SELECT count(*) + 1 FROM public.user_xp other
                     WHERE other.xp > member.xp)
                    FROM public.user_xp member WHERE user_id=%s''', (int(u['id']),))
        if row:
            result.update(xp=row[0], level=row[1], rank=row[2])
    except psycopg.Error:
        app.logger.exception('Profile query failed')
        return jsonify(error='Profile temporarily unavailable'), 503
    response = jsonify(result)
    response.headers['Cache-Control'] = 'no-store'
    return response


@app.get('/api/public/stats')
def stats():
    data = {'guild_count': None, 'xp_profiles': None, 'top_level': None}
    try:
        row = db('SELECT count(*), max(level) FROM public.user_xp')
        if row:
            data.update(xp_profiles=row[0], top_level=row[1])
    except psycopg.Error:
        app.logger.exception('Public stats query failed')
    url = os.getenv('BOT_PUBLIC_STATS_URL', '')
    if url:
        try:
            r = httpx.get(url, timeout=4)
            r.raise_for_status()
            count = r.json().get('guild_count')
            if type(count) is int and count >= 0:
                data['guild_count'] = count
        except (httpx.HTTPError, ValueError):
            pass
    response = jsonify(data)
    response.headers['Cache-Control'] = 'no-store'
    return response


@app.get('/healthz')
def health():
    return jsonify(status='ok')


@app.after_request
def headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['X-Frame-Options'] = 'DENY'
    return response


@app.get('/')
def index():
    return send_from_directory(SITE, 'index.html')


@app.get('/<path:filename>')
def static(filename):
    if filename.startswith('.') or '/' in filename:
        return 'Not found', 404
    if not (SITE / filename).is_file():
        return 'Not found', 404
    return send_from_directory(SITE, filename)

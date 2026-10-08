"""Transactional, content-free handoff and duplicate-message state."""
import re
import secrets
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path

MARKER = re.compile(r"`?\[bridge:([a-f0-9]{32}):([a-f0-9]{32}):(\d{1,2})\]`?\s*$")
START = re.compile(r"^/?discuss(?:\s+(\d{1,6}))?(?:\s*:\s*|\s+|$)(.*)$", re.I | re.S)
STRIP = re.compile(r"(?:<@!?\d+>\s*)?`?\[(?:discuss|bridge):[^\]\n]*\]`?", re.I)


class State:
    def __init__(self, path, config):
        self.path, self.config = str(path), config
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as db:
            db.executescript('''
            CREATE TABLE IF NOT EXISTS seen(bot INTEGER, message INTEGER, at REAL,
              PRIMARY KEY(bot,message));
            CREATE TABLE IF NOT EXISTS discussions(id TEXT PRIMARY KEY, channel INTEGER,
              origin INTEGER, remaining INTEGER, target INTEGER, sender INTEGER,
              token TEXT, busy INTEGER, expires REAL, status TEXT);
            ''')

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=5)
        db.row_factory = sqlite3.Row
        try:
            with db:
                yield db
        finally:
            db.close()

    def seen(self, bot, message):
        with self.connect() as db:
            db.execute('DELETE FROM seen WHERE at < ?', (time.time() - 86400,))
            db.execute('DELETE FROM discussions WHERE expires < ?', (time.time() - 86400,))
            db.execute('DELETE FROM seen WHERE rowid IN (SELECT rowid FROM seen ORDER BY at DESC LIMIT -1 OFFSET 20000)')
            return db.execute('INSERT OR IGNORE INTO seen VALUES (?,?,?)',
                              (bot, message, time.time())).rowcount == 0

    def start(self, message, bot, turns):
        sid = secrets.token_hex(16)
        with self.connect() as db:
            db.execute('INSERT INTO discussions VALUES (?,?,?,?,?,?,?,?,?,?)',
                       (sid, message.channel.id, message.id, turns, bot, 0,
                        '', 1, time.time() + self.config['handoff_seconds'], 'active'))
        return sid, turns

    def root_message(self, sid):
        with self.connect() as db:
            row = db.execute('SELECT origin FROM discussions WHERE id=?', (sid,)).fetchone()
            if not row:
                raise RuntimeError('Unknown discussion')
            return row[0]

    def claim(self, message, bot):
        match = MARKER.search(message.content or '')
        if not match or not message.author.bot:
            return None
        sid, token, n = match.groups()
        n = int(n)
        if not 1 <= n <= self.config['max_turns']:
            return None
        if bot not in self.config['enabled_bots'] or message.author.id not in self.config['enabled_bots']:
            return None
        with self.connect() as db:
            updated = db.execute('''UPDATE discussions SET busy=1, token='', expires=?
                WHERE id=? AND channel=? AND target=? AND sender=? AND token=?
                AND remaining=? AND busy=0 AND expires>? AND status='active' ''',
                (time.time() + self.config['handoff_seconds'], sid, message.channel.id,
                 bot, message.author.id, token, n, time.time())).rowcount
            return (sid, n) if updated else None

    def advance(self, sid, bot, target):
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            row = db.execute('SELECT * FROM discussions WHERE id=?', (sid,)).fetchone()
            if not row or row['status'] != 'active' or not row['busy'] or row['target'] != bot:
                raise RuntimeError('Invalid discussion transition')
            n = row['remaining'] - 1
            if not n or target is None:
                db.execute("UPDATE discussions SET status='complete',busy=0,token='' WHERE id=?", (sid,))
                return None
            if target not in self.config['enabled_bots'] or target == bot:
                raise RuntimeError('Invalid discussion target')
            token = secrets.token_hex(16)
            db.execute('''UPDATE discussions SET remaining=?,target=?,sender=?,token=?,busy=0,
                expires=? WHERE id=?''', (n, target, bot, token,
                                         time.time() + self.config['handoff_seconds'], sid))
            return f'`[bridge:{sid}:{token}:{n}]`'

    def fail(self, sid):
        with self.connect() as db:
            db.execute("UPDATE discussions SET status='failed',busy=0,token='' WHERE id=?", (sid,))

    def expired(self):
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            rows = db.execute("SELECT id,channel FROM discussions WHERE status='active' AND expires<?",
                              (time.time(),)).fetchall()
            for row in rows:
                db.execute("UPDATE discussions SET status='expired',token='' WHERE id=?", (row['id'],))
            return [dict(r) for r in rows]

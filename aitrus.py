#!/usr/bin/env python3

import os, sys
import threading
import http.client
import socket
import json
import time
import getpass
import base64

BOT_VERSION = "Aitrus 0.1"

class ircbot:
    def __init__(self, addr, port, nick, channel):
        self.server = (addr, port)
        self.nick = nick
        self.channel = channel
        self.inqueue = []

        self.sock = None
        self.connect()

    def connect(self):
        if self.sock:
            self.sock.shutdown(socket.SHUT_RDWR)
            self.sock.close()
        self.sock = socket.create_connection(self.server, 60.0)
        self.send('USER %s . . %s\r\n' % (self.nick, self.nick))
        self.send('NICK %s\r\n' % self.nick)
        self.send('JOIN #%s\r\n' % self.channel)

    def send(self, data):
        self.sock.send(bytes(data, 'utf8'))

    def run(self):
        packet = ''
        bad_time = 0
        good_time = 0
        while True:
            try:
                packet += str(self.sock.recv(4096), 'utf8')
            except socket.timeout:
                good_time += 1
                if good_time > 9:
                    # Reconnect and try again
                    bad_time += 1
                    if bad_time > 3:
                        print("Having trouble staying connected...  Bailing out!")
                        sys.exit(1)
                    self.connect()
                    continue

            for hub in self.inqueue:
                self.sendMsg('#' + self.channel, hub)
            self.inqueue = []

            if len(packet) == 0:
                continue

            good_time = 0
            bad_time = 0
            lines = packet.split('\r\n')
            for ln in lines[:-1]:
                self.parse(ln)

            packet = lines[-1] if len(lines[-1]) else ''

    def parse(self, line):
        if len(line) == 0:
            return

        sender = ''
        msg = line.split(None, 3)
        if line[0] == ':':
            sender = msg[0][1:]
            msg = msg[1:]
        if len(msg) < 1:
            return

        if msg[0] == 'PING':
            self.send('PONG ' + msg[1] + '\r\n')

        elif msg[0] == 'PRIVMSG':
            try:
                recp = msg[1]
                text = msg[2]
            except IndexError:
                print("Got bad message!")
                return

            snick = sender.split('!')[0]
            if recp == self.nick:
                dest = snick
            else:
                dest = recp

            if text.startswith(':'):
                text = text[1:]

            # TODO: Commands?

            if text.lower() == '\x01version\x01':
                self.sendNotice(snick, '\x01VERSION ' + BOT_VERSION + '\x01')
                return

    def sendMsg(self, dest, msg):
        self.send('PRIVMSG ' + dest + ' :' + msg + '\r\n')

    def sendNotice(self, dest, msg):
        self.send('NOTICE ' + dest + ' :' + msg + '\r\n')


class hubber:
    def __init__(self, repo, irc, username, password):
        self.repo = repo
        self.pulls = {}
        self.issues = {}
        self.irc = irc

        self.htclient = http.client.HTTPSConnection('api.github.com')
        authkey = base64.b64encode(bytes('%s:%s' % (username, password), 'utf8')).decode('ascii')
        self.headers = { 'Authorization': 'Basic ' + authkey }

    def init_db(self):
        self.htclient.request('GET', '/repos/%s/pulls?state=open' % (self.repo),
                              headers=self.headers)
        reply = self.htclient.getresponse()
        if reply.status != 200:
            print('Error fetching open pull requests')
            print(reply.headers)
            print(reply.read())
            sys.exit(1)
        jdata = json.loads(str(reply.read(), 'utf8'))

        for pull in jdata:
            pull_id = pull['number']
            self.pulls[pull_id] = {
                'url': pull['html_url'],
                'user': pull['user']['login'],
                'title': pull['title'],
                }

        self.htclient.request('GET', '/repos/%s/issues?state=open' % (self.repo),
                              headers=self.headers)
        reply = self.htclient.getresponse()
        if reply.status != 200:
            print('Error fetching open issues')
            print(reply.headers)
            print(reply.read())
            sys.exit(1)
        jdata = json.loads(str(reply.read(), 'utf8'))

        for issue in jdata:
            issue_id = issue['number']
            self.issues[issue_id] = {
                'url': issue['html_url'],
                'user': issue['user']['login'],
                'title': issue['title'],
                }

    def check_pulls(self):
        self.htclient.request('GET', '/repos/%s/pulls?state=open' % (self.repo),
                              headers=self.headers)
        reply = self.htclient.getresponse()
        if reply.status != 200:
            print('Error fetching new pull requests')
            print(reply.headers)
            print(reply.read())
        jdata = json.loads(str(reply.read(), 'utf8'))

        watch = set(self.pulls.keys())
        for pull in jdata:
            pull_id = pull['number']
            if pull_id not in watch:
                self.pulls[pull_id] = {
                    'url': pull['html_url'],
                    'user': pull['user']['login'],
                    'title': pull['title'],
                    }
                self.irc.inqueue.append("%s has created pull request #%d (%s): %s" \
                    % (self.pulls[pull_id]['user'], pull_id,
                       self.pulls[pull_id]['title'],
                       self.pulls[pull_id]['url']))
            else:
                watch.remove(pull_id)

        for pull in watch:
            # Find out who closed it
            self.htclient.request('GET', '/repos/%s/pulls/%d' % (self.repo, pull),
                                  headers=self.headers)
            reply = self.htclient.getresponse()
            if reply.status != 200:
                print('Error fetching pull request %d' % pull)
                print(reply.headers)
                print(reply.read())
            jdata = json.loads(str(reply.read(), 'utf8'))

            if jdata['merged']:
                self.irc.inqueue.append("%s has merged pull request #%d (%s)" \
                    % (jdata['merged_by']['login'], pull,
                       jdata['title']))
            else:
                self.irc.inqueue.append("Pull request #%d (%s) has been closed" \
                    % (jdata['number'], jdata['title']))

            del self.pulls[pull]

    def check_issues(self):
        self.htclient.request('GET', '/repos/%s/issues?state=open' % (self.repo),
                              headers=self.headers)
        reply = self.htclient.getresponse()
        if reply.status != 200:
            print('Error fetching new issues')
            print(reply.headers)
            print(reply.read())
        jdata = json.loads(str(reply.read(), 'utf8'))

        watch = set(self.issues.keys())
        for issue in jdata:
            issue_id = issue['number']
            if issue_id not in watch:
                self.issues[issue_id] = {
                    'url': issue['html_url'],
                    'user': issue['user']['login'],
                    'title': issue['title'],
                    }
                self.irc.inqueue.append("%s has created issue #%d (%s): %s" \
                    % (self.issues[issue_id]['user'], issue_id,
                       self.issues[issue_id]['title'],
                       self.issues[issue_id]['url']))
            else:
                watch.remove(issue_id)

        for issue in watch:
            self.irc.inqueue.append("Issue #%d (%s) has been closed" \
                % (issue, self.issues[issue]['title']))

            del self.issues[issue]

def hub_watcher(repos):
    while True:
        time.sleep(30)
        for repo in repos:
            repo.check_pulls()
        time.sleep(30)
        for repo in repos:
            repo.check_issues()

if len(sys.argv) < 6:
    print("Usage:  %s hostname port nick channel user/repo [user/repo [...]]" % sys.argv[0])
    sys.exit(1)

host = sys.argv[1]
port = int(sys.argv[2])
nick = sys.argv[3]
channel = sys.argv[4]
hub_repos = sys.argv[5:]

hub_user = input('Github Email/Username: ')
hub_pass = getpass.getpass()

irc = ircbot(host, port, nick, channel)
repos = []
for repo in hub_repos:
    _hub = hubber(repo, irc, hub_user, hub_pass)
    _hub.init_db()
    repos.append(_hub)

hub_th = threading.Thread(target=hub_watcher, args=(repos,))
hub_th.daemon = True
hub_th.start()
irc.run()

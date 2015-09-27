#!/usr/bin/env python
# -*- coding: utf-8 -*-

import getpass
import json
import logging
import os
import re
import sys
import unicodedata
import urllib.parse
import uuid

from optparse import OptionParser
import sleekxmpp
import mf2py
import mf2util
import requests


def secure_filename(text):
    text = unicodedata.normalize('NFKD', text)
    text = re.sub('[^\w@._-]', '', text).strip().lower()
    return text


def normalize_url(url):
    if (url and not url.lower().startswith('http://')
            and not url.lower().startswith('https://')):
        url = 'http://' + url
    return url


def load_user_info(jid):
    fn = os.path.join('_data', secure_filename(jid))
    if os.path.exists(fn):
        with open(fn) as f:
            return json.load(f)
    return {}


def save_user_info(jid, data):
    fn = os.path.join('_data/', secure_filename(jid))
    os.makedirs(os.path.dirname(fn), exist_ok=True)
    with open(fn, 'w') as f:
        json.dump(data, f, indent=True)


class MicropubBot(sleekxmpp.ClientXMPP):

    CLIENT_ID = 'https://github.com/kylewm/micropub-xmpp-bot'
    REDIRECT_URI = 'https://kylewm.github.io/oob/'

    def __init__(self, jid, password):
        sleekxmpp.ClientXMPP.__init__(self, jid, password)
        self.add_event_handler("session_start", self.start)
        self.add_event_handler("message", self.message)

    def start(self, event):
        self.send_presence()
        self.get_roster()

    def message(self, msg):
        if msg['type'] not in ('chat', 'normal'):
            return

        jid = msg['from'].bare
        user_info = load_user_info(jid)

        commands = [
            ('help', [], 'Display this message', []),
            ('connect', ['url'], 'Start micropub authorization with the given URL', ['open', 'login']),
            ('whoami', [], 'Display information about the currently authorized user', ['me']),
            ('whois', ['url'], 'Get information about a person based on their URL', ['who']),
            ('post', ['text'], 'Create a new note post via Micropub', ['publish']),
            ('reply', ['url', 'text'], 'Create a new reply post via Micropub', []),
            ('like', ['url'], 'Create a new like post via Micropub', ['favorite', 'fave', 'fav']),
            ('repost', ['url'], 'Create a new repost via Micropub', ['share']),
        ]

        # next message is the auth code
        if user_info.get('auth', {}).get('awaiting-code'):
            reply = self.do_continue_connect(jid, user_info, msg['body'])
            msg.reply(reply).send()
            return

        split = msg['body'].split(maxsplit=1)
        trycmd = split[0].lower()
        tail = '' if len(split) <= 1 else split[1]

        cmd = None
        args = None
        for cmdname, argnames, desc, aliases in commands:
            if trycmd == cmdname or trycmd in aliases:
                split = tail.split(maxsplit=len(argnames))
                if len(split) < len(argnames):
                    msg.reply('I need a little more information. Try "%s %s", or "help" for a list of all commands.' % (
                        cmdname, ' '.join('[%s]' % a for a in argnames))).send()
                    return
                cmd = cmdname
                args = dict(zip(argnames, split))
                break

        if cmd is None or args is None:
            msg.reply("I didn't understand %s. Try \"help\" for a list of commands" % trycmd).send()
            return

        if cmd == 'help':
            reply = 'Here are the things I know how to do\n  ' + '\n  '.join(
                '%s %s - %s' % (
                    cmdname, ' '.join('[%s]' % a for a in argnames), desc
                ) for cmdname, argnames, desc, aliases in commands
            )
        elif cmd == 'whois':
            reply = self.do_whois(normalize_url(args['url']))

        elif cmd == 'connect':
            reply = self.do_connect(
                jid, user_info, normalize_url(args['url']))

        elif cmd == 'whoami':
            if 'me' in user_info:
                reply = "You are currently logged in as %(me)s, with micropub endpoint %(micropub)s" % user_info
            else:
                reply = "You aren't currently logged in! Use \"connect\" to get started."

        elif cmd == 'post':
            reply = self.do_publish(jid, user_info, {
                'h': 'entry',
                'content': args['text'],
            })

        elif cmd == 'reply':
            reply = self.do_publish(jid, user_info, {
                'h': 'entry',
                'in-reply-to': normalize_url(args['url']),
                'content': args['text'],
            })

        elif cmd == 'like':
            reply = self.do_publish(jid, user_info, {
                'h': 'entry',
                'like-of': normalize_url(args['url']),
            })

        elif cmd == 'repost':
            reply = self.do_publish(jid, user_info, {
                'h': 'entry',
                'repost-of': normalize_url(args['url']),
            })

        else:
            reply = "I didn't understand that, try \"help\" for a list of commands"

        if reply:
            msg.reply(reply).send()

    def get_endpoints(self, url):
        parsed = mf2py.parse(url=url)
        return (
            (parsed['rels'][rel][0] if rel in parsed['rels'] else None)
            for rel in ('authorization_endpoint', 'token_endpoint', 'micropub')
        )

    def do_connect(self, jid, user_info, me):
        state = uuid.uuid4().hex
        auth_endpt, token_endpt, micropub_endpt = self.get_endpoints(me)
        if not auth_endpt:
            return "Oops, there's no authorization_endpoint defined for " + me
        elif not token_endpt:
            return "Darn, there's no token_endpoint defined for " + me
        elif not micropub_endpt:
            return "Shoot, there's no micropub defined for " + me

        # construct redirect url for authorization
        url = auth_endpt + '?' + urllib.parse.urlencode({
            'me': me,
            'client_id': self.CLIENT_ID,
            'state': state,
            'redirect_uri': self.REDIRECT_URI,
            'scope': 'post',
        })

        # save info here, to avoid overwriting anything until auth is complete
        user_info['auth'] = {
            'awaiting-code': True,
            'auth-endpoint': auth_endpt,
            'token-endpoint': token_endpt,
            'micropub': micropub_endpt,
            'me': me,
            'state': state
        }
        save_user_info(jid, user_info)

        return "Connecting with %s. Please visit %s to start authorization." % (me, url)

    def do_continue_connect(self, jid, user_info, code):
        auth_data = user_info.setdefault('auth', {})
        auth_data['awaiting-code'] = False

        me = auth_data.get('me')
        token_endpt = auth_data.get('token-endpoint')
        micropub_endpt = auth_data.get('micropub')

        resp = requests.post(token_endpt, data={
            'code': code,
            'me': me,
            'redirect_uri': self.REDIRECT_URI,
            'client_id': self.CLIENT_ID,
            'state': auth_data.get('state'),
        })

        print('response content', resp.text)
        data = urllib.parse.parse_qs(resp.text)
        print('response data', data)

        if resp.status_code // 100 != 2:
            reply = "Token endpoint rejected our request! Code: %d, Response: %s" % (resp.status_code, resp.text)
        elif 'me' not in data:
            reply = 'Token endpoint did not include "me" in its response'
        elif 'access_token' not in data:
            reply = 'Token endpoint did not include "access_token" in its response'
        else:
            user_info['me'] = data['me'][0]
            user_info['micropub'] = micropub_endpt
            user_info['token'] = data['access_token'][0]
            reply = "Saved an access token for %s! We're ready to roll." % me

        save_user_info(jid, user_info)
        return reply

    def do_publish(self, jid, user_info, payload):
        token = user_info.get('token')
        micropub = user_info.get('micropub')

        resp = requests.post(micropub, data={
            'access_token': token,
        } + payload)

        if resp.status_code == 201 or resp.status_code == 202:
            location = resp.headers.get('Location')
            return "Success! %s" % location
        else:
            return "Something went wrong! (%s: %s)" % (resp, resp.text)

    def do_whois(self, url):
        parsed = mf2py.parse(url=url)

        props = []
        for rel in 'authorization_endpoint', 'token_endpoint', 'micropub':
            for val in parsed['rels'].get(rel, []):
                props.append((rel, val))

        # top-level h-card first, then top-level h-* with .author
        hcard = None
        for item in parsed['items']:
            if 'h-card' in item['type']:
                hcard = item
                break

        if not hcard:
            for item in parsed['items']:
                if 'author' in item['properties']:
                    hcard = item['properties']['author'][0]
                    break
        if hcard:
            if isinstance(hcard, dict):
                for prop in 'name', 'photo', 'url':
                    for val in hcard['properties'].get(prop, []):
                        props.append((prop, val))
            else:
                props.append(('name', hcard))

        return ("Here's everything I could find about %s\n  " % url) + '\n  '.join(
            "%s: %s" % (k, v) for k, v in props)


if __name__ == '__main__':
    # Setup the command line arguments.
    optp = OptionParser()

    # Output verbosity options.
    optp.add_option('-q', '--quiet', help='set logging to ERROR',
                    action='store_const', dest='loglevel',
                    const=logging.ERROR, default=logging.INFO)
    optp.add_option('-d', '--debug', help='set logging to DEBUG',
                    action='store_const', dest='loglevel',
                    const=logging.DEBUG, default=logging.INFO)
    optp.add_option('-v', '--verbose', help='set logging to COMM',
                    action='store_const', dest='loglevel',
                    const=5, default=logging.INFO)

    # JID and password options.
    optp.add_option("-j", "--jid", dest="jid",
                    help="JID to use")
    optp.add_option("-p", "--password", dest="password",
                    help="password to use")

    opts, args = optp.parse_args()

    # Setup logging.
    logging.basicConfig(level=opts.loglevel,
                        format='%(levelname)-8s %(message)s')

    if opts.jid is None:
        opts.jid = input("Username: ")
    if opts.password is None:
        opts.password = getpass.getpass("Password: ")

    # Setup the EchoBot and register plugins. Note that while plugins may
    # have interdependencies, the order in which you register them does
    # not matter.
    xmpp = MicropubBot(opts.jid, opts.password)
    xmpp.register_plugin('xep_0030')  # Service Discovery
    xmpp.register_plugin('xep_0004')  # Data Forms
    xmpp.register_plugin('xep_0060')  # PubSub
    xmpp.register_plugin('xep_0199')  # XMPP Ping

    # If you want to verify the SSL certificates offered by a server:
    # xmpp.ca_certs = "path/to/ca/cert"

    # Connect to the XMPP server and start processing XMPP stanzas.
    if xmpp.connect():
        # If you do not have the dnspython library installed, you will need
        # to manually specify the name of the server if it does not match
        # the one in the JID. For example, to use Google Talk you would
        # need to use:
        #
        # if xmpp.connect(('talk.google.com', 5222)):
        #     ...
        xmpp.process(block=True)
        print("Done")
    else:
        print("Unable to connect.")

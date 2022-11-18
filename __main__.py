import asyncio
import os
import re
import json
import fnmatch

from .comm import Communicator


class NickServ(Communicator):
    def __init__(self):
        super().__init__()

        self.settings_path = os.path.join(os.path.dirname(__file__), "settings.json")

        with open(self.settings_path) as f:
            self.settings = json.loads(f.read())

        if "banned_usernames" not in self.settings:
            self.settings["banned_usernames"] = []
        if "banned_ips" not in self.settings:
            self.settings["banned_ips"] = []

        if "registered_usernames" in self.settings:
            self.settings["registered_usernames"] = {
                username: {fingerprints} if isinstance(fingerprints, str) else set(fingerprints)
                for username, fingerprints in self.settings["registered_usernames"].items()
            }
        else:
            self.settings["registered_usernames"] = {}


    def save_settings(self):
        with open(self.settings_path + ".tmp", "w") as f:
            f.write(json.dumps({
                **self.settings,
                "registered_usernames": {
                    username: list(fingerprints)
                    for username, fingerprints in self.settings["registered_usernames"].items()
                }
            }))
        os.rename(self.settings_path + ".tmp", self.settings_path)


    def is_username_banned(self, username):
        return any(fnmatch.fnmatch(username, glob) for glob in self.settings["banned_usernames"])


    def is_ip_banned(self, ip):
        return any(fnmatch.fnmatch(ip, glob) for glob in self.settings["banned_ips"])


    def make_rand_name(self):
        return os.urandom(5).hex()


    async def init(self):
        names = await self.names()
        for name in names:
            whois = await self.whois(name)
            await self.update_user_prefixes(name, whois)


    async def on_event(self, event):
        match = re.match(r"^ \* (.+) joined\. \(Connected: \d+\)$", event)
        if match:
            await self.on_user_joined(match.group(1))
            return

        match = re.match(r"^ \* (.+) is now known as (.+)\.$", event)
        if match:
            await self.on_user_renamed(match.group(1), match.group(2))
            return


    async def on_user_joined(self, username):
        if self.is_username_banned(username):
            self.send(f"{username}, sorry, this username is banned\r\n/rename {username} {self.make_rand_name()}\r\n")
            return

        whois = await self.whois(username)
        if self.is_ip_banned(whois["ip"]):
            self.send(f"{username}, sorry, your IP is banned\r\n/kick {username}\r\n")
            return

        if username in self.settings["registered_usernames"]:
            exp = self.settings["registered_usernames"][username]
            fingerprint = whois["fingerprint"]
            if fingerprint not in exp:
                new = self.make_rand_name()
                self.send(f"Username {username} is registered to {exp}; please choose another one. If this is your account, please log in with the old key and do !trust {fingerprint}\r\n/rename {username} {new}\r\n")
                username = new
        else:
            self.send(f"/msg {username} Hi there! I'm NickServ. I help register nicks on this chat. You can use !register to reserve this nick ({username}) for yourself, so that others can't use it to impersonate you (or use !help for more info).\r\n")

        await self.update_user_prefixes(username, whois)


    async def on_user_renamed(self, old, new):
        if self.is_username_banned(new):
            self.send(f"{new}, sorry, this username is banned\r\n/rename {new} {old}\r\n")
            return

        if new in self.settings["registered_usernames"]:
            whois = await self.whois(new)
            exp = self.settings["registered_usernames"][new]
            if whois["fingerprint"] not in exp:
                self.send(f"Username {new} is registered to {exp}; please choose another one.\r\n/rename {new} {old}\r\n")
                return

            await self.update_user_prefixes(new, whois)
        else:
            await self.update_user_prefixes(new)


    async def on_message(self, username, message):
        if not message.startswith("!"):
            return

        command, *args = message[1:].split()
        command = command.lower()

        if command == "help":
            self.do_help(*args)
        elif command == "register":
            await self.do_register(username, *args)
        elif command == "unregister":
            await self.do_unregister(username, *args)
        elif command == "trust":
            await self.do_trust(username, *args)
        elif command == "distrust":
            await self.do_distrust(username, *args)
        elif command == "ban":
            await self.do_ban(username, *args)
        elif command == "banip":
            await self.do_banip(username, *args)
        elif command in ("exit", "quit", "names"):
            self.send(f"You're probably confusing me with the chat system. Use /{command} instead of !{command}.\r\n")


    def do_help(self, topic="help", *_):
        if topic == "help":
            self.send("Hi, I'm NickServ. Here's what I can do: !help !register !unregister !trust !distrust !ban !banip. Use '!help [topic]' for more info.\r\n")
        elif topic == "register":
            self.send("Use !register to reserve a username for yourself (i.e.: only your SSH key will be allowed to use it). Example: !register to register your current name, !register <nickname> to register another name.\r\n")
        elif topic == "unregister":
            self.send("The inverse of !register (duh). Use !unregister to unregister your current username, or !unregister <nickname> to free up another name you are controlling.\r\n")
        elif topic == "trust":
            self.send("Register your username to another SSH key. Example: !trust <fingerprint>, !trust <fingerprint> <username>.\r\n")
        elif topic == "distrust":
            self.send("If your username is registered to multiple SSH keys, remove one key from the trust list. Examples: !distrust (removes current key), !distrust <fingerprint> (removes some fingerprint), !distrust <fingerprint> <username>.\r\n")
        elif topic == "ban":
            self.send("Ban user(s) by username (for OPs only)\r\n")
        elif topic == "banip":
            self.send("Ban user(s) by IP (for OPs only)\r\n")
        else:
            self.send(f"Unknown topic !{topic}\r\n")


    async def do_register(self, username, wanted_username=None, *_):
        if wanted_username is None:
            wanted_username = username

        if wanted_username in self.settings["registered_usernames"]:
            self.send(f"This username is already registered\r\n")
            return

        whois = await self.whois(username)
        if whois["fingerprint"] == "(no public key)":
            self.send(f"You cannot register this username because you are not authorized by public key.\r\n")
            return

        if wanted_username not in self.settings["registered_usernames"]:
            self.settings["registered_usernames"][wanted_username] = set()
        self.settings["registered_usernames"][wanted_username].add(whois["fingerprint"])
        self.save_settings()
        self.send(f"{wanted_username} is now registered to {whois['fingerprint']}.\r\n")

        await self.update_user_prefixes(username, whois)

        if username != wanted_username:
            self.send(f"/rename {username} {wanted_username}\r\n")


    async def do_unregister(self, username, wanted_username=None, *_):
        if wanted_username is None:
            wanted_username = username

        if wanted_username not in self.settings["registered_usernames"]:
            self.send(f"This username is not registered\r\n")
            return

        whois = await self.whois(username)
        if whois["fingerprint"] not in self.settings["registered_usernames"][wanted_username] and "room/op" not in whois:
            self.send(f"This username is not registered to you\r\n")
            return

        del self.settings["registered_usernames"][wanted_username]
        self.save_settings()
        self.send(f"{wanted_username} is not registered anymore.\r\n")

        await self.update_user_prefixes(wanted_username)


    async def do_trust(self, username, added_fingerprint=None, added_username=None, *_):
        whois = await self.whois(username)
        fingerprint = whois["fingerprint"]
        if added_fingerprint is None:
            added_fingerprint = fingerprint

        if added_username is None:
            added_username = username

        if added_username not in self.settings["registered_usernames"]:
            self.send(f"This username is not registered\r\n")
            return
        if "room/op" not in whois and fingerprint not in self.settings["registered_usernames"][added_username]:
            self.send(f"{added_username} is not controlled by you\r\n")
            return
        if added_fingerprint in self.settings["registered_usernames"][added_username]:
            self.send(f"{added_username} is already registered to {added_fingerprint}\r\n")
            return

        self.settings["registered_usernames"][added_username].add(added_fingerprint)
        self.save_settings()
        self.send(f"{added_fingerprint} is registered to {added_username} now.\r\n")


    async def do_distrust(self, username, removed_fingerprint=None, removed_username=None, *_):
        whois = await self.whois(username)
        fingerprint = whois["fingerprint"]
        if removed_fingerprint is None:
            removed_fingerprint = fingerprint

        if removed_username is None:
            removed_username = username

        if removed_username not in self.settings["registered_usernames"]:
            self.send(f"This username is not registered\r\n")
            return
        if "room/op" not in whois and fingerprint not in self.settings["registered_usernames"][removed_username]:
            self.send(f"{removed_username} is not controlled by you\r\n")
            return
        if removed_fingerprint not in self.settings["registered_usernames"][removed_username]:
            self.send(f"{removed_username} is not registered to {removed_fingerprint}\r\n")
            return
        if len(self.settings["registered_usernames"][removed_username]) == 1:
            self.send(f"{removed_username} has only one trusted fingerprint. If you remove it, you'll lose access to the account. If certain, use !unregister instead.\r\n")
            return

        self.settings["registered_usernames"][removed_username].remove(removed_fingerprint)
        self.save_settings()
        self.send(f"{removed_fingerprint} is not registered to {removed_username} anymore.\r\n")


    async def do_ban(self, username, *args):
        whois = await self.whois(username)
        if "room/op" not in whois:
            self.send(f"You are not an OP\r\n")
            return

        if not args:
            self.send(f"Invalid syntax\r\n")
            return

        for arg in args:
            self.settings["banned_usernames"].append(arg)
            self.send(f"User {arg} is now banned.\r\n")
        self.save_settings()


    async def do_banip(self, username, *args):
        whois = await self.whois(username)
        if "room/op" not in whois:
            self.send(f"You are not an OP\r\n")
            return

        if not args:
            self.send(f"Invalid syntax\r\n")
            return

        for arg in args:
            self.settings["banned_ips"].append(arg)
            self.send(f"IP {arg} is now banned.\r\n")
        self.save_settings()


    async def get_prefixes_for_user(self, username, whois=None):
        if not whois:
            whois = await self.whois(username)

        prefixes = ""
        if whois["fingerprint"] not in self.settings["registered_usernames"].get(username, []):
            prefixes += "?"
        if "room/op" in whois:
            prefixes = "@"

        return prefixes


    async def update_user_prefixes(self, username, whois=None):
        if not whois:
            whois = await self.whois(username)

        prefixes = await self.get_prefixes_for_user(username, whois)

        if whois["name"] != (prefixes + (" " if prefixes else "") + username):
            self.send(f"/rename {username} {username} {prefixes or 'remove'}\r\n")


nickserv = NickServ()


async def main():
    loop = asyncio.get_running_loop()
    loop.create_task(nickserv.init())

    await nickserv.serve()

    raise ValueError("Server is down")


asyncio.run(main())

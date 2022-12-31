import asyncio
import os
import re
import json

from .comm import Communicator


class NickServ(Communicator):
    def __init__(self):
        super().__init__()

        self.settings_path = os.path.join(os.path.dirname(__file__), "settings.json")

        with open(self.settings_path) as f:
            self.settings = json.loads(f.read())

        for key in ("banned_usernames", "banned_ips"):
            if key not in self.settings:
                self.settings[key] = {}
            elif isinstance(self.settings[key], list):
                self.settings[key] = {username: "(no reason)" for username in self.settings[key]}

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


    def get_username_main(self, username):
        return username.partition("+")[0]


    def get_username_ban_reason(self, username):
        main = self.get_username_main(username)
        for regex, reason in self.settings["banned_usernames"].items():
            try:
                if re.match(f"^{regex}$", username) or re.match(f"^{regex}$", main):
                    return reason
            except Exception:
                pass
        return None


    def get_ip_ban_reason(self, ip):
        for regex, reason in self.settings["banned_ips"].items():
            try:
                if re.match(f"^{regex}$", ip):
                    return reason
            except Exception:
                pass
        return None


    def make_rand_name(self):
        return os.urandom(5).hex()


    async def init(self):
        names = await self.names()
        for name in names:
            await self.update_user_prefixes(name)


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
        reason = self.get_username_ban_reason(username)
        if reason is not None:
            self.send(f"/msg {username} Sorry, your username is banned. Reason: {reason}\r\n/rename {username} {self.make_rand_name()}\r\n")
            return

        whois = await self.whois(username)
        reason = self.get_ip_ban_reason(whois["ip"])
        if reason is not None:
            self.send(f"/msg {username} Sorry, your IP is banned. Reason: {reason}\r\n/kick {username}\r\n")
            return

        main = self.get_username_main(username)
        if main in self.settings["registered_usernames"]:
            exp = self.settings["registered_usernames"][main]
            fingerprint = whois["fingerprint"]
            if fingerprint not in exp:
                new = self.make_rand_name()
                self.send(f"Username {username} is registered to {exp}; please choose another one. If this is your account, please log in with the old key and do !trust {fingerprint}\r\n/rename {username} {new}\r\n")
                username = new
        else:
            self.send(f"/msg {username} Hi there! I'm NickServ. I help register nicks on this chat. You can use !register to reserve this nick ({username}) for yourself, so that others can't use it to impersonate you (or use !help for more info).\r\n")

        await self.update_user_prefixes(username, whois)


    async def on_user_renamed(self, old, new):
        reason = self.get_username_ban_reason(new)
        if reason:
            self.send(f"/msg {new} Sorry, this username is banned. Reason: {reason}\r\n/rename {new} {old}\r\n")
            return

        new_main = self.get_username_main(new)

        if new_main in self.settings["registered_usernames"]:
            whois = await self.whois(new)
            exp = self.settings["registered_usernames"][new_main]
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
        elif command == "unban":
            await self.do_unban(username, *args)
        elif command == "unbanip":
            await self.do_unbanip(username, *args)
        elif command in ("exit", "quit", "names"):
            self.send(f"You're probably confusing me with the chat system. Use /{command} instead of !{command}.\r\n")


    def do_help(self, topic="help", *_):
        if topic.startswith("!"):
            topic = topic[1:]
        if topic == "help":
            self.send("Hi, I'm NickServ. Here's what I can do: !help !register !unregister !trust !distrust !ban !banip !unban !unbanip. Use '!help [topic]' for more info.\r\n")
        elif topic == "register":
            self.send("Use !register to reserve a username for yourself (i.e.: only your SSH key will be allowed to use it). Example: !register to register your current name, !register <nickname> to register another name.\r\n")
        elif topic == "unregister":
            self.send("The inverse of !register (duh). Use !unregister to unregister your current username, or !unregister <nickname> to free up another name you are controlling.\r\n")
        elif topic == "trust":
            self.send("Register your username to another SSH key. Example: !trust <fingerprint>, !trust <fingerprint> <username>.\r\n")
        elif topic == "distrust":
            self.send("If your username is registered to multiple SSH keys, remove one key from the trust list. Examples: !distrust (removes current key), !distrust <fingerprint> (removes some fingerprint), !distrust <fingerprint> <username>.\r\n")
        elif topic == "ban":
            self.send("Ban user(s) by username (for OPs only). Example !ban root Common username\r\n")
        elif topic == "banip":
            self.send("Ban user(s) by IP (for OPs only). Example !ban 127.* Local network\r\n")
        elif topic == "unban":
            self.send("Unban user(s) by username (for OPs only)\r\n")
        elif topic == "unbanip":
            self.send("Unban user(s) by IP (for OPs only)\r\n")
        else:
            self.send(f"Unknown topic !{topic}\r\n")


    async def do_register(self, username, wanted_username=None, *_):
        if wanted_username is None:
            wanted_username = username
        wanted_username = self.get_username_main(wanted_username)

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

        if self.get_username_main(username) != wanted_username:
            self.send(f"/rename {username} {wanted_username}\r\n")


    async def do_unregister(self, username, wanted_username=None, *_):
        if wanted_username is None:
            wanted_username = username
        wanted_username = self.get_username_main(wanted_username)

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

        names = await self.names()
        for name in names:
            if self.get_username_main(name) == wanted_username:
                await self.update_user_prefixes(name)


    async def do_trust(self, username, added_fingerprint=None, added_username=None, *_):
        whois = await self.whois(username)
        fingerprint = whois["fingerprint"]
        if added_fingerprint is None:
            added_fingerprint = fingerprint

        if added_username is None:
            added_username = username
        added_username = self.get_username_main(added_username)

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
        removed_username = self.get_username_main(removed_username)

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


    async def do_ban(self, username, banned_username=None, reason="(no reason)"):
        whois = await self.whois(username)
        if "room/op" not in whois:
            self.send("You are not an OP\r\n")
            return

        if not banned_username:
            self.send("Invalid syntax\r\n")
            return

        self.settings["banned_usernames"][banned_username] = reason
        self.send(f"User {banned_username} is now banned.\r\n")
        self.save_settings()


    async def do_banip(self, username, banned_ip=None, reason="(no reason)"):
        whois = await self.whois(username)
        if "room/op" not in whois:
            self.send("You are not an OP\r\n")
            return

        if not banned_ip:
            self.send("Invalid syntax\r\n")
            return

        self.settings["banned_ips"][banned_ip] = reason
        self.send(f"IP {banned_ip} is now banned.\r\n")
        self.save_settings()


    async def do_unban(self, username, *args):
        whois = await self.whois(username)
        if "room/op" not in whois:
            self.send(f"You are not an OP\r\n")
            return

        if not args:
            self.send(f"Invalid syntax\r\n")
            return

        old_list = self.settings["banned_usernames"]
        new_list = [username for username in old_list if username not in args]
        if len(new_list) == len(old_list):
            self.send(f"No changes\r\n")
        else:
            self.settings["banned_usernames"] = new_list
            self.send(f"Unbanned\r\n")
        self.save_settings()


    async def do_unbanip(self, username, *args):
        whois = await self.whois(username)
        if "room/op" not in whois:
            self.send(f"You are not an OP\r\n")
            return

        if not args:
            self.send(f"Invalid syntax\r\n")
            return

        old_list = self.settings["banned_ips"]
        new_list = [ip for ip in old_list if ip not in args]
        if len(new_list) == len(old_list):
            self.send(f"No changes\r\n")
        else:
            self.settings["banned_ips"] = new_list
            self.send(f"Unbanned\r\n")
        self.save_settings()


    async def get_prefixes_for_user(self, username, whois=None):
        if not whois:
            whois = await self.whois(username)

        main = self.get_username_main(username)

        prefixes = ""
        if whois["fingerprint"] not in self.settings["registered_usernames"].get(main, []):
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

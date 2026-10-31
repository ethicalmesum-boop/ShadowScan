import subprocess
import json

def check_live_hosts(subdomains):
    """
    Uses httpx to check which subdomains are alive.
    """
    print("[*] Checking for live hosts using httpx...")
    live_hosts = []
    
    # Subdomains ko ek string mein convert karna (newline separated)
    input_data = "\n".join(subdomains)
    
    try:
        # httpx command run karna with JSON output for easy parsing
        process = subprocess.Popen(
            ['httpx', '-silent', '-json'], 
            stdin=subprocess.PIPE, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE, 
            text=True
        )
        stdout, stderr = process.communicate(input=input_data)

        # JSON output se domains nikaalna
        for line in stdout.splitlines():
            try:
                data = json.loads(line)
                # Hum sirf woh domain lenge jiska status 200-499 ke beech ho
                if data.get('status_code') and 200 <= data.get('status_code') < 500:
                    live_hosts.append(data.get('url'))
            except json.JSONDecodeError:
                continue
                
    except Exception as e:
        print(f"[-] Error running httpx: {e}")

    return live_hosts

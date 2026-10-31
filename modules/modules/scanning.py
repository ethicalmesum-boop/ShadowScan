import subprocess

def check_live_hosts(subdomains):
    """
    Uses httpx to check which subdomains are alive.
    -silent: removes banner and unnecessary info
    -nc: removes color codes for cleaner python strings
    """
    print("[*] Checking for live hosts using httpx...")
    live_hosts = []
    
    # Subdomains ko newline separated string mein badlein
    input_data = "\n".join(subdomains)
    
    try:
        # Humne yahan se '-e' ya koi bhi invalid flag hata diya hai
        process = subprocess.Popen(
            ['httpx', '-silent', '-nc'], 
            stdin=subprocess.PIPE, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE, 
            text=True
        )
        stdout, stderr = process.communicate(input=input_data)

        for line in stdout.splitlines():
            url = line.strip()
            if url:
                live_hosts.append(url)
                
    except Exception as e:
        print(f"[-] Error running httpx: {e}")

    return live_hosts
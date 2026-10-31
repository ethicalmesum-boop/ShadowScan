import subprocess

def get_tech_stack(target):
    print(f"[*] Fingerprinting technology for {target}...")
    try:
        # whatweb use karke tech stack nikaalna
        process = subprocess.Popen(
            ['whatweb', target], 
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE, 
            text=True
        )
        stdout, stderr = process.communicate()
        return stdout.strip()
    except Exception as e:
        return f"[-] Tech fingerprinting failed: {e}"
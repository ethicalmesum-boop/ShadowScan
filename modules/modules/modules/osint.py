import subprocess
import os

def harvest_emails(target):
    print(f"[*] Gathering OSINT data for {target}...")
    
    if not os.path.exists('reports'):
        os.makedirs('reports')

    output_file = f"reports/osint_{target}.txt"

    try:
        # Changed -b google to -b all to prevent the exit status 1 error
        cmd = f"theHarvester -d {target} -b all -f {output_file}"
        
        # shell=True is necessary for theHarvester to execute correctly on Kali
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        
        if result.returncode == 0:
            print(f"[+] OSINT gathering complete. Results saved to {output_file}")
        else:
            # theHarvester often exits with 1 even if it finds data. 
            # We check if the file was created instead of relying on returncode.
            if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
                print(f"[+] OSINT data gathered and saved to {output_file}")
            else:
                print(f"[-] No OSINT data found for {target}.")
            
    except Exception as e:
        print(f"[-] OSINT Error: {e}")
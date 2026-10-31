import subprocess

def harvest_emails(target):
    """
    OSINT Layer: Uses theHarvester and Dmitry to gather emails and domain intel.
    """
    osint_results = []

    # 1. theHarvester (Email and Subdomain harvesting)
    try:
        # Using -b all to search across all available sources
        cmd_harvester = f"theHarvester -d {target} -b all"
        res_harvester = subprocess.check_output(cmd_harvester, shell=True, text=True)
        osint_results.append("[theHarvester Results]\n" + res_harvester)
    except Exception as e:
        osint_results.append(f"theHarvester Error: {e}")

    # 2. Dmitry (Domain Information Gathering Tool)
    try:
        # -i flag performs a comprehensive scan (Whois, Subnets, etc.)
        cmd_dmitry = f"dmitry -i {target}"
        res_dmitry = subprocess.check_output(cmd_dmitry, shell=True, text=True)
        osint_results.append("\n[Dmitry OSINT Results]\n" + res_dmitry)
    except Exception as e:
        osint_results.append(f"Dmitry Error: {e}")

    # Combine all results into one string
    final_report = "\n".join(osint_results)
    
    # Save to file to ensure no data is lost
    try:
        with open(f"reports/osint_{target}.txt", "w") as f:
            f.write(final_report)
    except Exception as e:
        print(f"File Save Error: {e}")

    return final_report
"""
Antivirus Detector - Detects installed antivirus software on Windows
"""

import platform


def detect_antivirus() -> str:
    """
    Detect installed antivirus software
    
    Returns:
        Name of detected antivirus or "Unknown"
    """
    if platform.system() != "Windows":
        return "Not Windows"
    
    try:
        import wmi

        # Primary method: query the Windows Security Center (SecurityCenter2 namespace).
        # This is equivalent to: Get-CimInstance -Namespace root\SecurityCenter2 -ClassName AntiVirusProduct
        # It correctly detects all AV products that register with Windows Security Center,
        # including Bitdefender, Kaspersky, Norton, etc.
        sc2 = wmi.WMI(namespace=r"root\SecurityCenter2")
        av_products = sc2.AntiVirusProduct()
        if av_products:
            # When multiple AVs are registered (common when a third-party AV is
            # installed — Windows keeps Defender registered alongside it), prefer
            # the non-Defender entry. Defender is always the fallback.
            DEFENDER_NAMES = ("windows defender", "microsoft defender")
            non_defender = [
                p for p in av_products
                if not any(d in p.displayName.lower() for d in DEFENDER_NAMES)
            ]
            best = non_defender[0] if non_defender else av_products[0]
            return best.displayName

    except Exception as e:
        print(f"SecurityCenter2 query failed, trying fallback: {e}")

    try:
        import wmi
        c = wmi.WMI()

        # Fallback: scan services for known AV keywords
        av_keywords = [
            'defender', 'antivirus', 'avast', 'avg', 'kaspersky',
            'mcafee', 'norton', 'bitdefender', 'eset', 'sophos',
            'trend micro', 'malwarebytes', 'avira'
        ]
        for av in c.Win32_Service(PathName="*"):
            av_name = av.DisplayName.lower() if av.DisplayName else ""
            for keyword in av_keywords:
                if keyword in av_name:
                    return av.DisplayName

        # Last resort: check for the Windows Defender process
        for process in c.Win32_Process():
            if process.Name and 'MsMpEng.exe' in process.Name:
                return "Windows Defender"

    except Exception as e:
        print(f"Error detecting AV (fallback): {e}")

    # Final fallback
    return "Windows Defender (Default)"


if __name__ == "__main__":
    print(f"Detected Antivirus: {detect_antivirus()}")

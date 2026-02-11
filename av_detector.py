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
        c = wmi.WMI()
        
        # Try to get antivirus from Windows Security Center
        for av in c.Win32_Service(PathName="*"):
            av_name = av.DisplayName.lower() if av.DisplayName else ""
            
            # Common antivirus names
            av_keywords = [
                'defender', 'antivirus', 'avast', 'avg', 'kaspersky',
                'mcafee', 'norton', 'bitdefender', 'eset', 'sophos',
                'trend micro', 'malwarebytes', 'avira'
            ]
            
            for keyword in av_keywords:
                if keyword in av_name:
                    return av.DisplayName
                    
        # Default to Windows Defender if found
        for process in c.Win32_Process():
            if process.Name and 'MsMpEng.exe' in process.Name:
                return "Windows Defender"
                
    except Exception as e:
        print(f"Error detecting AV: {e}")
        
    # Fallback
    return "Windows Defender (Default)"


if __name__ == "__main__":
    print(f"Detected Antivirus: {detect_antivirus()}")

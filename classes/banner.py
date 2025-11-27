"""
Banner and branding for CodeTwo PST Forensic Tool
"""
from .config import VERSION

BANNER = """
╔══════════════════════════════════════════════════════════════════════════════════════════╗
║                                                                                          ║
║  ██████╗  ██████╗  ██████╗ ████████╗███████╗███████╗██╗  ██╗████████╗ ██████╗ ██████╗    ║
║  ██╔══██╗██╔═══██╗██╔═══██╗╚══██╔══╝██╔════╝██╔════╝██║ ██╔╝╚══██╔══╝██╔═══██╗██╔══██╗   ║
║  ██████╔╝██║   ██║██║   ██║   ██║   ███████╗█████╗  █████╔╝    ██║   ██║   ██║██████╔╝   ║
║  ██╔══██╗██║   ██║██║   ██║   ██║   ╚════██║██╔══╝  ██╔═██╗    ██║   ██║   ██║██╔══██╗   ║
║  ██║  ██║╚██████╔╝╚██████╔╝   ██║   ███████║███████╗██║  ██╗   ██║   ╚██████╔╝██║  ██║   ║
║  ╚═╝  ╚═╝ ╚═════╝  ╚═════╝    ╚═╝   ╚══════╝╚══════╝╚═╝  ╚═╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝   ║
║                                                                                          ║
║                   CodeTwo Backup PST Forensic Tool v{version}                                ║
║                                                                                          ║
║                           Rootsektor IT-Security GmbH                                    ║
║                               www.rootsektor.de                                          ║
║                                                                                          ║
║     Author:  Sebastian Michel (s.michel@rootsektor.de)                                   ║
║     Purpose: Forensic PST Reconstruction from Encrypted CodeTwo Backups                  ║
║                                                                                          ║
╚══════════════════════════════════════════════════════════════════════════════════════════╝
""".format(version=VERSION)


def print_banner():
    """Print the banner to console"""
    print(BANNER)

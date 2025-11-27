"""
CodeTwo Backup PST Forensic Tool
================================

A professional forensic tool for decrypting CodeTwo Office365 Backup archives
and directly creating PST files without intermediate decrypted files.

Features:
- Direct decrypt-to-PST pipeline (no intermediate files)
- Multiprocessing for parallel decryption
- Full property support (Subject, Sender, Recipients, Body, Attachments)
- Message deduplication
- Forensic logging with SHA256 hashes
- Batch processing for multiple mailboxes

Author:  Sebastian Michel
Company: Rootsektor IT-Security GmbH
Email:   s.michel@rootsektor.de
Web:     www.rootsektor.de

License: Forensic Analysis & Data Recovery Only
"""

from .classes.config import VERSION, TOOL_NAME
from .classes.banner import print_banner, BANNER
from .classes.crypto import CodeTwoDecryptor, calculate_sha256
from .classes.database import SdfDatabaseReader, MailboxInfoReader, FolderData
from .classes.dll_loader import DLLLoader
from .classes.pst_builder import PSTBuilder
from .classes.forensic_logger import ForensicLogger, ForensicRecord, ProcessingStats
from .classes.processor import MailboxProcessor, BatchProcessor

__version__ = VERSION
__all__ = [
    'VERSION',
    'TOOL_NAME',
    'print_banner',
    'BANNER',
    'CodeTwoDecryptor',
    'calculate_sha256',
    'SdfDatabaseReader',
    'MailboxInfoReader',
    'FolderData',
    'DLLLoader',
    'PSTBuilder',
    'ForensicLogger',
    'ForensicRecord',
    'ProcessingStats',
    'MailboxProcessor',
    'BatchProcessor',
]

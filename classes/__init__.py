"""
CodeTwo Backup PST Forensic Tool - Classes Module
=================================================

All core classes and utilities for the forensic tool.
"""

from .config import VERSION, TOOL_NAME, DLL_DIR
from .banner import print_banner, BANNER
from .crypto import CodeTwoDecryptor, calculate_sha256
from .database import SdfDatabaseReader, MailboxInfoReader, FolderData
from .dll_loader import DLLLoader
from .pst_builder import PSTBuilder
from .forensic_logger import ForensicLogger, ForensicRecord, ProcessingStats
from .processor import MailboxProcessor, BatchProcessor

__all__ = [
    'VERSION',
    'TOOL_NAME',
    'DLL_DIR',
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

"""
Forensic logging for CodeTwo PST Forensic Tool
"""
import csv
import json
from pathlib import Path
from datetime import datetime
from dataclasses import dataclass, asdict
from typing import List, Dict, Any


@dataclass
class ForensicRecord:
    """Forensic record for each processed message"""
    timestamp: str
    source_file: str
    source_hash_sha256: str
    encrypted_size: int
    decrypted_size: int
    folder_id: int
    folder_name: str
    subject: str
    sender: str
    recipients: str
    message_date: str
    is_read: bool
    has_attachments: bool
    attachment_count: int
    recipient_count: int
    property_count: int
    decryption_time_ms: float
    pst_add_time_ms: float
    status: str
    error_message: str = ""


@dataclass
class ProcessingStats:
    """Overall statistics for the processing"""
    start_time: str
    end_time: str
    total_files: int
    successful: int
    failed: int
    duplicates: int
    total_encrypted_bytes: int
    total_decrypted_bytes: int
    total_attachments: int
    total_recipients: int
    read_messages: int
    unread_messages: int
    total_time_seconds: float
    decryption_time_seconds: float
    pst_build_time_seconds: float
    storage_key: str
    aes_key_hash: str
    aes_iv_hash: str
    mailbox_name: str
    mailbox_email: str
    total_folders: int
    pst_file_path: str
    pst_file_size: int
    workers_used: int


class ForensicLogger:
    """Handles forensic logging and statistics"""

    def __init__(self, output_dir: Path, base_name: str):
        self.output_dir = output_dir
        self.base_name = base_name
        self.records: List[ForensicRecord] = []
        self.start_time = datetime.now()

    def add_record(self, record: ForensicRecord):
        """Add a forensic record"""
        self.records.append(record)

    def create_record(
        self,
        source_file: str,
        source_hash: str,
        encrypted_size: int,
        decrypted_size: int,
        folder_id: int,
        folder_name: str,
        metadata: Dict[str, Any],
        decryption_time_ms: float,
        pst_add_time_ms: float,
        status: str,
        error_message: str = ""
    ) -> ForensicRecord:
        """Create a new forensic record"""
        return ForensicRecord(
            timestamp=datetime.now().isoformat(),
            source_file=source_file,
            source_hash_sha256=source_hash,
            encrypted_size=encrypted_size,
            decrypted_size=decrypted_size,
            folder_id=folder_id,
            folder_name=folder_name,
            subject=metadata.get('subject', ''),
            sender=metadata.get('sender', ''),
            recipients=metadata.get('recipients', ''),
            message_date=metadata.get('message_date', ''),
            is_read=metadata.get('is_read', False),
            has_attachments=metadata.get('attachment_count', 0) > 0,
            attachment_count=metadata.get('attachment_count', 0),
            recipient_count=metadata.get('recipient_count', 0),
            property_count=metadata.get('property_count', 0),
            decryption_time_ms=decryption_time_ms,
            pst_add_time_ms=pst_add_time_ms,
            status=status,
            error_message=error_message
        )

    def write_csv(self) -> Path:
        """Write forensic log to CSV file"""
        csv_file = self.output_dir / f"{self.base_name}.forensic.csv"

        fieldnames = [
            'timestamp', 'source_file', 'source_hash_sha256',
            'encrypted_size', 'decrypted_size', 'folder_id', 'folder_name',
            'subject', 'sender', 'recipients', 'message_date', 'is_read',
            'has_attachments', 'attachment_count', 'recipient_count',
            'property_count', 'decryption_time_ms', 'pst_add_time_ms',
            'status', 'error_message'
        ]

        with open(csv_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for record in self.records:
                writer.writerow(asdict(record))

        return csv_file

    def write_summary(
        self,
        stats: ProcessingStats
    ) -> Path:
        """Write summary JSON file"""
        summary_file = self.output_dir / f"{self.base_name}.forensic.json"

        with open(summary_file, 'w', encoding='utf-8') as f:
            json.dump(asdict(stats), f, indent=2)

        return summary_file

    def calculate_stats(
        self,
        end_time: datetime,
        decryption_time: float,
        pst_build_time: float,
        storage_key: str,
        aes_key_hash: str,
        aes_iv_hash: str,
        mailbox_name: str,
        mailbox_email: str,
        total_folders: int,
        pst_file_path: Path,
        workers_used: int
    ) -> ProcessingStats:
        """Calculate processing statistics from records"""
        successful = sum(1 for r in self.records if r.status == "SUCCESS")
        failed = sum(1 for r in self.records if r.status in ("FAILED", "ERROR"))
        duplicates = sum(1 for r in self.records if r.status == "DUPLICATE")

        total_encrypted = sum(r.encrypted_size for r in self.records)
        total_decrypted = sum(r.decrypted_size for r in self.records if r.status == "SUCCESS")
        total_attachments = sum(r.attachment_count for r in self.records if r.status == "SUCCESS")
        total_recipients = sum(r.recipient_count for r in self.records if r.status == "SUCCESS")
        read_count = sum(1 for r in self.records if r.status == "SUCCESS" and r.is_read)
        unread_count = sum(1 for r in self.records if r.status == "SUCCESS" and not r.is_read)

        pst_size = 0
        if pst_file_path.exists():
            pst_size = pst_file_path.stat().st_size

        total_time = (end_time - self.start_time).total_seconds()

        return ProcessingStats(
            start_time=self.start_time.isoformat(),
            end_time=end_time.isoformat(),
            total_files=len(self.records),
            successful=successful,
            failed=failed,
            duplicates=duplicates,
            total_encrypted_bytes=total_encrypted,
            total_decrypted_bytes=total_decrypted,
            total_attachments=total_attachments,
            total_recipients=total_recipients,
            read_messages=read_count,
            unread_messages=unread_count,
            total_time_seconds=total_time,
            decryption_time_seconds=decryption_time,
            pst_build_time_seconds=pst_build_time,
            storage_key=storage_key,
            aes_key_hash=aes_key_hash,
            aes_iv_hash=aes_iv_hash,
            mailbox_name=mailbox_name,
            mailbox_email=mailbox_email,
            total_folders=total_folders,
            pst_file_path=str(pst_file_path),
            pst_file_size=pst_size,
            workers_used=workers_used
        )

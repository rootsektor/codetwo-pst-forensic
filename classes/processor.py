"""
Main processor for CodeTwo PST Forensic Tool
Handles multiprocessing decryption and PST building

Multiprocessing Strategy:
- Batch mode: Multiple mailboxes (PST files) processed in parallel
- Each mailbox worker loads its own DLLs (process isolation)
- Within each mailbox: Sequential message processing (Aspose.Email not thread-safe)
- Live progress tracking via shared Manager dictionaries
"""
import time
import logging
import queue
import threading
import sys
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Tuple, Optional, Any
from multiprocessing import Pool, cpu_count, Manager, Process
from dataclasses import dataclass, field
from concurrent.futures import ProcessPoolExecutor, as_completed

from .config import VERSION
from .banner import print_banner
from .crypto import CodeTwoDecryptor, calculate_sha256
from .database import (
    SdfDatabaseReader, MailboxInfoReader, FolderData,
    find_sdf_database, find_storage_id
)
from .dll_loader import DLLLoader
from .pst_builder import PSTBuilder
from .forensic_logger import ForensicLogger, ForensicRecord, ProcessingStats

try:
    from rich.console import Console, Group
    from rich.progress import (
        Progress, SpinnerColumn, BarColumn, TextColumn,
        TimeElapsedColumn, TimeRemainingColumn, MofNCompleteColumn,
        TaskProgressColumn, TaskID
    )
    from rich.table import Table
    from rich.panel import Panel
    from rich.live import Live
    from rich.layout import Layout
    from rich import box
    RICH_AVAILABLE = True
    console = Console()
except ImportError:
    RICH_AVAILABLE = False
    console = None


@dataclass
class DecryptedMessage:
    """Holds decrypted message data for processing"""
    file_path: Path
    encrypted_data: bytes
    decrypted_data: bytes
    folder_id: int
    decryption_time_ms: float
    source_hash: str


def decrypt_file_worker(args: Tuple) -> Tuple[str, bytes, bytes, int, float, str, str]:
    """Worker function for parallel decryption"""
    file_path, folder_id, aes_key, aes_iv = args

    start_time = time.time()

    try:
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import unpad
        import hashlib

        with open(file_path, 'rb') as f:
            encrypted_data = f.read()

        source_hash = hashlib.sha256(encrypted_data).hexdigest()

        cipher = AES.new(aes_key, AES.MODE_CBC, aes_iv)
        decrypted_data = cipher.decrypt(encrypted_data)

        try:
            decrypted_data = unpad(decrypted_data, AES.block_size)
        except ValueError:
            pass

        decryption_time = (time.time() - start_time) * 1000

        return (
            str(file_path),
            encrypted_data,
            decrypted_data,
            folder_id,
            decryption_time,
            source_hash,
            ""  # No error
        )

    except Exception as e:
        decryption_time = (time.time() - start_time) * 1000
        return (
            str(file_path),
            b"",
            b"",
            folder_id,
            decryption_time,
            "",
            str(e)
        )


@dataclass
class MailboxResult:
    """Result from processing a single mailbox"""
    mailbox_folder: str
    mailbox_email: str
    success: bool
    total_messages: int
    successful_messages: int
    failed_messages: int
    duplicate_messages: int
    pst_file: str
    pst_size_mb: float
    processing_time_seconds: float
    error_message: str = ""


@dataclass
class WorkerProgress:
    """Live progress information for a worker"""
    worker_id: int
    mailbox_email: str
    archive_file: str  # Currently processing archive file
    processed: int
    total: int
    start_time: float
    status: str = "running"  # running, completed, failed

    @property
    def progress_percent(self) -> float:
        if self.total == 0:
            return 0.0
        return (self.processed / self.total) * 100

    @property
    def eta_seconds(self) -> Optional[float]:
        if self.processed == 0 or self.total == 0:
            return None
        elapsed = time.time() - self.start_time
        rate = self.processed / elapsed
        remaining = self.total - self.processed
        return remaining / rate if rate > 0 else None


def process_mailbox_worker(args: Tuple) -> MailboxResult:
    """
    Worker function for parallel mailbox processing.
    Each worker process loads its own DLLs and creates its own PST file.
    Supports optional progress_dict for live progress tracking.
    """
    # Unpack args - support both old format (3 items) and new format (5 items with progress tracking)
    if len(args) == 5:
        mailbox_folder, storage_root, output_dir, worker_id, progress_dict = args
    else:
        mailbox_folder, storage_root, output_dir = args
        worker_id = None
        progress_dict = None

    mailbox_folder = Path(mailbox_folder)
    storage_root = Path(storage_root)
    output_dir = Path(output_dir)

    start_time = time.time()

    try:
        # Create processor in this worker process
        processor = MailboxProcessor(
            mailbox_folder=mailbox_folder,
            storage_root=storage_root,
            output_dir=output_dir,
            workers=1,  # No sub-parallelism within worker
            quiet=True,  # Suppress output in worker
            worker_id=worker_id,
            progress_dict=progress_dict
        )

        stats = processor.process()

        processing_time = time.time() - start_time

        # Mark as completed in progress dict
        if progress_dict is not None and worker_id is not None:
            progress_dict[worker_id] = {
                'status': 'completed',
                'mailbox_email': processor.mailbox_email,
                'processed': stats.successful if stats else 0,
                'total': stats.total_files if stats else 0,
                'start_time': start_time,
                'archive_file': ''
            }

        if stats:
            return MailboxResult(
                mailbox_folder=str(mailbox_folder),
                mailbox_email=processor.mailbox_email,
                success=stats.successful > 0,
                total_messages=stats.total_files,
                successful_messages=stats.successful,
                failed_messages=stats.failed,
                duplicate_messages=stats.duplicates,
                pst_file=stats.pst_file_path,
                pst_size_mb=stats.pst_file_size / 1024 / 1024,
                processing_time_seconds=processing_time
            )
        else:
            return MailboxResult(
                mailbox_folder=str(mailbox_folder),
                mailbox_email=processor.mailbox_email or "unknown",
                success=False,
                total_messages=0,
                successful_messages=0,
                failed_messages=0,
                duplicate_messages=0,
                pst_file="",
                pst_size_mb=0,
                processing_time_seconds=processing_time,
                error_message="Processing returned no stats"
            )

    except Exception as e:
        processing_time = time.time() - start_time
        # Mark as failed in progress dict
        if progress_dict is not None and worker_id is not None:
            progress_dict[worker_id] = {
                'status': 'failed',
                'mailbox_email': 'unknown',
                'processed': 0,
                'total': 0,
                'start_time': start_time,
                'archive_file': '',
                'error': str(e)
            }
        return MailboxResult(
            mailbox_folder=str(mailbox_folder),
            mailbox_email="unknown",
            success=False,
            total_messages=0,
            successful_messages=0,
            failed_messages=0,
            duplicate_messages=0,
            pst_file="",
            pst_size_mb=0,
            processing_time_seconds=processing_time,
            error_message=str(e)
        )


class MailboxProcessor:
    """Process a single mailbox: decrypt .dac files and build PST"""

    def __init__(
        self,
        mailbox_folder: Path,
        storage_root: Path,
        output_dir: Path,
        workers: int = None,
        quiet: bool = False,
        worker_id: int = None,
        progress_dict: Dict = None
    ):
        self.mailbox_folder = mailbox_folder
        self.storage_root = storage_root
        self.output_dir = output_dir
        self.workers = workers or max(1, cpu_count() - 1)
        self.quiet = quiet
        self.worker_id = worker_id
        self.progress_dict = progress_dict
        self.logger = logging.getLogger(__name__)

        self.decryptor = CodeTwoDecryptor()
        self.loader: Optional[DLLLoader] = None
        self.folders: Dict[int, FolderData] = {}
        self.mailbox_name = ""
        self.mailbox_email = ""

    def _update_progress(self, processed: int, total: int, archive_file: str = "", status: str = "running"):
        """Update the shared progress dictionary"""
        if self.progress_dict is not None and self.worker_id is not None:
            self.progress_dict[self.worker_id] = {
                'status': status,
                'mailbox_email': self.mailbox_email,
                'processed': processed,
                'total': total,
                'start_time': getattr(self, '_process_start_time', time.time()),
                'archive_file': archive_file
            }

    def find_dac_files(self) -> List[Tuple[Path, int]]:
        """Find all .dac files with folder IDs"""
        dac_files = []

        for dac_file in self.mailbox_folder.rglob("*.dac"):
            folder_id = 0
            try:
                parent_folder = dac_file.parent.name
                if parent_folder.isdigit():
                    folder_id = int(parent_folder)
            except:
                pass

            dac_files.append((dac_file, folder_id))

        return sorted(dac_files)

    def initialize(self) -> bool:
        """Initialize decryption and DLL loading"""
        # Read mailbox info
        mailbox_file = self.mailbox_folder / "mailbox_2.xml"
        self.mailbox_name, self.mailbox_email = MailboxInfoReader.read_mailbox_info(mailbox_file)

        if not self.quiet:
            print(f"\nMailbox: {self.mailbox_name} <{self.mailbox_email}>")

        # Initialize decryption
        xmc_file = self.storage_root / "storage_3.xmc"
        if not xmc_file.exists():
            self.logger.error(f"storage_3.xmc not found in {self.storage_root}")
            return False

        try:
            self.decryptor.decrypt_storage_config(str(xmc_file))
            self.decryptor.derive_aes_keys()

            if not self.quiet:
                print(f"  Storage key: {self.decryptor.storage_key}")
                key_hash, iv_hash = self.decryptor.get_key_hashes()
                print(f"  AES Key hash: {key_hash[:16]}...")

        except Exception as e:
            self.logger.error(f"Failed to initialize decryption: {e}")
            return False

        # Load DLLs
        self.loader = DLLLoader()
        if not self.loader.load_all(quiet=self.quiet):
            self.logger.error("Failed to load required DLLs")
            return False

        # Read folder structure
        sdf_path = find_sdf_database(self.mailbox_folder)
        if sdf_path:
            if not self.quiet:
                print(f"\nReading folder structure from: {sdf_path}")
            db_reader = SdfDatabaseReader(self.loader, sdf_path)
            self.folders = db_reader.read_folders()
            if not self.quiet:
                print(f"  Found {len(self.folders)} folders")
            # Log folder count for debugging even in quiet mode
            self.logger.info(f"Mailbox {self.mailbox_email}: Read {len(self.folders)} folders from {sdf_path}")
        else:
            self.logger.warning(f"Mailbox {self.mailbox_email}: No mailbox.sdf found in {self.mailbox_folder}")

        return True

    def process(self) -> Optional[ProcessingStats]:
        """Process the mailbox: decrypt and build PST"""
        if not self.initialize():
            return None

        # Find .dac files
        dac_files = self.find_dac_files()
        if not dac_files:
            if not self.quiet:
                print("No .dac files found")
            return None

        if not self.quiet:
            print(f"\nFound {len(dac_files)} encrypted message files")

        # Create output directory and PST path
        self.output_dir.mkdir(parents=True, exist_ok=True)
        pst_path = self.output_dir / f"{self.mailbox_email}.pst"
        base_name = self.mailbox_email

        # Initialize forensic logger
        forensic_logger = ForensicLogger(self.output_dir, base_name)

        # Create PST builder
        builder = PSTBuilder(self.loader, pst_path)
        if not builder.create_pst():
            self.logger.error("Failed to create PST file")
            return None

        if not self.quiet:
            print(f"\nCreated PST: {pst_path}")

        # Create folder structure
        if self.folders:
            for folder_id in sorted(self.folders.keys()):
                folder_data = self.folders[folder_id]
                parent_folder = builder.folder_map.get(folder_data.parent_id)
                builder.create_folder(folder_data, parent_folder)

            if not self.quiet:
                print(f"Created {len(builder.folder_map)} folders in PST")
            self.logger.info(f"Mailbox {self.mailbox_email}: Created {len(builder.folder_map)} folders in PST")
        else:
            self.logger.warning(f"Mailbox {self.mailbox_email}: No folders to create (self.folders is empty)")

        # Prepare work items for parallel decryption
        work_items = [
            (dac_file, folder_id, self.decryptor.aes_key, self.decryptor.aes_iv)
            for dac_file, folder_id in dac_files
        ]

        # Statistics
        success_count = 0
        fail_count = 0
        duplicate_count = 0
        total_decryption_time = 0.0
        total_pst_time = 0.0

        total = len(work_items)

        if not self.quiet:
            print(f"\nProcessing {total} messages with {self.workers} workers...")

        # Helper function to process a single result
        def process_result(result, idx=0):
            nonlocal success_count, fail_count, duplicate_count, total_decryption_time, total_pst_time

            file_path, encrypted_data, decrypted_data, folder_id, decrypt_time, source_hash, error = result

            total_decryption_time += decrypt_time / 1000.0
            folder_name = self.folders.get(folder_id, FolderData(0, 0, "Unknown", "")).display_name

            if error:
                record = forensic_logger.create_record(
                    source_file=file_path,
                    source_hash="",
                    encrypted_size=0,
                    decrypted_size=0,
                    folder_id=folder_id,
                    folder_name=folder_name,
                    metadata={},
                    decryption_time_ms=decrypt_time,
                    pst_add_time_ms=0,
                    status="DECRYPT_ERROR",
                    error_message=error
                )
                forensic_logger.add_record(record)
                fail_count += 1
            else:
                pst_start = time.time()
                success, metadata = builder.add_message(decrypted_data, folder_id)
                pst_time = (time.time() - pst_start) * 1000
                total_pst_time += pst_time / 1000.0

                if success:
                    status = "SUCCESS"
                    success_count += 1
                elif metadata.get('is_duplicate'):
                    status = "DUPLICATE"
                    duplicate_count += 1
                else:
                    status = "PST_ERROR"
                    fail_count += 1

                record = forensic_logger.create_record(
                    source_file=file_path,
                    source_hash=source_hash,
                    encrypted_size=len(encrypted_data),
                    decrypted_size=len(decrypted_data),
                    folder_id=folder_id,
                    folder_name=folder_name,
                    metadata=metadata,
                    decryption_time_ms=decrypt_time,
                    pst_add_time_ms=pst_time,
                    status=status
                )
                forensic_logger.add_record(record)

        # Choose processing mode: parallel (workers > 1) or sequential (workers == 1)
        use_multiprocessing = self.workers > 1

        if use_multiprocessing:
            # Parallel processing with Pool
            if RICH_AVAILABLE and console and not self.quiet:
                with Progress(
                    SpinnerColumn(),
                    TextColumn("[progress.description]{task.description}"),
                    BarColumn(),
                    MofNCompleteColumn(),
                    TextColumn("*"),
                    TimeElapsedColumn(),
                    TextColumn("*"),
                    TimeRemainingColumn(),
                    console=console
                ) as progress:
                    task = progress.add_task("[cyan]Processing...", total=total)
                    with Pool(processes=self.workers) as pool:
                        for result in pool.imap_unordered(decrypt_file_worker, work_items):
                            process_result(result)
                            progress.update(task, advance=1)
            else:
                with Pool(processes=self.workers) as pool:
                    for i, result in enumerate(pool.imap_unordered(decrypt_file_worker, work_items), 1):
                        if not self.quiet and (i % 10 == 0 or i == total):
                            pct = (i / total) * 100
                            print(f"\r  Progress: {i}/{total} ({pct:.1f}%)", end='', flush=True)
                        process_result(result, i)
                if not self.quiet:
                    print()
        else:
            # Sequential processing (no Pool) - safe for use in worker processes
            # Initialize progress tracking
            self._process_start_time = time.time()
            self._update_progress(0, total, "", "running")

            for i, work_item in enumerate(work_items, 1):
                # Update progress with current archive file
                current_file = Path(work_item[0]).name
                self._update_progress(i - 1, total, current_file, "running")

                if not self.quiet and (i % 10 == 0 or i == total):
                    pct = (i / total) * 100
                    print(f"\r  Progress: {i}/{total} ({pct:.1f}%)", end='', flush=True)
                result = decrypt_file_worker(work_item)
                process_result(result, i)

                # Update progress after processing
                self._update_progress(i, total, current_file, "running")
            if not self.quiet:
                print()

        # Close PST
        builder.close()

        # Calculate and save statistics
        end_time = datetime.now()
        key_hash, iv_hash = self.decryptor.get_key_hashes()

        stats = forensic_logger.calculate_stats(
            end_time=end_time,
            decryption_time=total_decryption_time,
            pst_build_time=total_pst_time,
            storage_key=self.decryptor.storage_key or "",
            aes_key_hash=key_hash,
            aes_iv_hash=iv_hash,
            mailbox_name=self.mailbox_name,
            mailbox_email=self.mailbox_email,
            total_folders=len(self.folders),
            pst_file_path=pst_path,
            workers_used=self.workers
        )

        # Write logs
        csv_file = forensic_logger.write_csv()
        json_file = forensic_logger.write_summary(stats)

        # Print results
        if not self.quiet:
            print(f"\nResults:")
            print(f"  Total Files: {total}")
            print(f"  Successful: {success_count}")
            print(f"  Duplicates Skipped: {duplicate_count}")
            print(f"  Failed: {fail_count}")
            print(f"  Read Messages: {stats.read_messages}")
            print(f"  Unread Messages: {stats.unread_messages}")
            print(f"  Total Attachments: {stats.total_attachments}")
            print(f"  Total Recipients: {stats.total_recipients}")
            print(f"  PST File: {pst_path}")
            print(f"  PST Size: {stats.pst_file_size / 1024 / 1024:.2f} MB")
            print(f"  Duration: {stats.total_time_seconds:.2f} seconds")
            print(f"  Decryption Time: {total_decryption_time:.2f} seconds")
            print(f"  PST Build Time: {total_pst_time:.2f} seconds")
            print(f"  Speed: {total / stats.total_time_seconds:.2f} messages/sec")
            print(f"\nForensic Logs:")
            print(f"  CSV: {csv_file}")
            print(f"  JSON: {json_file}")

        return stats


def _format_eta(seconds: Optional[float]) -> str:
    """Format ETA in human-readable format"""
    if seconds is None or seconds <= 0:
        return "--:--"
    if seconds < 60:
        return f"{int(seconds)}s"
    elif seconds < 3600:
        mins = int(seconds // 60)
        secs = int(seconds % 60)
        return f"{mins}m {secs}s"
    else:
        hours = int(seconds // 3600)
        mins = int((seconds % 3600) // 60)
        return f"{hours}h {mins}m"


@dataclass
class MailboxScanInfo:
    """Pre-scan information for a mailbox"""
    folder: Path
    dac_count: int
    total_size_bytes: int

    @property
    def total_size_mb(self) -> float:
        return self.total_size_bytes / (1024 * 1024)


@dataclass
class StorageScanResult:
    """Result of pre-scanning the storage"""
    mailboxes: List[MailboxScanInfo]
    total_dac_files: int
    total_size_bytes: int
    scan_time_seconds: float

    @property
    def total_size_mb(self) -> float:
        return self.total_size_bytes / (1024 * 1024)

    @property
    def total_size_gb(self) -> float:
        return self.total_size_bytes / (1024 * 1024 * 1024)


class BatchProcessor:
    """Process multiple mailboxes in parallel with live progress tracking using Rich Progress bars"""

    def __init__(
        self,
        storage_root: Path,
        output_dir: Path,
        workers: int = None
    ):
        self.storage_root = storage_root
        self.output_dir = output_dir
        self.workers = workers or max(1, cpu_count() - 1)
        self.logger = logging.getLogger(__name__)
        self.scan_result: Optional[StorageScanResult] = None

    def find_mailbox_folders(self) -> List[Path]:
        """Find all mailbox folders (containing mailbox_2.xml)"""
        mailbox_folders = []

        for subdir in self.storage_root.iterdir():
            if subdir.is_dir():
                mailbox_file = subdir / "mailbox_2.xml"
                if mailbox_file.exists():
                    mailbox_folders.append(subdir)

        return sorted(mailbox_folders)

    def pre_scan_storage(self) -> StorageScanResult:
        """
        Pre-scan the storage to count all .dac files and their total size.
        This enables accurate progress tracking and ETA calculation.
        """
        start_time = time.time()
        mailbox_folders = self.find_mailbox_folders()

        mailboxes: List[MailboxScanInfo] = []
        total_dac_files = 0
        total_size_bytes = 0

        if RICH_AVAILABLE and console:
            console.print("[yellow]Pre-scanning storage for accurate progress tracking...[/yellow]")
            with Progress(
                SpinnerColumn(),
                TextColumn("[bold blue]{task.description}"),
                BarColumn(bar_width=30),
                MofNCompleteColumn(),
                TimeElapsedColumn(),
                console=console,
                transient=True
            ) as progress:
                scan_task = progress.add_task(
                    "Scanning mailboxes...",
                    total=len(mailbox_folders)
                )

                for folder in mailbox_folders:
                    dac_count = 0
                    folder_size = 0

                    for dac_file in folder.rglob("*.dac"):
                        dac_count += 1
                        try:
                            folder_size += dac_file.stat().st_size
                        except (OSError, IOError):
                            pass

                    mailboxes.append(MailboxScanInfo(
                        folder=folder,
                        dac_count=dac_count,
                        total_size_bytes=folder_size
                    ))
                    total_dac_files += dac_count
                    total_size_bytes += folder_size

                    progress.update(scan_task, advance=1)
        else:
            print("Pre-scanning storage for accurate progress tracking...")
            for i, folder in enumerate(mailbox_folders, 1):
                dac_count = 0
                folder_size = 0

                for dac_file in folder.rglob("*.dac"):
                    dac_count += 1
                    try:
                        folder_size += dac_file.stat().st_size
                    except (OSError, IOError):
                        pass

                mailboxes.append(MailboxScanInfo(
                    folder=folder,
                    dac_count=dac_count,
                    total_size_bytes=folder_size
                ))
                total_dac_files += dac_count
                total_size_bytes += folder_size

                if i % 10 == 0 or i == len(mailbox_folders):
                    print(f"\r  Scanned {i}/{len(mailbox_folders)} mailboxes...", end='', flush=True)
            print()

        scan_time = time.time() - start_time

        self.scan_result = StorageScanResult(
            mailboxes=mailboxes,
            total_dac_files=total_dac_files,
            total_size_bytes=total_size_bytes,
            scan_time_seconds=scan_time
        )

        # Print scan summary
        if RICH_AVAILABLE and console:
            console.print(f"[green]Scan complete:[/green] {total_dac_files:,} files, "
                         f"{self.scan_result.total_size_gb:.2f} GB in {scan_time:.1f}s")
        else:
            print(f"Scan complete: {total_dac_files:,} files, "
                  f"{self.scan_result.total_size_gb:.2f} GB in {scan_time:.1f}s")

        return self.scan_result

    def process_all(self) -> bool:
        """Process all mailboxes in parallel with Rich progress bars (flicker-free)"""
        # Pre-scan storage for accurate progress tracking
        scan_result = self.pre_scan_storage()

        if not scan_result.mailboxes:
            if RICH_AVAILABLE and console:
                console.print(f"[red]No mailbox folders found in {self.storage_root}[/red]")
            else:
                print(f"No mailbox folders found in {self.storage_root}")
            return False

        num_mailboxes = len(scan_result.mailboxes)
        parallel_workers = min(self.workers, num_mailboxes)
        total_files = scan_result.total_dac_files
        total_bytes = scan_result.total_size_bytes

        # Create lookup for mailbox sizes and file counts by folder path
        mailbox_sizes: Dict[str, int] = {
            str(m.folder): m.total_size_bytes for m in scan_result.mailboxes
        }
        mailbox_file_counts: Dict[str, int] = {
            str(m.folder): m.dac_count for m in scan_result.mailboxes
        }

        # Calculate average bytes per file for throughput estimation
        avg_bytes_per_file = total_bytes / total_files if total_files > 0 else 0

        if RICH_AVAILABLE and console:
            console.print(f"\n[bold green]Processing {num_mailboxes} mailboxes[/bold green]")
            console.print(f"[bold]Total:[/bold] {total_files:,} files, {scan_result.total_size_gb:.2f} GB")
            console.print(f"[bold]Workers:[/bold] {parallel_workers} parallel\n")
        else:
            print(f"\nProcessing {num_mailboxes} mailboxes")
            print(f"Total: {total_files:,} files, {scan_result.total_size_gb:.2f} GB")
            print(f"Workers: {parallel_workers} parallel")

        self.output_dir.mkdir(parents=True, exist_ok=True)

        # Create a manager for shared state
        manager = Manager()
        progress_dict = manager.dict()

        # Prepare work items using scan results
        work_items = []
        for idx, mailbox_info in enumerate(scan_result.mailboxes):
            work_items.append((
                str(mailbox_info.folder),
                str(self.storage_root),
                str(self.output_dir),
                idx,
                progress_dict
            ))

        results: List[MailboxResult] = []
        start_time = time.time()

        # Track bytes processed for throughput calculation
        bytes_processed = 0

        if RICH_AVAILABLE and console:
            # Track stats for display
            stats_info = {"throughput": "-- MB/s", "size_gb": 0.0}

            # Create progress bar component
            progress = Progress(
                SpinnerColumn(),
                TextColumn("{task.description}", justify="left"),
                BarColumn(bar_width=30),
                TaskProgressColumn(),
                TextColumn("{task.fields[info]}", style="cyan"),
                TimeElapsedColumn(),
                TimeRemainingColumn(),
                console=console,
                expand=False,
            )

            # Create overall progress task - based on total FILES
            overall_task = progress.add_task(
                f"[bold white]Overall[/bold white]",
                total=total_files,
                info=f"0/{total_files:,}"
            )

            # Create worker slot tasks (will be reused)
            worker_tasks: Dict[int, TaskID] = {}
            for i in range(parallel_workers):
                task_id = progress.add_task(
                    f"[dim]Slot {i+1}: waiting...[/dim]",
                    total=100,
                    completed=0,
                    info="",
                    visible=True,
                    start=False
                )
                worker_tasks[i] = task_id

            # Track which mailbox is on which worker slot
            slot_to_mailbox: Dict[int, int] = {}
            mailbox_to_slot: Dict[int, int] = {}
            free_slots: List[int] = list(range(parallel_workers))
            completed_count = 0
            completed_mailboxes: set = set()
            bytes_completed = 0

            # Create lookup for bytes and file count by mailbox index
            mailbox_bytes_by_idx: Dict[int, int] = {
                idx: m.total_size_bytes for idx, m in enumerate(scan_result.mailboxes)
            }
            mailbox_files_by_idx: Dict[int, int] = {
                idx: m.dac_count for idx, m in enumerate(scan_result.mailboxes)
            }

            def make_display() -> Group:
                """Create combined display with stats and progress"""
                throughput_line = f"[bold yellow]Throughput:[/bold yellow] {stats_info['throughput']}"
                size_line = f"[bold yellow]Size:[/bold yellow] {stats_info['size_gb']:.1f} / {scan_result.total_size_gb:.1f} GB"
                return Group(throughput_line, size_line, "", progress)

            with Live(make_display(), console=console, refresh_per_second=4, transient=False) as live:
                with Pool(processes=parallel_workers) as pool:
                    result_iter = pool.imap_unordered(process_mailbox_worker, work_items)
                    pending = num_mailboxes
                    last_update = time.time()

                    while pending > 0:
                        current_time = time.time()
                        if current_time - last_update >= 0.1:
                            active_bytes_processed = 0
                            progress_snapshot = dict(progress_dict)

                            for mailbox_id, info in progress_snapshot.items():
                                status = info.get('status', 'running')

                                if mailbox_id in completed_mailboxes:
                                    continue

                                if status == 'running':
                                    if mailbox_id not in mailbox_to_slot:
                                        if free_slots:
                                            slot = free_slots.pop(0)
                                            mailbox_to_slot[mailbox_id] = slot
                                            slot_to_mailbox[slot] = mailbox_id
                                            progress.start_task(worker_tasks[slot])
                                        else:
                                            continue

                                    slot = mailbox_to_slot[mailbox_id]
                                    task_id = worker_tasks[slot]

                                    email = info.get('mailbox_email', 'loading...')
                                    if len(email) > 28:
                                        email = email[:25] + "..."

                                    processed = info.get('processed', 0)
                                    total = info.get('total', 0)

                                    if total > 0:
                                        mailbox_total_bytes = mailbox_bytes_by_idx.get(mailbox_id, 0)
                                        mailbox_progress_bytes = int(mailbox_total_bytes * (processed / total))
                                        active_bytes_processed += mailbox_progress_bytes

                                        progress.update(
                                            task_id,
                                            description=f"[cyan]{email}[/cyan]",
                                            completed=processed,
                                            total=total,
                                            info=f"{processed:,}/{total:,}"
                                        )
                                    else:
                                        progress.update(
                                            task_id,
                                            description=f"[yellow]{email}[/yellow]",
                                            completed=0,
                                            total=100,
                                            info="init..."
                                        )

                                elif status == 'completed' and mailbox_id in mailbox_to_slot:
                                    slot = mailbox_to_slot[mailbox_id]
                                    task_id = worker_tasks[slot]

                                    progress.reset(task_id)
                                    progress.update(
                                        task_id,
                                        description=f"[dim]Slot {slot+1}: waiting...[/dim]",
                                        completed=0,
                                        total=100,
                                        info="",
                                        visible=True
                                    )
                                    progress.stop_task(task_id)

                                    free_slots.append(slot)
                                    del mailbox_to_slot[mailbox_id]
                                    del slot_to_mailbox[slot]
                                    completed_mailboxes.add(mailbox_id)

                            # Calculate stats
                            current_bytes = bytes_completed + active_bytes_processed
                            elapsed = current_time - start_time

                            if total_bytes > 0:
                                current_files_estimate = int(total_files * (current_bytes / total_bytes))
                            else:
                                current_files_estimate = 0

                            if elapsed > 0 and current_bytes > 0:
                                mb_per_sec = (current_bytes / (1024 * 1024)) / elapsed
                                stats_info["throughput"] = f"{mb_per_sec:.1f} MB/s"

                            stats_info["size_gb"] = current_bytes / (1024 * 1024 * 1024)

                            progress.update(
                                overall_task,
                                completed=current_files_estimate,
                                info=f"{current_files_estimate:,}/{total_files:,}"
                            )

                            live.update(make_display())
                            last_update = current_time

                        try:
                            result = result_iter.next(timeout=0.1)
                            results.append(result)
                            completed_count += 1
                            pending -= 1

                            completed_mailbox_bytes = mailbox_sizes.get(result.mailbox_folder, 0)
                            bytes_completed += completed_mailbox_bytes
                            bytes_processed += completed_mailbox_bytes

                            # Don't print OK messages during live display - they interfere with the progress view
                            # Results will be shown in the final summary table

                        except StopIteration:
                            break
                        except Exception as e:
                            if 'TimeoutError' not in type(e).__name__ and 'timeout' not in str(type(e)).lower():
                                raise

                # Final update
                total_time_final = time.time() - start_time
                final_mb_per_sec = (total_bytes / (1024 * 1024)) / total_time_final if total_time_final > 0 else 0
                stats_info["throughput"] = f"[bold green]{final_mb_per_sec:.1f} MB/s[/bold green]"
                stats_info["size_gb"] = scan_result.total_size_gb
                progress.update(
                    overall_task,
                    completed=total_files,
                    info=f"[bold green]{total_files:,}/{total_files:,} Complete![/bold green]"
                )
                live.update(make_display())

            # Print final results with Rich
            total_time = time.time() - start_time
            self._print_rich_summary(results, total_time, num_mailboxes, parallel_workers,
                                     total_files, total_bytes, bytes_processed)

        else:
            # Fallback to simple processing without Rich
            print(f"\nProcessing {num_mailboxes} mailboxes with {parallel_workers} workers...")
            with Pool(processes=parallel_workers) as pool:
                for i, result in enumerate(pool.imap_unordered(process_mailbox_worker, work_items), 1):
                    results.append(result)
                    status = "OK" if result.success else "FAIL"
                    print(f"  [{i}/{num_mailboxes}] {status}: {result.mailbox_email}")

            total_time = time.time() - start_time
            self._print_simple_summary(results, total_time, num_mailboxes, parallel_workers)

        total_failed = sum(1 for r in results if not r.success)
        return total_failed == 0

    def _print_rich_summary(self, results: List[MailboxResult], total_time: float,
                            num_mailboxes: int, parallel_workers: int,
                            total_files: int = 0, total_bytes: int = 0,
                            bytes_processed: int = 0):
        """Print summary using Rich formatting"""
        console.print()

        # Results table
        results_table = Table(
            title="[bold]Completed Mailboxes[/bold]",
            box=box.ROUNDED,
            show_lines=False
        )
        results_table.add_column("Status", justify="center", width=8)
        results_table.add_column("Mailbox", style="cyan")
        results_table.add_column("Messages", justify="right")
        results_table.add_column("PST Size", justify="right")
        results_table.add_column("Time", justify="right")

        for result in results:
            status = "[bold green]OK[/bold green]" if result.success else "[bold red]FAIL[/bold red]"
            results_table.add_row(
                status,
                result.mailbox_email,
                f"{result.successful_messages}/{result.total_messages}",
                f"{result.pst_size_mb:.2f} MB",
                f"{result.processing_time_seconds:.1f}s"
            )

        console.print(results_table)

        # Statistics
        total_successful = sum(1 for r in results if r.success)
        total_failed_count = sum(1 for r in results if not r.success)
        total_messages = sum(r.total_messages for r in results)
        total_successful_msgs = sum(r.successful_messages for r in results)
        total_pst_size = sum(r.pst_size_mb for r in results)

        # Calculate throughput metrics
        msg_throughput = total_messages / total_time if total_time > 0 else 0
        # Use total_bytes (from scan) for accurate throughput calculation
        mb_throughput = (total_bytes / (1024 * 1024)) / total_time if total_time > 0 else 0
        source_size_gb = total_bytes / (1024 * 1024 * 1024)

        stats_table = Table(
            title="[bold]Batch Processing Summary[/bold]",
            box=box.ROUNDED,
            show_header=False,
            expand=False
        )
        stats_table.add_column("Metric", style="bold")
        stats_table.add_column("Value", style="cyan")

        stats_table.add_row("Mailboxes Processed", str(num_mailboxes))
        stats_table.add_row("Successful", f"[green]{total_successful}[/green]")
        stats_table.add_row("Failed", f"[red]{total_failed_count}[/red]" if total_failed_count > 0 else "0")
        stats_table.add_row("Parallel Workers", str(parallel_workers))
        stats_table.add_row("", "")
        stats_table.add_row("Total Files (Source)", f"{total_files:,}")
        stats_table.add_row("Source Data Size", f"{source_size_gb:.2f} GB")
        stats_table.add_row("", "")
        stats_table.add_row("Messages Processed", f"{total_messages:,}")
        stats_table.add_row("Successful Messages", f"{total_successful_msgs:,}")
        stats_table.add_row("Total PST Size", f"{total_pst_size:.2f} MB")
        stats_table.add_row("", "")
        stats_table.add_row("Total Time", f"{total_time:.2f}s ({total_time/60:.1f} min)")
        stats_table.add_row("Avg Time/Mailbox", f"{total_time/num_mailboxes:.2f}s")
        stats_table.add_row("", "")
        stats_table.add_row("[bold]Performance[/bold]", "")
        stats_table.add_row("Messages/sec", f"{msg_throughput:.1f}")
        stats_table.add_row("Read Throughput", f"[bold]{mb_throughput:.1f} MB/s[/bold]")
        stats_table.add_row("", "")
        stats_table.add_row("Output Directory", str(self.output_dir))

        console.print(stats_table)

        # Failed mailboxes
        failed_results = [r for r in results if not r.success]
        if failed_results:
            console.print("\n[bold red]Failed Mailboxes:[/bold red]")
            for r in failed_results:
                console.print(f"  [red]- {r.mailbox_email}: {r.error_message}[/red]")

    def _print_simple_summary(self, results: List[MailboxResult], total_time: float,
                               num_mailboxes: int, parallel_workers: int):
        """Print summary without Rich"""
        total_successful = sum(1 for r in results if r.success)
        total_failed = sum(1 for r in results if not r.success)
        total_messages = sum(r.total_messages for r in results)
        total_successful_msgs = sum(r.successful_messages for r in results)
        total_pst_size = sum(r.pst_size_mb for r in results)
        throughput = total_messages / total_time if total_time > 0 else 0

        print(f"\n{'='*70}")
        print("BATCH PROCESSING COMPLETE")
        print(f"{'='*70}")
        print(f"  Mailboxes Processed:  {num_mailboxes}")
        print(f"  Successful:           {total_successful}")
        print(f"  Failed:               {total_failed}")
        print(f"  Parallel Workers:     {parallel_workers}")
        print(f"{'='*70}")
        print(f"  Total Messages:       {total_messages}")
        print(f"  Successful Messages:  {total_successful_msgs}")
        print(f"  Total PST Size:       {total_pst_size:.2f} MB")
        print(f"{'='*70}")
        print(f"  Total Time:           {total_time:.2f} seconds ({total_time/60:.1f} minutes)")
        print(f"  Avg Time/Mailbox:     {total_time/num_mailboxes:.2f} seconds")
        print(f"  Throughput:           {throughput:.2f} messages/sec")
        print(f"  Output Directory:     {self.output_dir}")
        print(f"{'='*70}")

        failed_results = [r for r in results if not r.success]
        if failed_results:
            print("\nFailed Mailboxes:")
            for r in failed_results:
                print(f"  - {r.mailbox_email}: {r.error_message}")

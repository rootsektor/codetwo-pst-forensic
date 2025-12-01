#!/usr/bin/env python3.11
"""
CodeTwo Backup PST Forensic Tool
================================

A professional forensic tool for decrypting CodeTwo Office365 Backup archives
and directly creating PST files without intermediate decrypted files.

Author:  Sebastian Michel
Company: Rootsektor IT-Security GmbH
Email:   s.michel@rootsektor.de
Web:     www.rootsektor.de
"""

import sys
import os
import logging
import argparse
from pathlib import Path
from multiprocessing import cpu_count

# Fix Windows console encoding for Unicode characters
if sys.platform == 'win32':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
        sys.stderr.reconfigure(encoding='utf-8')
    except:
        pass

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from classes.config import VERSION
from classes.banner import print_banner
from classes.processor import MailboxProcessor, BatchProcessor


def setup_logging(verbose: bool = False, log_file: Path = None):
    """Setup logging configuration"""
    level = logging.DEBUG if verbose else logging.INFO

    handlers = [logging.StreamHandler()]
    if log_file:
        handlers.append(logging.FileHandler(log_file))

    logging.basicConfig(
        level=level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        handlers=handlers
    )


def main():
    parser = argparse.ArgumentParser(
        description='CodeTwo Backup PST Forensic Tool - Direct Decrypt & PST Creation',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Process single mailbox
  python main.py data/mailbox_folder -o output/

  # Process all mailboxes in a storage folder
  python main.py data/ -o output/ --batch

  # Use multiple workers for faster decryption
  python main.py data/ -o output/ --batch -w 8

Author:  Sebastian Michel (s.michel@rootsektor.de)
Company: Rootsektor IT-Security GmbH (www.rootsektor.de)
Purpose: Forensic PST Reconstruction from Encrypted CodeTwo Backups
        """
    )

    parser.add_argument(
        'input_dir',
        help='Path to mailbox folder or storage root for batch mode'
    )

    parser.add_argument(
        '-o', '--output',
        default='output',
        help='Output directory for PST files (default: output/)'
    )

    parser.add_argument(
        '-w', '--workers',
        type=int,
        default=None,
        help=f'Number of parallel workers for decryption (default: {max(1, cpu_count() - 1)})'
    )

    parser.add_argument(
        '--batch',
        action='store_true',
        help='Batch process all mailboxes in the storage folder'
    )

    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose logging'
    )

    parser.add_argument(
        '-q', '--quiet',
        action='store_true',
        help='Minimal output (only errors)'
    )

    parser.add_argument(
        '--version',
        action='version',
        version=f'CodeTwo Backup PST Forensic Tool v{VERSION}'
    )

    args = parser.parse_args()

    # Validate input directory
    input_dir = Path(args.input_dir)
    if not input_dir.exists():
        print(f"ERROR: Directory not found: {input_dir}")
        sys.exit(1)

    output_dir = Path(args.output)

    # Setup logging
    setup_logging(verbose=args.verbose)

    # Print banner
    if not args.quiet:
        print_banner()

    try:
        if args.batch:
            # Batch process all mailboxes
            processor = BatchProcessor(
                storage_root=input_dir,
                output_dir=output_dir,
                workers=args.workers
            )
            success = processor.process_all()
        else:
            # Single mailbox processing
            # Determine if input_dir is a mailbox folder or contains storage_3.xmc
            storage_root = input_dir
            mailbox_folder = input_dir

            # Check for storage_3.xmc
            xmc_file = input_dir / "storage_3.xmc"
            if not xmc_file.exists():
                # Check parent
                if (input_dir.parent / "storage_3.xmc").exists():
                    storage_root = input_dir.parent

            processor = MailboxProcessor(
                mailbox_folder=mailbox_folder,
                storage_root=storage_root,
                output_dir=output_dir,
                workers=args.workers,
                quiet=args.quiet
            )

            stats = processor.process()
            success = stats is not None and stats.successful > 0

        if success:
            if not args.quiet:
                print("\nProcessing completed successfully!")
            sys.exit(0)
        else:
            if not args.quiet:
                print("\nProcessing completed with errors")
            sys.exit(1)

    except KeyboardInterrupt:
        print("\nInterrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"\nERROR: {e}")
        logging.exception("Fatal error")
        sys.exit(1)


if __name__ == '__main__':
    main()

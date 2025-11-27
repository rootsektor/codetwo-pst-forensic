"""
Database reading for CodeTwo backup folder structure
"""
import logging
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class FolderData:
    """Mailbox folder information"""
    folder_id: int
    parent_id: int
    display_name: str
    entry_id: str
    folder_class: str = "IPF.Note"
    well_known_name: int = 255


class SdfDatabaseReader:
    """Read folder structure from mailbox.sdf database using SqlServerCe DLL"""

    def __init__(self, loader, sdf_path: Path):
        self.loader = loader
        self.sdf_path = sdf_path

    def read_folders(self) -> Dict[int, FolderData]:
        """Read folder structure from database"""
        folders = {}

        SqlCeConnection = self.loader.types.get('SqlCeConnection')
        if not SqlCeConnection:
            logger.warning(f"SqlCeConnection type not available, cannot read folders from {self.sdf_path}")
            return folders

        try:
            import System
            conn_str = f"Data Source={self.sdf_path}"
            conn = System.Activator.CreateInstance(SqlCeConnection, conn_str)
            conn.Open()

            cmd = conn.CreateCommand()
            cmd.CommandText = "SELECT FolderID, ParentFolderID, DisplayName, EntryID, FolderClass, WellKnownName FROM Folder"

            reader = cmd.ExecuteReader()
            while reader.Read():
                folder_id = int(reader.GetValue(0)) if not reader.IsDBNull(0) else 0
                parent_id = int(reader.GetValue(1)) if not reader.IsDBNull(1) else 0
                display_name = str(reader.GetValue(2)) if not reader.IsDBNull(2) else f"Folder_{folder_id}"
                entry_id = str(reader.GetValue(3)) if not reader.IsDBNull(3) else ""
                folder_class = str(reader.GetValue(4)) if not reader.IsDBNull(4) else "IPF.Note"
                well_known = int(reader.GetValue(5)) if not reader.IsDBNull(5) else 255

                folders[folder_id] = FolderData(
                    folder_id=folder_id,
                    parent_id=parent_id,
                    display_name=display_name,
                    entry_id=entry_id,
                    folder_class=folder_class,
                    well_known_name=well_known
                )

            reader.Close()
            conn.Close()
            logger.debug(f"Read {len(folders)} folders from {self.sdf_path}")

        except Exception as e:
            logger.error(f"Error reading folders from {self.sdf_path}: {e}")

        return folders


class MailboxInfoReader:
    """Read mailbox information from mailbox_2.xml"""

    @staticmethod
    def read_mailbox_info(mailbox_file: Path) -> Tuple[str, str]:
        """Extract mailbox name and email from mailbox_2.xml"""
        if not mailbox_file.exists():
            return mailbox_file.parent.name, "unknown@unknown.com"

        try:
            tree = ET.parse(mailbox_file)
            root = tree.getroot()

            ns = {'c2': 'http://www.codetwo.com'}

            display_name = "Unknown"
            email = "unknown@unknown.com"

            # Try with namespace prefix first
            info_node = root.find('c2:Info', ns)
            if info_node is None:
                info_node = root.find('{http://www.codetwo.com}Info')

            if info_node is not None:
                name_node = info_node.find('c2:DisplayName', ns)
                if name_node is None:
                    name_node = info_node.find('{http://www.codetwo.com}DisplayName')
                if name_node is not None and name_node.text:
                    display_name = name_node.text

                email_node = info_node.find('c2:EmailAddress', ns)
                if email_node is None:
                    email_node = info_node.find('{http://www.codetwo.com}EmailAddress')
                if email_node is not None and email_node.text:
                    email = email_node.text
            else:
                # Iterate through all elements
                for elem in root.iter():
                    tag_name = elem.tag.split('}')[-1] if '}' in elem.tag else elem.tag
                    if tag_name == 'DisplayName' and elem.text:
                        display_name = elem.text
                    elif tag_name == 'EmailAddress' and elem.text:
                        email = elem.text

            return display_name, email

        except Exception:
            return mailbox_file.parent.name, "unknown@unknown.com"


def find_sdf_database(mailbox_folder: Path) -> Optional[Path]:
    """Find mailbox.sdf in the mailbox folder structure"""
    # Check directly in folder
    sdf_file = mailbox_folder / "mailbox.sdf"
    if sdf_file.exists():
        return sdf_file

    # Check in parent storage folder (GUID folder)
    for sdf in mailbox_folder.rglob("mailbox.sdf"):
        return sdf

    return None


def find_storage_id(mailbox_folder: Path) -> Optional[str]:
    """Find the storage GUID folder in the mailbox structure"""
    for item in mailbox_folder.iterdir():
        if item.is_dir():
            # Check if it looks like a GUID
            name = item.name
            if len(name) == 36 and name.count('-') == 4:
                return name
    return None

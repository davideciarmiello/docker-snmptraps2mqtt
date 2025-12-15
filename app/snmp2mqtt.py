#System
import asyncio
import json
import logging
import os
import signal
import sys

from datetime import datetime
from pathlib import Path

# https://github-mirror.rsyslog.com/rsyslog/rsyslog/src/commit/20a09456c5c175073b7ae8302a54b70c7f6917b0/tests/snmptrapreceiverv2.py

#SNMP
from pysnmp.entity import engine, config
from pysnmp.carrier.asyncio.dgram import udp
from pysnmp.entity.rfc3413 import ntfrcv
from pysnmp.proto.rfc1902 import OctetString, ObjectName

from pysnmp.smi import builder, view, compiler, rfc1902
from pysnmp.smi.rfc1902 import ObjectType, ObjectIdentity
from pyasn1.type.univ import OctetString

import pysmi
from pysmi import debug as pysmi_debug

#MQTT
import paho.mqtt.client as mqtt

logging.basicConfig(level=logging.DEBUG)

# Config from ENV
MQTT_BROKER = os.getenv("MQTT_BROKER", "broker")
MQTT_PORT = int(os.getenv("MQTT_PORT", 1883))
MQTT_TOPIC = os.getenv("MQTT_TOPIC", "snmp/traps")
MQTT_USER = os.getenv("MQTT_USER")
MQTT_PASSWORD = os.getenv("MQTT_PASSWORD")
SNMP_PORT = int(os.getenv("SNMP_PORT", 162))
SNMP_MIBS_PATH = os.getenv("SNMP_MIBS_PATH", "/data/snmp_mibs")
SNMP_MIBS_TO_LOAD = os.getenv("SNMP_MIBS_TO_LOAD", "")

# MQTT client
mqtt_client = mqtt.Client(callback_api_version=mqtt.CallbackAPIVersion.VERSION2)
if MQTT_USER and MQTT_PASSWORD:
    mqtt_client.username_pw_set(MQTT_USER, MQTT_PASSWORD)
message_queue = []
def on_connect(client, userdata, flags, reason_code, properties):
    logging.info(f"MQTT Connected to {MQTT_BROKER}:{MQTT_PORT}. Reason code: {reason_code}")    
    # Invia eventuali messaggi in coda
    while message_queue:
        topic, payload = message_queue.pop(0)
        logging.info("Invio messaggio in coda: %s -> %s", topic, payload)
        client.publish(topic, payload)
def on_disconnect(client, userdata, flags, reason_code, properties):
    logging.info(f"MQTT Disconnected. Reason code: {reason_code}")
    
mqtt_client.on_connect = on_connect
mqtt_client.on_disconnect = on_disconnect
mqtt_client.connect(MQTT_BROKER, MQTT_PORT, 60)
mqtt_client.loop_start()

# Funzione per inviare messaggi MQTT in sicurezza
def send_mqtt_message(topic, payload):
    if mqtt_client.is_connected():
        mqtt_client.publish(topic, payload)
    else:
        logging.info("Client non connesso, metto in coda: %s -> %s", topic, payload)
        message_queue.append((topic, payload))



# -----------------------
# Configurazione SNMP
# -----------------------

# Assemble MIB viewer
mibBuilder = builder.MibBuilder()
paths = ['/usr/share/snmp/mibs', SNMP_MIBS_PATH]
paths = [p for p in paths if p and os.path.isdir(p)]
    
# Aggiungi le directory come MIB sources
mibBuilder.add_mib_sources(*[builder.DirMibSource(str(Path(p))) for p in paths])
mibBuilder.add_mib_sources(
    builder.DirMibSource('/data/compiled_mibs')
)

# Aggiunge il compiler con più percorsi
compiler.add_mib_compiler(mibBuilder, 
    sources=[f'file://{Path(p).resolve()}' for p in paths], # + ['http://mibs.snmplabs.com/asn1/@mib@'],
    destination='/data/compiled_mibs')
    
#mibBuilder.loadModules('RFC1213-MIB')
#logging.info(f"Loaded MIB: RFC1213-MIB")
#
#mibBuilder.loadModules('SNMPv2-MIB')
#logging.info(f"Loaded MIB: SNMPv2-MIB")

def load_modules(modules):
    for module in modules:
        try:
            mibBuilder.load_modules(module)
            logging.info(f"Loaded MIB: {module}")
        except Exception as e:
            logging.info(f"Failed loading {module}: {e}")
            pysmi_debug.set_logger(pysmi_debug.Debug('compiler'))
            mibBuilder.load_modules(module)
            pysmi_debug.set_logger(pysmi_debug.Debug())
            logging.info(f"")  
            
def compile_folder(path):
    if os.path.isdir(path):
        logging.info(f"Compile mib folder exists: Loading all mibs in {path}")
        modules = [
            os.path.splitext(f)[0]
            for f in os.listdir(path)
            if os.path.isfile(os.path.join(path, f))
        ]
        load_modules(modules)
    else:
        logging.info(f"Compile mib folder not exists: {path}")
        

pysmi_debug.set_logger(pysmi_debug.Debug())
modules_to_load = [m.strip() for m in SNMP_MIBS_TO_LOAD.split(",") if m.strip()]
load_modules(modules_to_load)

# Pre-load MIB modules we expect to work with
compile_folder(SNMP_MIBS_PATH)
# Split e trim di ciascun modulo

#mibBuilder.loadModules('ZYXEL-ES-ZyxelAPMgmt')
#logging.info(f"Loaded MIB: zyxel")

#mibBuilder.add_mib_sources(builder.DirMibSource('/data/snmp_mibs_default'))
#if not SNMP_MIBS_PATH:
#    mibBuilder.add_mib_sources(builder.DirMibSource('/percorso/ai/mibs'))
#compiler.add_mib_compiler(mibBuilder)
mibViewController = view.MibViewController(mibBuilder)
snmpEngine = engine.SnmpEngine()


def cbFun(snmp_engine, state_reference, context_engine_id,
          context_name, var_binds, cb_ctx):
    logging.info("Received TRAP:")
    transportAddress = (None, None)
    try:
        transportDomain, transportAddress = snmpEngine.message_dispatcher.get_transport_info(state_reference)        
    except Exception as e:
        logging.info(f"Error : {e}")
        pass
        
    ha_data = {
        "source": transportAddress[0] if isinstance(transportAddress, tuple) else str(transportAddress)
    }
    decoded = []
    for oid, val in var_binds:
        oid_str = ".".join(str(x) for x in oid)
        
            
            
        try:
            # Convert types into printable forms
            val_str = val.prettyPrint()
            if isinstance(val, OctetString):
                text = val.asOctets().decode('utf-8')
        except UnicodeDecodeError as e:
            val_octet = val.asOctets()
            if len(val_octet) == 6:
                val_str = ':'.join(f'{b:02X}' for b in val_octet)
            else:
                val_str = val_octet.hex()
        except Exception:
            val_str = repr(val)
        logging.debug(f"VarBind : oid: {oid} - val: {val_str} ")        
        
            
        pretty_name = None

        try:
            #obj = ObjectIdentity(oid_str)
            obj = ObjectIdentity(oid)
            obj.resolve_with_mib(mibViewController)
            pretty_name = obj.prettyPrint()
        except Exception as e:
            logging.info(f"Error : {e}")
            pass
        name_or_id = pretty_name if pretty_name else oid_str
        
        # Detect the trap OID (snmpTrapOID.0)
        if oid_str == "1.3.6.1.6.3.1.1.4.1.0":     
            try:
                obj = ObjectIdentity(val_str)
                obj.resolve_with_mib(mibViewController)
                ha_data["trap_name"] = obj.prettyPrint()
            except Exception as e:
                logging.info(f"Error : {e}")
                pass
            ha_data["trap_oid"] = val_str         
            continue
        elif not name_or_id in ha_data and pretty_name:
            ha_data[name_or_id] = val_str

        decoded.append({
            "oid": oid_str,
            "value": val_str,
            "name": pretty_name
        })

    ha_data["varbinds"] = decoded
    payload = json.dumps(ha_data)  # converte dict in stringa JSON
    logging.debug(f"{payload}")
    send_mqtt_message(MQTT_TOPIC, payload)

# v2c/communities
community = 'public'
config.add_v1_system(snmpEngine, 'my-area', community.decode() if isinstance(community, bytes) else community)
# UDP transport
config.add_transport(
    snmpEngine,
    udp.DOMAIN_NAME,
    udp.UdpTransport().open_server_mode(("0.0.0.0", SNMP_PORT))
)

ntfrcv.NotificationReceiver(snmpEngine, cbFun)    

logging.info(f"SNMP trap listener in ascolto su UDP {SNMP_PORT}")


def shutdown(signum, frame):
    if signum:
        logging.info("Shutting down receiver (signal %s)", signum)
    try:
        snmpEngine.close_dispatcher()
    except Exception:
        pass
    try:
        mqtt_client.disconnect()
        mqtt_client.loop_stop()  # ferma il loop se in background
    except Exception as e:
        logging.exception("Error disconnecting MQTT: %s", e)
    sys.exit(0)

signal.signal(signal.SIGTERM, shutdown)
signal.signal(signal.SIGINT, shutdown)

try:
    snmpEngine.transport_dispatcher.job_started(1)
    snmpEngine.open_dispatcher()
except KeyboardInterrupt:
    logging.info("Shutting down receiver")
except Exception as e:
    logging.exception("Receiver error: %s", e)
finally:
    shutdown(0, 0)

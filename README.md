# docker-snmptraps2mqtt
Listen device information via SNMP Traps and publish them in a MQTT topic as json formatted string.

You can listen snmp traps and send to mqtt, usefull for home assistant. 

```yaml
services:
  snmptraps2mqtt:
    image: davideciarmi/snmptraps2mqtt:latest
    environment:
      - MQTT_BROKER=${MQTT_BROKER}
      - MQTT_PORT=${MQTT_PORT}
      - MQTT_USER=${MQTT_USER}
      - MQTT_PASSWORD=${MQTT_PASSWORD}
      - MQTT_TOPIC=snmp/traps
      - SNMP_PORT=162
      - SNMP_MIBS_TO_LOAD=INET-ADDRESS-MIB,NET-SNMP-MIB,RFC1213-MIB
    ports:
      - "162:162/udp"
    volumes:
      - ./mibs:/data/snmp_mibs
    restart: unless-stopped
    

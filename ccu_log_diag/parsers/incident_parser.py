from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

from ccu_log_diag.model.events import (
    Domain,
    Event,
    EventType,
    ParseQuality,
    SourceLocation,
)


SHORT_TS = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})/(?P<day>\d{1,2})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2})\s+UTC\s+--"
)
LONG_TS = re.compile(
    r"^\[(?P<month>[A-Z][a-z]+)/(?P<day>\d{1,2})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+UTC\]"
)
FULL_TS = re.compile(
    r"^(?P<date>\d{4}-\d{2}-\d{2})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+(?P<offset>[+-]\d{4})"
)
NAIVE_ISO_TS = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2}T"
    r"\d{2}:\d{2}:\d{2}(?:\.\d+)?)"
)
NAIVE_SPACE_TS = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2}\s+"
    r"\d{2}:\d{2}:\d{2}(?:\.\d+)?)"
)
SYSLOG_TS = re.compile(
    r"^(?:<\d+>\s*)?(?P<month>[A-Z][a-z]{2})\s+"
    r"(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})"
)
BRACKET_ISO_TS = re.compile(
    r"^\[(?P<timestamp>\d{4}-\d{2}-\d{2}T"
    r"\d{2}:\d{2}:\d{2}(?:\.\d+)?Z)\s+UTC\]"
)
BRACKET_DATE_TS = re.compile(
    r"^\[(?P<date>\d{4}-\d{2}-\d{2})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2}(?:\.\d+)?)\]"
)


PATTERNS: tuple[tuple[re.Pattern[str], EventType, str, dict[str, str]], ...] = (
    (
        re.compile(
            r"Special_Version_Check_DSP old:(?P<old_version>[0-9A-F.]+)\s+"
            r"new:(?P<new_version>[0-9A-F.]+)",
            re.I,
        ),
        EventType.MODULE_STATE,
        "SDSP firmware update version transition",
        {"category": "firmware_update", "module": "SDSP1"},
    ),
    (
        re.compile(r"Updater\s+-->\s+Update All Success", re.I),
        EventType.MODULE_STATE,
        "Firmware update completed successfully",
        {"category": "firmware_update", "status": "success"},
    ),
    (
        re.compile(r"PM(?P<module>\d+)->(?P<fault>Err_[A-Za-z0-9_]+)", re.I),
        EventType.ERROR_CODE,
        "Power-module fault reported",
        {"category": "power_module_fault"},
    ),
    (
        re.compile(r"LLCFault,\s*MdAddr:(?P<module_address>\d+)", re.I),
        EventType.ALARM,
        "Power-module LLC fault received",
        {"category": "power_module_fault", "state": "fault"},
    ),
    (
        re.compile(
            r"MdAddr:0x(?P<module_address>[0-9A-Fa-f]+),"
            r"MdState is Fault!(?! Recover)",
            re.I,
        ),
        EventType.MODULE_STATE,
        "Power module entered fault state",
        {"category": "power_module_fault", "state": "fault"},
    ),
    (
        re.compile(
            r"MdGrpState is Fault!(?! Recover)",
            re.I,
        ),
        EventType.MODULE_STATE,
        "Power-module group entered fault state",
        {"category": "power_module_group", "state": "fault"},
    ),
    (
        re.compile(
            r"OutputPWR\(0\.1kw\) switch to (?P<to_raw>\d+) "
            r"from (?P<from_raw>\d+)",
            re.I,
        ),
        EventType.POWER_REQUEST,
        "Power-cabinet output allocation changed",
        {"measurement": "cabinet_output_allocation", "power_scale": "0.1"},
    ),
    (
        re.compile(r"Get ValidMdNum:(?P<valid_module_count>\d+)", re.I),
        EventType.MODULE_STATE,
        "Power cabinet valid-module count changed",
        {"category": "power_module_availability"},
    ),
    (
        re.compile(r"State E non forcefully set recover", re.I),
        EventType.ERROR_CODE_CLEARED,
        "Non-forced CP State E recovered",
        {"code": "C36", "cp_state": "E", "active": "false"},
    ),
    (
        re.compile(r"State_EF_Switch_To_State_A", re.I),
        EventType.CP_STATE_CHANGE,
        "CP state recovered from E/F to A",
        {"transition": "EF_to_A", "cp_state": "A", "active": "false"},
    ),
    (
        re.compile(r"State_A_Switch_To_State_E", re.I),
        EventType.CP_STATE_CHANGE,
        "CP state changed from A to E",
        {"transition": "A_to_E", "cp_state": "E", "active": "true"},
    ),
    (
        re.compile(r"current alarm error id:\s*80\b", re.I),
        EventType.ALARM,
        "CCU alarm 80 confirmed CP State E",
        {"code": "C36", "internal_alarm_id": "80", "cp_state": "E"},
    ),
    (
        re.compile(r"State E non forcefully set(?! recover)", re.I),
        EventType.CONNECTOR_STATUS,
        "CP State E set by non-forced detection",
        {
            "code": "C36",
            "cp_state": "E",
            "active": "true",
            "forced": "false",
        },
    ),
    (
        re.compile(
            r"Gun1AlarmReserveBitmap:(?P<alarm_bitmap>[0-9A-Fa-f]{4})",
            re.I,
        ),
        EventType.ALARM,
        "Connector 1 alarm bitmap updated",
        {"connector": "1"},
    ),
    (
        re.compile(
            r"Update connector\s+(?P<connector>\d+)\s+maintenance code list\s+"
            r'["\'](?P<codes>C\d+(?:,C\d+)*)["\']',
            re.I,
        ),
        EventType.ERROR_CODE,
        "Connector maintenance C-code list updated",
        {"category": "connector_alarm_vector"},
    ),
    (
        re.compile(
            r"R37 raw md\[0\]:\s*Hz=(?P<frequency_raw>-?[0-9.]+),\s*"
            r"VA=(?P<va_raw>-?[0-9.]+),VB=(?P<vb_raw>-?[0-9.]+),"
            r"VC=(?P<vc_raw>-?[0-9.]+)",
            re.I,
        ),
        EventType.POWER_FEEDBACK,
        "Power-cabinet AC input sample",
        {"measurement": "r37_ac_input", "voltage_scale": "0.1"},
    ),
    (
        re.compile(
            r"P_CharReq:(?!.*EV_Target_V).*"
            r"RES{2,3}OC=(?P<soc>\d+).*"
            r"V_Target_C=0\(-1\)A",
            re.I,
        ),
        EventType.POWER_REQUEST,
        "Initial PreCharge request had no valid target voltage",
        {
            "measurement": "EVTargetVoltage",
            "target_voltage_V": "0",
            "category": "initial_precharge_zero_voltage",
        },
    ),
    (
        re.compile(
            r"Precharge_Wait_For_Higher_Voltage_ev_Target:"
            r"(?P<target_voltage_V>-?[0-9.]+)",
            re.I,
        ),
        EventType.ISO15118_STATE,
        "PreCharge voltage wait used EV target",
        {"state": "precharge_wait_for_higher_voltage"},
    ),
    (
        re.compile(
            r"(?!.*P_CharReq:.*RES{2,3}OC=).*"
            r"EV_Target_V=(?P<voltage_mantissa>-?[0-9.]+)"
            r"\((?P<voltage_exponent>-?\d+)\)V",
            re.I,
        ),
        EventType.POWER_REQUEST,
        "EV PreCharge target voltage",
        {"measurement": "EVTargetVoltage", "stage": "precharge"},
    ),
    (
        re.compile(r"\bSes_StopReq\b", re.I),
        EventType.NORMAL_STOP,
        "EV requested session stop",
        {"initiator": "vehicle", "stage": "precharge"},
    ),
    (
        re.compile(
            r"action:ClearChargingProfile.*"
            r'["\']id["\']\s*:\s*(?P<profile_id>\d+).*'
            r'["\']connectorId["\']\s*:\s*(?P<connector>\d+)',
            re.I,
        ),
        EventType.POWER_REQUEST,
        "Platform requested charging-profile removal",
        {"action": "ClearChargingProfile"},
    ),
    (
        re.compile(
            r"ClearChargingProfileResponse=.*"
            r'["\']status["\']\s*:\s*["\']Accepted["\']',
            re.I,
        ),
        EventType.AUTHORIZATION,
        "Charging-profile removal accepted",
        {"action": "ClearChargingProfile", "status": "Accepted"},
    ),
    (
        re.compile(
            r"period:\s*(?P<period_s>\d+)\s*\.\s*"
            r'Limit:\s*(?P<power_W>\d+)\s*["\']W["\']',
            re.I,
        ),
        EventType.POWER_REQUEST,
        "Smart-charging power limit applied",
        {"controller": "smart_charging", "measurement": "power_limit"},
    ),
    (
        re.compile(
            r"EVSE_Max_C_Limit=(?P<mantissa>-?[0-9.]+)"
            r"\((?P<exponent>-?\d+)\)A.*"
            r"EVSE_Max_P_Limit=(?P<power_mantissa>-?[0-9.]+)"
            r"\((?P<power_exponent>-?\d+)\)W",
            re.I,
        ),
        EventType.EV_CURRENT_LIMIT,
        "CCU advertised EVSE current and power limits",
        {"measurement": "EVSEMaximumLimit"},
    ),
    (
        re.compile(r"Alarm:\s*Output current over EV request current", re.I),
        EventType.ALARM,
        "Output current remained above EV-request current",
        {"protection": "output_current_over_ev_request"},
    ),
    (
        re.compile(
            r'(?=.*["\']connectorId["\']\s*:\s*(?P<connector>\d+))'
            r'(?=.*["\']errorCode["\']\s*:\s*["\']OverCurrentFailure["\'])'
            r'(?=.*["\']vendorErrorCode["\']\s*:\s*["\']S25["\'])',
            re.I,
        ),
        EventType.ERROR_CODE,
        "Current-tracking fault reported as S25",
        {"code": "S25", "vendor": "Sungrow", "active": "true"},
    ),
    (
        re.compile(
            r"currentoutput\s*:(?P<connector>\d+)\s+"
            r"(?P<current_raw>-?[0-9.]+)",
            re.I,
        ),
        EventType.POWER_FEEDBACK,
        "Power cabinet output-current sample",
        {
            "device": "power_cabinet",
            "measurement": "output_current",
            "current_scale": "0.1",
        },
    ),
    (
        re.compile(
            r"Voltoutput\s*:(?P<connector>\d+)\s+"
            r"(?P<voltage_raw>-?[0-9.]+)",
            re.I,
        ),
        EventType.POWER_FEEDBACK,
        "Power cabinet output-voltage sample",
        {
            "device": "power_cabinet",
            "measurement": "output_voltage",
            "voltage_scale": "0.1",
        },
    ),
    (
        re.compile(
            r"The gun(?P<gun>\d+) out power:\s*(?P<power_W>\d+)",
            re.I,
        ),
        EventType.POWER_REQUEST,
        "EMS300CP allocated gun output power",
        {"controller": "EMS300CP", "measurement": "ems_power_limit"},
    ),
    (
        re.compile(
            r"C_DemandReq:.*RES{2,3}OC=(?P<soc>\d+).*Ready=(?P<ready>\d+)"
            r".*E_Code=(?P<ev_error>\d+)",
            re.I,
        ),
        EventType.ISO15118_STATE,
        "EV CurrentDemand state of charge",
        {"message": "C_DemandReq"},
    ),
    (
        re.compile(r"Cable check timer finish,\s*proceedin[g]?", re.I),
        EventType.CABLECHECK_FINISHED,
        "CableCheck completed and state machine proceeded",
        {"result": "completed"},
    ),
    (
        re.compile(r"Short circuit check pass,\s*drop voltage to 0", re.I),
        EventType.POWER_REQUEST,
        "Charger commanded voltage drop after CableCheck",
        {"action": "drop_voltage", "target_voltage_V": "0"},
    ),
    (
        re.compile(
            r"Error item:\s*Dc output voltage and EV request voltage difference "
            r"- trigger,\s*value:\s*(?P<difference_V>[0-9.]+)",
            re.I,
        ),
        EventType.ALARM,
        "Output voltage exceeded EV-request voltage allowance",
        {"protection": "output_over_ev_request_voltage"},
    ),
    (
        re.compile(
            r"CCU(?P<connector>\d+)\s+Stop Reason:"
            r"(?P<reason>Precharge_Fault)",
            re.I,
        ),
        EventType.SESSION_STOP,
        "CCU reported Precharge_Fault stop reason",
        {"stage": "precharge"},
    ),
    (
        re.compile(
            r"CCU(?P<connector>\d+)\s+Stop Reason:"
            r"(?P<reason>Current_Demand_Fault)",
            re.I,
        ),
        EventType.SESSION_STOP,
        "CCU reported Current_Demand_Fault stop reason",
        {"stage": "current_demand"},
    ),
    (
        re.compile(r"CurrentDemand_Fault_Trig+er", re.I),
        EventType.PROTOCOL_ERROR,
        "CurrentDemand fault triggered",
        {"stage": "current_demand", "reason": "Current_Demand_Fault"},
    ),
    (
        re.compile(
            r"EVTargetVoltage=(?P<voltage_mantissa>-?[0-9.]+)"
            r"\((?P<voltage_exponent>-?\d+)\)V",
            re.I,
        ),
        EventType.POWER_REQUEST,
        "EV target voltage",
        {"measurement": "EVTargetVoltage"},
    ),
    (
        re.compile(
            r"EVMaximumVoltageLimit=(?P<voltage_mantissa>-?[0-9.]+)"
            r"\((?P<voltage_exponent>-?\d+)\)V",
            re.I,
        ),
        EventType.POWER_REQUEST,
        "EV maximum voltage limit",
        {"measurement": "EVMaximumVoltageLimit"},
    ),
    (
        re.compile(
            r'(?=.*StartTransaction=\{)'
            r'(?=.*["\']connectorId["\']\s*:\s*(?P<connector>\d+))'
            r'(?=.*["\']idTag["\']\s*:\s*["\'](?P<id_tag>[^"\']+)["\'])'
            r'(?=.*["\']meterStart["\']\s*:\s*(?P<meter_start>\d+))',
            re.I,
        ),
        EventType.SESSION_START,
        "OCPP StartTransaction requested",
        {"endpoint": "customer_ocpp"},
    ),
    (
        re.compile(
            r'(?=.*StartTransactionResponse=\{)'
            r'(?=.*["\']status["\']\s*:\s*["\'](?P<auth_status>Invalid)["\'])'
            r'(?=.*["\']transactionId["\']\s*:\s*(?P<transaction_id>\d+))'
            r'(?=.*["\']connectorId["\']\s*:\s*(?P<connector>\d+))',
            re.I,
        ),
        EventType.AUTHORIZATION,
        "Customer backend rejected StartTransaction idTag",
        {"endpoint": "customer_ocpp", "action": "StartTransaction"},
    ),
    (
        re.compile(
            r'(?=.*StopTransaction=\{)'
            r'(?=.*["\']connectorId["\']\s*:\s*(?P<connector>\d+))'
            r'(?=.*["\']idTag["\']\s*:\s*["\'](?P<id_tag>[^"\']+)["\'])'
            r'(?=.*["\']meterStop["\']\s*:\s*(?P<meter_stop>\d+))'
            r'(?=.*["\']reason["\']\s*:\s*["\'](?P<reason>DeAuthorized)["\'])',
            re.I,
        ),
        EventType.SESSION_STOP,
        "OCPP transaction stopped after deauthorization",
        {"endpoint": "customer_ocpp"},
    ),
    (
        re.compile(
            r'(?=.*StopTransaction=\{)'
            r'(?=.*["\']connectorId["\']\s*:\s*(?P<connector>\d+))'
            r'(?=.*["\']meterStop["\']\s*:\s*(?P<meter_stop>\d+))'
            r'(?=.*["\']reason["\']\s*:\s*["\'](?P<reason>[^"\']+)["\'])'
            r'(?=.*["\']transactionId["\']\s*:\s*(?P<transaction_id>\d+))',
            re.I,
        ),
        EventType.SESSION_STOP,
        "OCPP StopTransaction requested",
        {"endpoint": "customer_ocpp"},
    ),
    (
        re.compile(
            r'ocppin_Mainten received.*["\']idTagInfo["\'].*'
            r'["\']status["\']\s*:\s*["\']Accepted["\'].*'
            r'["\']transactionId["\']\s*:\s*(?P<transaction_id>\d+)',
            re.I,
        ),
        EventType.AUTHORIZATION,
        "Maintenance backend accepted StartTransaction",
        {
            "endpoint": "maintenance",
            "action": "StartTransaction",
            "auth_status": "Accepted",
        },
    ),
    (
        re.compile(
            r'Update eth link status from ["\'](?P<interface>eth\d+)["\'] '
            r"to (?P<link_state>true|false)",
            re.I,
        ),
        EventType.NETWORK_STATE,
        "Internal Ethernet link status changed",
        {"scope": "internal_device_network"},
    ),
    (
        re.compile(
            r'DC Meter IP ["\'](?P<ip>\d{1,3}(?:\.\d{1,3}){3})["\'] '
            r"Set time completed",
            re.I,
        ),
        EventType.NETWORK_STATE,
        "DC meter responded to time synchronization",
        {"state": "reachable", "device": "dc_meter"},
    ),
    (
        re.compile(
            r"Meter comm type:\s*(?P<operation>\d+)\s+Network reply error code:.*"
            r"\((?P<network_error>TimeoutError)\)",
            re.I,
        ),
        EventType.CONNECTIVITY_LOST,
        "DC meter HTTP operation timed out",
        {
            "endpoint": "dc_meter_http",
            "device": "dc_meter",
            "layer": "application",
            "state": "timeout",
        },
    ),
    (
        re.compile(
            r'CCU error raw .*["\']CCUIndex["\']\s*:\s*(?P<connector>\d+).*'
            r'["\']LEM_Error["\']\s*:\s*\[(?P<lem_errors_blob>[^]]*'
            r'["\']Description["\'][^]]*)\]\s*,\s*'
            r'["\']METER_Error["\']',
            re.I,
        ),
        EventType.ERROR_CODE,
        "Connector reported LEM fault vector",
        {"category": "lem_fault_vector"},
    ),
    (
        re.compile(
            r'Update connector\s+(?P<connector>\d+)\s+code list\s+'
            r'["\'](?P<codes>(?:L\d+,?)+)["\']',
            re.I,
        ),
        EventType.ERROR_CODE,
        "Connector LEM error-code list updated",
        {"category": "lem_fault_vector"},
    ),
    (
        re.compile(
            r"Update connector\s+(?P<connector>\d+)\s+code list,\s*clean",
            re.I,
        ),
        EventType.ERROR_CODE_CLEARED,
        "Connector LEM error-code list cleared",
        {"category": "lem_meter_offline", "code": "L20", "state": "cleared"},
    ),
    (
        re.compile(
            r"CCU index:\s*(?P<connector>\d+)\s*:\s*"
            r"DC meter fatal error recover",
            re.I,
        ),
        EventType.ERROR_CODE_CLEARED,
        "DC meter fatal communication error recovered",
        {"category": "lem_meter_offline", "code": "L20", "state": "recovered"},
    ),
    (
        re.compile(
            r"Change connector:\s*(?P<connector>\d+)\s+status to fault",
            re.I,
        ),
        EventType.CONNECTOR_STATUS,
        "Connector entered fault status",
        {"status": "Faulted"},
    ),
    (
        re.compile(
            r"lem Dc Meter Energency Stop Trig .*index\s+(?P<connector>\d+)",
            re.I,
        ),
        EventType.ALARM,
        "DC meter communication fault triggered connector protection",
        {"device": "dc_meter", "action": "protective_stop"},
    ),
    (
        re.compile(
            r"CCU(?P<connector>\d+)->(?P<fault>Err_(?:LEM|Connector)_[A-Za-z0-9_]+)",
            re.I,
        ),
        EventType.ERROR_CODE,
        "Connector fault-state entry recorded",
        {"category": "connector_fault_state"},
    ),
    (
        re.compile(
            r"P_CharReq:.*RES{2,3}OC=(?P<soc>\d+).*Ready=(?P<ready>\d+).*E_Code=(?P<ev_error>\d+)",
            re.I,
        ),
        EventType.ISO15118_STATE,
        "EV PowerDelivery/charge request received",
        {"message": "P_CharReq"},
    ),
    (
        re.compile(r"EV_InvalidTargetVoltage_Stop_Charging.*Lower than ValidLimit Minimum", re.I),
        EventType.PROTOCOL_ERROR,
        "EV target voltage below charger minimum",
        {"reason": "invalid_target_voltage_below_minimum", "origin": "ev_request"},
    ),
    (
        re.compile(r"PreCharge_Fault_Trig+er", re.I),
        EventType.PROTOCOL_ERROR,
        "PreCharge fault triggered",
        {"stage": "precharge"},
    ),
    (
        re.compile(r"EvseEmergencyStop.*EVSE_Em_stop drop voltage", re.I),
        EventType.EMERGENCY_STOP,
        "EVSE safety stop and voltage drop",
        {"origin": "evse_protection", "action": "drop_voltage"},
    ),
    (
        re.compile(r"EVTargetCurrent=(?P<mantissa>-?[0-9.]+)\((?P<exponent>-?\d+)\)A", re.I),
        EventType.CURRENT_DEMAND,
        "EV target current",
        {"measurement": "EVTargetCurrent"},
    ),
    (
        re.compile(
            r"EV_Target_C=(?P<mantissa>-?[0-9.]+)"
            r"\((?P<exponent>-?\d+)\)[Am]?",
            re.I,
        ),
        EventType.CURRENT_DEMAND,
        "EV target current",
        {"measurement": "EVTargetCurrent"},
    ),
    (
        re.compile(
            r"Connector_Power_Info_Changed!\s*V:(?P<voltage>[0-9.]+),\s*C:(?P<current_raw>[0-9.]+)",
            re.I,
        ),
        EventType.POWER_FEEDBACK,
        "Connector power feedback changed",
        {"current_scale": "0.1"},
    ),
    (
        re.compile(r"EVMaximumCurrentLimit=(?P<mantissa>-?[0-9.]+)\((?P<exponent>-?\d+)\)A", re.I),
        EventType.EV_CURRENT_LIMIT,
        "EV maximum current limit",
        {"measurement": "EVMaximumCurrentLimit"},
    ),
    (
        re.compile(r"State_CD_Switch_To_State_B", re.I),
        EventType.CP_STATE_CHANGE,
        "CP changed from charging state C/D to B",
        {"transition": "C/D_to_B"},
    ),
    (
        re.compile(r"C_To_B_Charging_Detected", re.I),
        EventType.CP_STATE_CHANGE,
        "Vehicle changed CP state from C to B",
        {"transition": "C_to_B", "initiator": "vehicle"},
    ),
    (
        re.compile(r"EV_Normal_Stop_Trigger", re.I),
        EventType.NORMAL_STOP,
        "Vehicle stop trigger detected",
        {"initiator": "vehicle"},
    ),
    (
        re.compile(r"C_To_B_Charging_Emergency_Stop|EvEmergencyStop|EV_E_Stop", re.I),
        EventType.EMERGENCY_STOP,
        "Vehicle-side emergency stop",
        {"stop_reason": "EV_E_Stop"},
    ),
    (
        re.compile(r"vendorErrorCode[\"']?\s*[:=]\s*[\"']?S3\b", re.I),
        EventType.ERROR_CODE,
        "OCPP vendor error code S3",
        {"code": "S3", "vendor": "Sungrow"},
    ),
    (
        re.compile(r"Update connector\s+(?P<connector>\d+)\s+(?:maintenance\s+)?code list\s+[\"']S3[\"']", re.I),
        EventType.ERROR_CODE,
        "CCU mapped stop reason to S3",
        {"code": "S3", "vendor": "Sungrow"},
    ),
    (
        re.compile(
            r'(?=.*["\']connectorId["\']\s*:\s*(?P<connector>\d+))'
            r'(?=.*["\']errorCode["\']\s*:\s*["\'](?P<ocpp_error>[^"\']*)["\'])'
            r'(?=.*["\']status["\']\s*:\s*["\'](?P<status>[^"\']+)["\'])'
            r'(?=.*["\']vendorErrorCode["\']\s*:\s*["\'][^"\']*\bS20\b)',
            re.I,
        ),
        EventType.ERROR_CODE,
        "Connector reported OCPP vendor error S20",
        {"code": "S20", "vendor": "Sungrow", "active": "true"},
    ),
    (
        re.compile(
            r'CCU error raw .*["\']CCUIndex["\']\s*:\s*(?P<connector>\d+).*'
            r'["\']Stop_Error["\']\s*:\s*\[\{["\']Description["\']\s*:\s*["\']20["\']',
            re.I,
        ),
        EventType.ERROR_CODE,
        "CCU reported frame communication timeout S20",
        {"code": "S20", "vendor": "Sungrow", "active": "true"},
    ),
    (
        re.compile(
            r'CCU error raw .*["\']CCUIndex["\']\s*:\s*(?P<connector>\d+).*'
            r'["\']Stop_Error["\']\s*:\s*\[\s*\]',
            re.I,
        ),
        EventType.ERROR_CODE_CLEARED,
        "CCU stop-error list cleared",
        {"active": "false"},
    ),
    (
        re.compile(
            r'Warning exist connector:\s*(?P<connector>\d+)\s*,\s*code:\s*["\']S20["\']',
            re.I,
        ),
        EventType.ERROR_CODE,
        "S20 remained in connector warning state",
        {"code": "S20", "vendor": "Sungrow", "active": "true"},
    ),
    (
        re.compile(
            r'StateSwicthed:from\s+["\'](?P<from_state>[^"\']+)["\']\s+to:\s+'
            r'["\'](?P<to_state>[^"\']+)["\']',
            re.I,
        ),
        EventType.CONNECTOR_STATUS,
        "Connector state-machine transition",
        {},
    ),
    (
        re.compile(
            r'(?=.*["\']connectorId["\']\s*:\s*(?P<connector>\d+))'
            r'(?=.*["\']errorCode["\']\s*:\s*["\'](?P<ocpp_error>[^"\']*)["\'])'
            r'(?=.*["\']status["\']\s*:\s*["\'](?P<status>[^"\']+)["\'])'
            r'(?=.*["\']vendorErrorCode["\']\s*:\s*["\'](?P<vendor_error>[^"\']*)["\'])',
            re.I,
        ),
        EventType.CONNECTOR_STATUS,
        "OCPP connector status reported",
        {},
    ),
    (
        re.compile(r"StopTransaction=.*[\"']reason[\"']\s*:\s*[\"']Local[\"']", re.I),
        EventType.SESSION_STOP,
        "OCPP StopTransaction reason Local",
        {"reason": "Local"},
    ),
    (
        re.compile(
            r"(?:StopTransactionResponse|actionID[\"']?\s*:\s*[\"']StopTransaction[\"']).*"
            r"status[\"']?\s*:\s*[\"']Accepted[\"']",
            re.I,
        ),
        EventType.OCPP_STOP_ACCEPTED,
        "OCPP StopTransaction accepted",
        {"status": "Accepted"},
    ),
    (
        re.compile(r"connection lost(?:,\s*counting:\d+)?", re.I),
        EventType.CONNECTIVITY_LOST,
        "Network connection loss recorded",
        {},
    ),
    (
        re.compile(r"SSL socket creation failed", re.I),
        EventType.CONNECTIVITY_LOST,
        "OCPP SSL socket creation failed",
        {"layer": "tls"},
    ),
    (
        re.compile(r'Update maintenance back-end status:\s*["\']Maintenance_Network_Down["\']', re.I),
        EventType.CONNECTIVITY_LOST,
        "Maintenance backend marked disconnected",
        {"endpoint": "maintenance", "state": "down"},
    ),
    (
        re.compile(r'Update maintenance back-end status:\s*["\']Maintenance_Network_Good["\']', re.I),
        EventType.WEBSOCKET_CONNECTED,
        "Maintenance backend marked connected",
        {"endpoint": "maintenance", "state": "good"},
    ),
    (
        re.compile(r"OCPP_Connection_Restore maintenance", re.I),
        EventType.WEBSOCKET_CONNECTED,
        "Maintenance backend connection restored",
        {"endpoint": "maintenance", "state": "restored"},
    ),
    (
        re.compile(r"IPv4ConnectionStatus:\s*DISCONNECTED", re.I),
        EventType.NETWORK_STATE,
        "Cellular IPv4 data call disconnected",
        {"interface": "usb0", "state": "disconnected"},
    ),
    (
        re.compile(r"requestGetSIMStatus\s+SIMStatus:\s*SIM_READY", re.I),
        EventType.NETWORK_STATE,
        "Cellular SIM reported ready",
        {"device": "sim", "state": "sim_ready"},
    ),
    (
        re.compile(r"modem iccid:\s*[0-9A-F]+", re.I),
        EventType.NETWORK_STATE,
        "Router modem recognized customer SIM",
        {"device": "customer_router_sim", "state": "router_sim_detected"},
    ),
    (
        re.compile(
            r"mcc:(?P<mcc>\d+)\s+mnc:(?P<mnc>\d+).*?"
            r"band:(?P<band>\d+).*?"
            r"rsrp:(?P<rsrp>-?\d+)\s+rsrq:(?P<rsrq>-?\d+)\s+"
            r"sinr:(?P<sinr>-?\d+)\s+rssi:(?P<rssi>-?\d+)",
            re.I,
        ),
        EventType.NETWORK_STATE,
        "Customer router LTE registration and radio sample",
        {"device": "customer_router_modem", "state": "router_lte_registered"},
    ),
    (
        re.compile(
            r"DHCPACK\(lan0\)\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
            r"\s+(?P<mac>[0-9a-f:]{17})",
            re.I,
        ),
        EventType.NETWORK_STATE,
        "Customer router LAN DHCP lease acknowledged",
        {"device": "customer_router", "state": "router_lan_dhcp_ack"},
    ),
    (
        re.compile(r"Lease of\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+obtained", re.I),
        EventType.NETWORK_STATE,
        "Cellular DHCP lease obtained",
        {"interface": "usb0", "state": "lease_obtained"},
    ),
    (
        re.compile(r"\bstart\s+dlm_connect\b", re.I),
        EventType.NETWORK_MANAGER_START,
        "DLM/ALM network manager started",
        {"manager": "dlm_connect"},
    ),
    (
        re.compile(
            r"Detect the network status every \d+\s*s,"
            r"Recording connection lost",
            re.I,
        ),
        EventType.NETWORK_STATE,
        "Network monitor initialized with connection recorded down",
        {"state": "monitor_recorded_down"},
    ),
    (
        re.compile(r"Error:\s*Nexthop has invalid gateway", re.I),
        EventType.PROTOCOL_ERROR,
        "Customer router route addition used an invalid gateway",
        {"path": "customer_router", "state": "invalid_gateway"},
    ),
    (
        re.compile(r"mgntmode\s*:\s*Non-DLM/ALM", re.I),
        EventType.NETWORK_MANAGER_RELEASE,
        "DLM/ALM stopped managing the interface",
        {"manager": "dlm_connect", "mode": "Non-DLM/ALM"},
    ),
    (
        re.compile(r"connection mode\s*:\s*simMode", re.I),
        EventType.NETWORK_MODE_CHANGE,
        "SIM mode started network reconfiguration",
        {"manager": "simMode", "mode": "simMode"},
    ),
    (
        re.compile(r"router_connection_enable:\s*true", re.I),
        EventType.NETWORK_STATE,
        "Customer router connection enabled",
        {"path": "customer_router", "state": "enabled"},
    ),
    (
        re.compile(
            r"ping_detection_external_network:\s*(?P<ping_state>true|false)",
            re.I,
        ),
        EventType.NETWORK_STATE,
        "External network ping check completed",
        {"path": "customer_router"},
    ),
    (
        re.compile(
            r'["\']opBackendConnState["\']\s*:\s*(?P<backend_state>[01])',
            re.I,
        ),
        EventType.NETWORK_STATE,
        "Customer operation backend state reported",
        {"endpoint": "customer_ocpp", "category": "operation_backend_state"},
    ),
    (
        re.compile(
            r"Started PowerCabinetFogNodeApplication in "
            r"(?P<startup_seconds>[0-9.]+) seconds",
            re.I,
        ),
        EventType.MODULE_STATE,
        "PowerCabinetFogNode application started",
        {"category": "process_start", "state": "started"},
    ),
    (
        re.compile(
            r"\[(?P<channel>Operation|Maintenance)\]\s+"
            r"On connection open \(HTTP status:\s*(?P<http_status>101)\)",
            re.I,
        ),
        EventType.WEBSOCKET_CONNECTED,
        "FogNode backend WebSocket connected",
        {},
    ),
    (
        re.compile(
            r"\[(?P<channel>Operation|Maintenance)\]\s+Sending:\s*"
            r'\[2,["\'](?P<message_id>[^"\']+)["\'],'
            r'["\'](?P<action>BootNotification|Heartbeat)["\']',
            re.I,
        ),
        EventType.NETWORK_STATE,
        "OCPP backend request sent",
        {"state": "request_sent"},
    ),
    (
        re.compile(
            r"\[(?P<channel>Operation|Maintenance)\]\s+Received\s+"
            r'\[3,["\'](?P<message_id>[^"\']+)["\']',
            re.I,
        ),
        EventType.NETWORK_STATE,
        "OCPP backend response received",
        {"state": "response_received"},
    ),
    (
        re.compile(
            r"\[pool-(?P<pool>\d+)-thread-\d+\].*"
            r"Heartbeat request timed out",
            re.I,
        ),
        EventType.CONNECTIVITY_LOST,
        "FogNode backend heartbeat timed out",
        {"state": "heartbeat_timeout"},
    ),
    (
        re.compile(
            r"\[Operation\].*On connection close "
            r"\(code:\s*(?P<close_code>1006),\s*reason:\s*"
            r"(?P<reason>[^)]*pong in time[^)]*)",
            re.I,
        ),
        EventType.CONNECTIVITY_LOST,
        "Operation WebSocket closed after Pong timeout",
        {
            "endpoint": "customer_ocpp",
            "state": "pong_timeout",
            "detection_delay_only": True,
        },
    ),
    (
        re.compile(
            r"\[Operation\].*On error triggered caused by:\s*"
            r"ConnectException\s+(?P<url>ws://\S+)",
            re.I,
        ),
        EventType.CONNECTIVITY_LOST,
        "Operation WebSocket reconnect raised ConnectException",
        {"endpoint": "customer_ocpp", "state": "reconnect_failed"},
    ),
    (
        re.compile(
            r"\[Operation\].*On connection close "
            r"\(code:\s*-1,\s*reason:\s*Connection timed out",
            re.I,
        ),
        EventType.CONNECTIVITY_LOST,
        "Operation WebSocket reconnect timed out",
        {"endpoint": "customer_ocpp", "state": "reconnect_timeout"},
    ),
    (
        re.compile(
            r"operationStatus:\s*(?P<operation_status>\w+),\s*"
            r"maintenanceStatus:\s*(?P<maintenance_status>\w+),\s*"
            r"publicNetStatus:\s*(?P<public_net_status>\w+)",
            re.I,
        ),
        EventType.NETWORK_STATE,
        "FogNode operation, maintenance, and public-network status",
        {"category": "fognode_backend_status"},
    ),
    (
        re.compile(
            r"(?P<channel>Operation|Maintenance) Websocket Ping Interval "
            r"is set to (?P<ping_interval_seconds>\d+)",
            re.I,
        ),
        EventType.NETWORK_STATE,
        "FogNode WebSocket Ping interval configured",
        {"category": "websocket_ping_interval"},
    ),
    (
        re.compile(
            r"DeviceReport\s*\|\s*action:(?P<action>BootNotification|Heartbeat)"
            r"\s*\|\s*messageId:(?P<message_id>[^|\s]+)",
            re.I,
        ),
        EventType.NETWORK_STATE,
        "OCPP backend request sent",
        {"state": "request_sent"},
    ),
    (
        re.compile(
            r"PlatformCommand\s*\|\s*action:\s*\|\s*"
            r"messageId:(?P<message_id>[^|\s]+)",
            re.I,
        ),
        EventType.NETWORK_STATE,
        "OCPP backend response received",
        {"state": "response_received"},
    ),
    (
        re.compile(r"connection mode\s*:\s*routerMode", re.I),
        EventType.NETWORK_MODE_CHANGE,
        "Router mode took network ownership",
        {"manager": "routerMode", "mode": "routerMode"},
    ),
    (
        re.compile(r"router_connect\.sh\s*-\s*(?P<pid>\d+)\s+ready to kill", re.I),
        EventType.PROCESS_CLEANUP,
        "Duplicate router network script selected for termination",
        {"process": "router_connect.sh"},
    ),
    (
        re.compile(r"Starting SGServerEMS", re.I),
        EventType.SERVICE_START,
        "SGServerEMS started",
        {"service": "SGServerEMS"},
    ),
    (
        re.compile(r"\bip for .+ resolved success:", re.I),
        EventType.DNS_RECOVERED,
        "Backend hostname resolved successfully",
        {"state": "resolved"},
    ),
    (
        re.compile(r"DNS gateway .+ OK", re.I),
        EventType.NETWORK_STATE,
        "DNS gateway reachable",
        {"state": "gateway_ok"},
    ),
    (
        re.compile(r"Heartbeat Received", re.I),
        EventType.NETWORK_STATE,
        "Backend heartbeat response received",
        {"state": "reachable"},
    ),
    (
        re.compile(r"On connection open \(HTTP status:\s*101\)", re.I),
        EventType.WEBSOCKET_CONNECTED,
        "OCPP WebSocket connected",
        {"http_status": "101"},
    ),
    (
        re.compile(r"BootNotification.*status[\"']?\s*[:=]\s*[\"']?Accepted", re.I),
        EventType.OCPP_BOOT_ACCEPTED,
        "OCPP BootNotification accepted",
        {"status": "Accepted"},
    ),
)


def _timestamp(line: str, year: int, utc_offset_hours: float = 0.0) -> str:
    bracket_iso = BRACKET_ISO_TS.search(line)
    if bracket_iso:
        return bracket_iso.group("timestamp")
    bracket_date = BRACKET_DATE_TS.search(line)
    if bracket_date:
        value = f"{bracket_date.group('date')} {bracket_date.group('time')}"
        parsed = datetime.strptime(
            value,
            "%Y-%m-%d %H:%M:%S.%f"
            if "." in bracket_date.group("time")
            else "%Y-%m-%d %H:%M:%S",
        ).replace(tzinfo=timezone.utc)
        return parsed.isoformat().replace("+00:00", "Z")
    long_timestamp = LONG_TS.search(line)
    if long_timestamp:
        value = (
            f"{year} {long_timestamp.group('month')} {long_timestamp.group('day')} "
            f"{long_timestamp.group('time')}"
        )
        parsed = datetime.strptime(
            value,
            "%Y %B %d %H:%M:%S.%f" if "." in long_timestamp.group("time") else "%Y %B %d %H:%M:%S",
        ).replace(tzinfo=timezone.utc)
        return parsed.isoformat().replace("+00:00", "Z")
    short = SHORT_TS.search(line)
    if short:
        parsed = datetime.strptime(
            f"{year} {short.group('month')} {short.group('day')} {short.group('time')}",
            "%Y %b %d %H:%M:%S",
        ).replace(tzinfo=timezone.utc)
        return parsed.isoformat().replace("+00:00", "Z")
    full = FULL_TS.search(line)
    if full:
        parsed = datetime.strptime(
            f"{full.group('date')} {full.group('time')} {full.group('offset')}",
            "%Y-%m-%d %H:%M:%S.%f %z" if "." in full.group("time") else "%Y-%m-%d %H:%M:%S %z",
        )
        return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    naive_iso = NAIVE_ISO_TS.search(line)
    if naive_iso:
        value = naive_iso.group("timestamp")
        date_part, separator, fraction = value.partition(".")
        if separator:
            value = f"{date_part}.{fraction[:6]}"
        parsed = datetime.fromisoformat(value).replace(tzinfo=timezone.utc)
        return parsed.isoformat().replace("+00:00", "Z")
    naive_space = NAIVE_SPACE_TS.search(line)
    if naive_space:
        value = naive_space.group("timestamp")
        parsed = datetime.fromisoformat(value).replace(tzinfo=timezone.utc)
        return parsed.isoformat().replace("+00:00", "Z")
    syslog = SYSLOG_TS.search(line)
    if syslog:
        parsed = datetime.strptime(
            f"{year} {syslog.group('month')} {syslog.group('day')} "
            f"{syslog.group('time')}",
            "%Y %b %d %H:%M:%S",
        ).replace(tzinfo=timezone.utc)
        parsed -= timedelta(hours=utc_offset_hours)
        return parsed.isoformat().replace("+00:00", "Z")
    return ""


def _component(path: Path) -> str:
    lower = path.name.lower()
    if lower == "syslog.log" and path.parent.name.casefold() == "router":
        return "router_syslog"
    if "powercabinetfognode" in lower:
        return "powercabinetfognode"
    for component in (
        "dlm-network",
        "router_network",
        "centraldistributor",
        "mainprocess",
        "ocppsungrow",
        "maintenanceocpp",
        "ocpp",
        "network",
    ):
        if component in lower:
            return component
    return path.stem


def _domain(event_type: EventType) -> Domain:
    if event_type in {EventType.CP_STATE_CHANGE, EventType.NORMAL_STOP}:
        return Domain.CP
    if event_type in {EventType.POWER_FEEDBACK, EventType.POWER_REQUEST}:
        return Domain.POWER
    if event_type in {
        EventType.ERROR_CODE,
        EventType.SESSION_START,
        EventType.SESSION_STOP,
        EventType.AUTHORIZATION,
        EventType.WEBSOCKET_CONNECTED,
        EventType.OCPP_BOOT_ACCEPTED,
        EventType.OCPP_STOP_ACCEPTED,
        EventType.ERROR_CODE_CLEARED,
        EventType.CONNECTOR_STATUS,
    }:
        return Domain.OCPP
    if event_type in {
        EventType.CURRENT_DEMAND,
        EventType.EV_CURRENT_LIMIT,
        EventType.EMERGENCY_STOP,
        EventType.ISO15118_STATE,
        EventType.PROTOCOL_ERROR,
        EventType.CABLECHECK_FINISHED,
    }:
        return Domain.ISO15118
    return Domain.NETWORK


def parse_incident_file(
    path: Path,
    *,
    year: int,
    charger_id: str,
    utc_offset_hours: float = 0.0,
    start_utc: datetime | None = None,
    end_utc: datetime | None = None,
) -> list[Event]:
    events: list[Event] = []
    current_interface = ""
    current_smart_connector: int | None = None
    component = _component(path)
    path_connector_match = re.search(r"CCU_Ethernet(?P<connector>\d+)", path.name, re.I)
    path_connector_id = (
        int(path_connector_match.group("connector"))
        if path_connector_match
        else None
    )
    aggregates: dict[str, dict[str, object]] = {}
    signal_values: dict[str, list[float]] = {
        "rssi_dbm": [],
        "rsrq_db": [],
        "rsrp_dbm": [],
        "snr_db": [],
    }
    window_date_tokens: set[str] = set()
    if start_utc is not None and end_utc is not None:
        local_start = start_utc + timedelta(hours=utc_offset_hours)
        local_end = end_utc + timedelta(hours=utc_offset_hours)
        day = local_start.date()
        while day <= local_end.date():
            abbreviated = day.strftime("%b")
            full = day.strftime("%B")
            window_date_tokens.update(
                {
                    day.isoformat(),
                    f"{abbreviated}/{day.day}",
                    f"{abbreviated}/{day.day:02d}",
                    f"{full}/{day.day}",
                    f"{full}/{day.day:02d}",
                    f"{abbreviated} {day.day:2d}",
                    f"{abbreviated} {day.day:02d}",
                }
            )
            day += timedelta(days=1)

    def observe(key: str, text: str, line_no: int) -> None:
        timestamp = _timestamp(text, year, utc_offset_hours)
        item = aggregates.setdefault(
            key,
            {
                "count": 0,
                "first_ts": timestamp,
                "last_ts": timestamp,
                "first_line": line_no,
                "sample": text[:1000],
            },
        )
        item["count"] = int(item["count"]) + 1
        if timestamp:
            item["last_ts"] = timestamp

    with path.open("r", encoding="utf-8", errors="ignore") as handle:
        for line_no, line in enumerate(handle, 1):
            text = line.rstrip("\r\n")
            if window_date_tokens and not any(
                token in text[:40] for token in window_date_tokens
            ):
                continue
            line_timestamp = _timestamp(text, year, utc_offset_hours)
            if start_utc is not None or end_utc is not None:
                if not line_timestamp:
                    continue
                parsed_line_time = datetime.fromisoformat(
                    line_timestamp[:-1] + "+00:00"
                    if line_timestamp.endswith("Z")
                    else line_timestamp
                ).astimezone(timezone.utc)
                if start_utc is not None and parsed_line_time < start_utc:
                    continue
                if end_utc is not None and parsed_line_time > end_utc:
                    continue
            if component == "ocppsungrow":
                if "Trying to connect to:" in text:
                    observe("maintenance_attempt", text, line_no)
                if "On connection close" in text:
                    observe("maintenance_close", text, line_no)
            if component == "router_network":
                if re.search(r"DNS gateway .+ OK", text, re.I):
                    observe("gateway_ok", text, line_no)
                elif re.search(r"DNS gateway .+ not detected.*Re-adding", text, re.I):
                    observe("gateway_readded", text, line_no)
                if re.search(r"ip for connect\.longship\.io resolved success", text, re.I):
                    observe("customer_dns", text, line_no)
            signal_match = re.search(
                r"LTE:\s*RSSI\s+(?P<rssi>-?[0-9.]+)\s*dBm,\s*"
                r"RSRQ\s+(?P<rsrq>-?[0-9.]+)\s*dB,\s*"
                r"RSRP\s+(?P<rsrp>-?[0-9.]+)\s*dBm,\s*"
                r"SNR\s+(?P<snr>-?[0-9.]+)\s*dB",
                text,
                re.I,
            )
            if signal_match:
                observe("cellular_signal", text, line_no)
                for source, target in (
                    ("rssi", "rssi_dbm"),
                    ("rsrq", "rsrq_db"),
                    ("rsrp", "rsrp_dbm"),
                    ("snr", "snr_db"),
                ):
                    signal_values[target].append(float(signal_match.group(source)))
            if re.search(
                r"DC Meter:\s*2\s+offline,\s*i_isOnlineCounter below 0",
                text,
                re.I,
            ):
                observe("meter2_offline", text, line_no)
            if re.search(
                r"DC Meter:\s*1\s+offline,\s*i_isOnlineCounter below 0",
                text,
                re.I,
            ):
                observe("meter1_offline", text, line_no)
            interface_match = re.search(r"\binterface\s+(eth\d+)\b", text, re.I)
            if interface_match:
                current_interface = interface_match.group(1).lower()
            smart_connector_match = re.search(
                r"Smart charging limit setting info of connector\s+(?P<connector>\d+)",
                text,
                re.I,
            )
            if smart_connector_match:
                current_smart_connector = int(
                    smart_connector_match.group("connector")
                )
            for pattern, event_type, summary, defaults in PATTERNS:
                if defaults.get("code") == "S20" and "S20" not in text:
                    continue
                if (
                    summary == "OCPP connector status reported"
                    and "StatusNotification" not in text
                ):
                    continue
                if (
                    summary == "DNS gateway reachable"
                    and component == "router_network"
                ):
                    continue
                if (
                    summary == "Backend hostname resolved successfully"
                    and "connect.longship.io" in text
                ):
                    continue
                if (
                    summary
                    in {
                        "CCU reported frame communication timeout S20",
                        "CCU stop-error list cleared",
                    }
                    and "CCU error raw" not in text
                ):
                    continue
                match = pattern.search(text)
                if not match:
                    continue
                timestamp = line_timestamp
                attrs = dict(defaults)
                attrs.update({key: value for key, value in match.groupdict().items() if value})
                if event_type in {EventType.CURRENT_DEMAND, EventType.EV_CURRENT_LIMIT}:
                    try:
                        attrs["current_A"] = float(attrs["mantissa"]) * (10 ** int(attrs["exponent"]))
                    except (KeyError, ValueError):
                        pass
                if event_type == EventType.CURRENT_DEMAND:
                    ev_max_power = re.search(
                        r"EV_Max_P_Limit=(?P<mantissa>-?[0-9.]+)"
                        r"\((?P<exponent>-?\d+)\)W",
                        text,
                        re.I,
                    )
                    if ev_max_power:
                        attrs["ev_max_power_kW"] = (
                            float(ev_max_power.group("mantissa"))
                            * (10 ** int(ev_max_power.group("exponent")))
                            / 1000
                        )
                if (
                    event_type == EventType.EV_CURRENT_LIMIT
                    and attrs.get("power_mantissa")
                ):
                    attrs["power_kW"] = (
                        float(attrs["power_mantissa"])
                        * (10 ** int(attrs["power_exponent"]))
                        / 1000
                    )
                if event_type == EventType.POWER_FEEDBACK:
                    try:
                        if attrs.get("voltage"):
                            attrs["voltage_V"] = float(attrs["voltage"])
                        elif attrs.get("voltage_raw"):
                            attrs["voltage_V"] = float(
                                attrs["voltage_raw"]
                            ) * float(attrs["voltage_scale"])
                        if attrs.get("current_raw"):
                            attrs["current_A"] = float(
                                attrs["current_raw"]
                            ) * float(attrs["current_scale"])
                        if attrs.get("voltage_V") and attrs.get("current_A"):
                            attrs["power_kW"] = (
                                attrs["voltage_V"] * attrs["current_A"] / 1000
                            )
                        if attrs.get("measurement") == "r37_ac_input":
                            scale = float(attrs["voltage_scale"])
                            attrs["phase_voltages_V"] = [
                                float(attrs["va_raw"]) * scale,
                                float(attrs["vb_raw"]) * scale,
                                float(attrs["vc_raw"]) * scale,
                            ]
                    except (KeyError, ValueError):
                        pass
                if (
                    event_type == EventType.ISO15118_STATE
                    and attrs.get("message") == "P_CharReq"
                ):
                    target_voltage = re.search(
                        r"EV_Target_V=(?P<mantissa>-?[0-9.]+)"
                        r"\((?P<exponent>-?\d+)\)V",
                        text,
                        re.I,
                    )
                    if target_voltage:
                        attrs["target_voltage_V"] = (
                            float(target_voltage.group("mantissa"))
                            * (10 ** int(target_voltage.group("exponent")))
                        )
                if event_type == EventType.POWER_REQUEST and attrs.get(
                    "voltage_mantissa"
                ):
                    attrs["voltage_V"] = float(
                        attrs["voltage_mantissa"]
                    ) * (10 ** int(attrs["voltage_exponent"]))
                    if attrs.get("measurement") == "EVTargetVoltage":
                        attrs["target_voltage_V"] = attrs["voltage_V"]
                if event_type == EventType.POWER_REQUEST and attrs.get(
                    "power_W"
                ):
                    attrs["power_kW"] = float(attrs["power_W"]) / 1000
                if (
                    event_type == EventType.POWER_REQUEST
                    and attrs.get("measurement") == "cabinet_output_allocation"
                ):
                    scale = float(attrs["power_scale"])
                    attrs["from_power_kW"] = float(attrs["from_raw"]) * scale
                    attrs["to_power_kW"] = float(attrs["to_raw"]) * scale
                inner_time = re.search(
                    r"\[D\d+\s+(?P<inner_time>\d{2}:\d{2}:\d{2}\.\d+)\]",
                    text,
                    re.I,
                )
                if inner_time:
                    attrs["inner_time"] = inner_time.group("inner_time")
                if attrs.get("link_state"):
                    attrs["state"] = (
                        "link_up"
                        if str(attrs["link_state"]).lower() == "true"
                        else "link_down"
                    )
                if attrs.get("lem_errors_blob"):
                    attrs["codes"] = [
                        f"L{code}"
                        for code in re.findall(
                            r'["\']Description["\']\s*:\s*["\'](\d+)["\']',
                            str(attrs["lem_errors_blob"]),
                            re.I,
                        )
                    ]
                elif attrs.get("codes"):
                    attrs["codes"] = str(attrs["codes"]).split(",")
                if attrs.get("device") == "dc_meter" and attrs.get("ip"):
                    attrs["meter_connector"] = (
                        2 if str(attrs["ip"]).startswith("192.168.10.") else 1
                    )
                if event_type == EventType.WEBSOCKET_CONNECTED:
                    attrs.setdefault(
                        "endpoint",
                        "maintenance"
                        if component in {"ocppsungrow", "maintenanceocpp"}
                        else "customer_ocpp",
                    )
                if summary == "Backend heartbeat response received":
                    attrs["endpoint"] = (
                        "maintenance"
                        if component in {"ocppsungrow", "maintenanceocpp"}
                        else "customer_ocpp"
                    )
                if summary in {
                    "OCPP backend request sent",
                    "OCPP backend response received",
                }:
                    channel = str(attrs.get("channel", "")).casefold()
                    attrs["endpoint"] = (
                        "maintenance"
                        if channel == "maintenance"
                        or component in {"ocppsungrow", "maintenanceocpp"}
                        else "customer_ocpp"
                    )
                if attrs.get("channel"):
                    attrs.setdefault(
                        "endpoint",
                        "maintenance"
                        if str(attrs["channel"]).casefold() == "maintenance"
                        else "customer_ocpp",
                    )
                if (
                    summary == "FogNode backend heartbeat timed out"
                    and attrs.get("pool")
                ):
                    attrs["endpoint"] = (
                        "customer_ocpp"
                        if attrs["pool"] == "5"
                        else "maintenance"
                        if attrs["pool"] == "6"
                        else "unknown"
                    )
                if attrs.get("category") == "operation_backend_state":
                    attrs["state"] = (
                        "good"
                        if attrs.get("backend_state") == "1"
                        else "down"
                    )
                if attrs.get("ping_state"):
                    attrs["state"] = (
                        "external_ping_ok"
                        if str(attrs["ping_state"]).lower() == "true"
                        else "external_ping_failed"
                    )
                if current_interface:
                    attrs.setdefault("interface", current_interface)
                event_summary = summary
                if event_type == EventType.PROCESS_CLEANUP and attrs.get("pid"):
                    event_summary = f"{summary} (pid={attrs['pid']})"
                if (
                    attrs.get("category") == "connector_fault_state"
                    and attrs.get("fault")
                ):
                    event_summary = f"{summary} ({attrs['fault']})"
                if (
                    attrs.get("category") == "power_module_fault"
                    and attrs.get("fault")
                ):
                    event_summary = f"{summary} ({attrs['fault']})"
                if event_type in {
                    EventType.CURRENT_DEMAND,
                    EventType.EV_CURRENT_LIMIT,
                    EventType.POWER_FEEDBACK,
                } and isinstance(attrs.get("current_A"), (int, float)):
                    event_summary = (
                        f"{summary} ({float(attrs['current_A']):.1f} A)"
                    )
                connector = attrs.get("connector")
                connector_id = (
                    int(connector)
                    if connector and connector.isdigit()
                    else path_connector_id
                )
                if (
                    connector_id is None
                    and attrs.get("controller") == "smart_charging"
                ):
                    connector_id = current_smart_connector
                if connector_id is None and attrs.get("meter_connector"):
                    connector_id = int(attrs["meter_connector"])
                event_domain = _domain(event_type)
                if attrs.get("category") in {
                    "lem_fault_vector",
                    "connector_fault_state",
                } or attrs.get("device") == "dc_meter" or attrs.get(
                    "protection"
                ) in {
                    "output_over_ev_request_voltage",
                    "output_current_over_ev_request",
                }:
                    event_domain = Domain.POWER
                if attrs.get("reason") == "Precharge_Fault":
                    event_domain = Domain.ISO15118
                if attrs.get("reason") == "Current_Demand_Fault":
                    event_domain = Domain.POWER
                if attrs.get("cp_state"):
                    event_domain = Domain.CP
                if attrs.get("category") == "firmware_update":
                    event_domain = Domain.SYSTEM
                if attrs.get("category") == "process_start":
                    event_domain = Domain.SYSTEM
                if attrs.get("path") == "customer_router":
                    event_domain = Domain.NETWORK
                if attrs.get("category") in {
                    "power_module_fault",
                    "power_module_group",
                    "power_module_availability",
                }:
                    event_domain = Domain.POWER
                events.append(
                    Event(
                        id=f"incident-{path.stem}-{line_no}-{event_type.value.lower()}",
                        ts_utc=timestamp,
                        source=component,
                        type=event_type,
                        summary=event_summary,
                        raw=text[:1000],
                        connector_id=connector_id,
                        attrs=attrs,
                        domain=event_domain,
                        component=component,
                        original_timestamp=timestamp,
                        charger_id=charger_id,
                        parse_quality=ParseQuality.EXACT,
                        source_location=SourceLocation(path=path.name, line=line_no),
                    )
                )
                break

    aggregate_definitions = {
        "maintenance_attempt": (
            EventType.CONNECTIVITY_LOST,
            "Maintenance backend reconnect attempts",
            {"endpoint": "maintenance", "action": "connect_attempt"},
        ),
        "maintenance_close": (
            EventType.CONNECTIVITY_LOST,
            "Maintenance backend WebSocket closures",
            {"endpoint": "maintenance", "remote": "true"},
        ),
        "gateway_ok": (
            EventType.NETWORK_STATE,
            "Default gateway checks succeeded",
            {"state": "gateway_ok"},
        ),
        "gateway_readded": (
            EventType.NETWORK_STATE,
            "Default gateway was missing and re-added",
            {"state": "gateway_readded"},
        ),
        "customer_dns": (
            EventType.NETWORK_STATE,
            "Customer OCPP hostname resolved",
            {"endpoint": "customer_ocpp", "state": "dns_resolved"},
        ),
        "cellular_signal": (
            EventType.NETWORK_STATE,
            "Cellular signal samples",
            {"interface": "usb0", "state": "signal_sampled"},
        ),
        "meter2_offline": (
            EventType.CONNECTIVITY_LOST,
            "Connector 2 DC meter offline samples",
            {
                "endpoint": "dc_meter",
                "device": "dc_meter",
                "state": "offline",
                "connector": "2",
            },
        ),
        "meter1_offline": (
            EventType.CONNECTIVITY_LOST,
            "Connector 1 DC meter offline samples",
            {
                "endpoint": "dc_meter",
                "device": "dc_meter",
                "state": "offline",
                "connector": "1",
            },
        ),
    }
    for key, item in aggregates.items():
        event_type, summary, defaults = aggregate_definitions[key]
        attrs = {
            **defaults,
            "count": item["count"],
            "first_ts": item["first_ts"],
            "last_ts": item["last_ts"],
        }
        if key == "cellular_signal":
            attrs.update(
                {
                    f"{name}_min": min(values)
                    for name, values in signal_values.items()
                    if values
                }
            )
            attrs.update(
                {
                    f"{name}_max": max(values)
                    for name, values in signal_values.items()
                    if values
                }
            )
        events.append(
            Event(
                id=f"incident-{path.stem}-aggregate-{key}",
                ts_utc=str(item["first_ts"]),
                source=component,
                type=event_type,
                summary=f"{summary} ({item['count']})",
                raw=str(item["sample"]),
                attrs=attrs,
                domain=(
                    Domain.POWER
                    if key in {"meter1_offline", "meter2_offline"}
                    else Domain.NETWORK
                ),
                connector_id=(
                    1
                    if key == "meter1_offline"
                    else 2 if key == "meter2_offline" else None
                ),
                component=component,
                original_timestamp=str(item["first_ts"]),
                charger_id=charger_id,
                parse_quality=ParseQuality.EXACT,
                source_location=SourceLocation(
                    path=path.name, line=int(item["first_line"])
                ),
            )
        )
    return events

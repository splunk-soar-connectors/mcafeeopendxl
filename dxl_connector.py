# Phantom App imports
import os

import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult

from dxl_consts import *

from dxlclient.client import DxlClient
from dxlclient.client_config import DxlClientConfig
from dxlclient.message import Event

from dxltieclient import TieClient
from dxltieclient.constants import HashType

from dxlmarclient import MarClient

import simplejson as json
import uuid
import datetime

now = datetime.datetime.utcnow()
nowform = now.strftime("%Y-%m-%d %H:%M:%S")

# Define the App Class
class DXLConnector(BaseConnector):

    def __init__(self):

        # Call the BaseConnectors init first
        super(DXLConnector, self).__init__()

    def _message(self, dxl_msg):

        # Creating DXL message in CEF format for McAfee SIA DXL Task Manager
        agentuid = str(uuid.uuid4()).lower()
        cef = {
              "DXLCommonEvent":
              {
              "AgentGUID": agentuid,
              "Analyzer": "",
              "AnalyzerName": "Phantom Cyber Post IP",
              "AnalyzerVersion": "",
              "DetectedUTC": nowform,
              "SourceIPV4": "",
              "TargetIPV4": dxl_msg,
              "ThreatActionTaken": "contain",
              "ThreatCategory": "IP",
              "ThreatEventID": "204250",
              "ThreatName": "Suspicious IP",
              "ThreatSeverity": "5",
              "ThreatType": "Suspicious IP for containment.",
              "TargetPort": "80",
              "ThreatHandled": "",
              "AnalyzerIPV6": "",
              "SourceIPV6": "",
              "TargetIPV6": ""
              }
              }

        return cef
        
    def _test_connectivity(self, param):

        config = self.get_config()

        # Get Variables
        dxl_topic = config.get(DXL_TOPIC)
        dxl_tmsg = config.get(DXL_TMSG)

        if (not dxl_topic):
            self.save_progress("No DXL Topic Defined.")
            return self.get_status()

        if (not dxl_tmsg):
            self.save_progress("No Test Message Defined.")
            return self.get_status()

        self.save_progress("Sending a DXL Message to check connectivity")

        # Progress
        self.save_progress(phantom.APP_PROG_CONNECTING_TO_ELLIPSES, dxl_topic)

        try:
            dir = os.path.dirname(__file__)
            CONFIG_FILE = os.path.join(dir, 'certs/dxlclient.config')
            dxlconfig = DxlClientConfig.create_dxl_config_from_file(CONFIG_FILE)

            with DxlClient(dxlconfig) as client:
                client.connect()
                event = Event(dxl_topic)
                event.payload = str(dxl_tmsg).encode()
                client.send_event(event)

        except:
            self.set_status(phantom.APP_ERROR, DXL_ERR_SERVER_CONNECTION)
            self.append_to_message(DXL_ERR_CONNECTIVITY_TEST)
            return self.get_status()

        return self.set_status_save_progress(phantom.APP_SUCCESS, DXL_SUCC_CONNECTIVITY_TEST)

    def _handle_dxl_ip(self, param):

        # Push IP Address over the McAfee Data Exchange Layer (DXL)

        config = self.get_config()
        self.debug_print("param", param)

        action_result = ActionResult(dict(param))
        self.add_action_result(action_result)

        dxl_topic = config.get(DXL_TOPIC)
        dxl_msg = param[DXL_PUSH_IP]

        try:
            dir = os.path.dirname(__file__)
            CONFIG_FILE = os.path.join(dir, 'certs/dxlclient.config')
            dxlconfig = DxlClientConfig.create_dxl_config_from_file(CONFIG_FILE)

            message = self._message(dxl_msg)
            
            with DxlClient(dxlconfig) as client:
                client.connect()
                event = Event(dxl_topic)
                event.payload = str(message).encode()
                client.send_event(event)
                action_result.add_data(dxl_msg)
                action_result.set_status(phantom.APP_SUCCESS, DXL_SUCC_QUERY)

        except:
            action_result.set_status(phantom.APP_ERROR, DXL_ERR_QUERY, dxl_msg)
            return action_result.get_status()

        return action_result.get_status()

    def _handle_tie_md5(self, param):

        # Push malicious hash into the McAfee Threat Intelligence Exchange Database (TIE)

        self.debug_print("param", param)

        action_result = ActionResult(dict(param))
        self.add_action_result(action_result)

        dxl_msg = param[DXL_PUSH_MD5]
        dxl_rep = param[DXL_REP]

        if (dxl_rep == "KNOWN_TRUSTED_INSTALLER"):
            dxl_rep = "100"
        elif (dxl_rep == "KNOWN_TRUSTED"):
            dxl_rep = "99"
        elif (dxl_rep == "MOST_LIKELY_TRUSTED"):
            dxl_rep = "85"
        elif (dxl_rep == "MIGHT_BE_TRUSTED"):
            dxl_rep = "70"
        elif (dxl_rep == "UNKNOWN"):
            dxl_rep = "50"
        elif (dxl_rep == "MIGHT_BE_MALICIOUS"):
            dxl_rep = "30"
        elif (dxl_rep == "MOST_LIKELY_MALICIOUS"):
            dxl_rep = "15"
        elif (dxl_rep == "KNOWN_MALICIOUS"):
            dxl_rep = "1"
        elif (dxl_rep == "NOT_SET"):
            dxl_rep = "0"

        try:
            dir = os.path.dirname(__file__)
            CONFIG_FILE = os.path.join(dir, 'certs/dxlclient.config')
            dxlconfig = DxlClientConfig.create_dxl_config_from_file(CONFIG_FILE)

            with DxlClient(dxlconfig) as client:
                client.connect()
                tie_client = TieClient(client)
                tie_client.set_file_reputation(
                    dxl_rep, {
                        HashType.MD5: dxl_msg
                    },
                    filename="Phantom_SharedHash",
                    comment="Reputation set via Phantom"
                )
                action_result.add_data(dxl_msg)
                action_result.set_status(phantom.APP_SUCCESS, DXL_SUCC_QUERY)
        except:
            self.set_status(phantom.APP_ERROR, DXL_ERR_SERVER_CONNECTION)
            self.append_to_message(DXL_ERR_CONNECTIVITY_TEST)
            action_result.set_status(phantom.APP_ERROR, DXL_ERR_QUERY, dxl_msg)
            return self.get_status()

        return action_result.get_status()

    def _handle_mar_md5(self, param):

        # Lookup malicious MD5 Hash

        self.debug_print("param", param)

        action_result = ActionResult(dict(param))
        self.add_action_result(action_result)

        dxl_msg = param[DXL_LOOKUP_MD5]

        try:
            dir = os.path.dirname(__file__)
            CONFIG_FILE = os.path.join(dir, 'certs/dxlclient.config')
            dxlconfig = DxlClientConfig.create_dxl_config_from_file(CONFIG_FILE)

            with DxlClient(dxlconfig) as client:
                client.connect()
                marclient = MarClient(client)

                results_context = marclient.search(
                    projections=[{
                        "name": "HostInfo",
                        "outputs": ["hostname", "ip_address"]
                    }, {
                        "name": "Files",
                        "outputs": ["md5", "status"]
                    }],
                    conditions={
                        "or": [{
                            "and": [{
                                "name": "Files",
                                "output": "md5",
                                "op": "EQUALS",
                                "value": dxl_msg
                            }]
                        }]
                    }
                )

                if results_context.has_results:
                    results = results_context.get_results(limit=10)
                print results

            action_result.add_data(results)
            action_result.set_status(phantom.APP_SUCCESS, DXL_SUCC_QUERY)

        except:
            action_result.set_status(phantom.APP_ERROR, DXL_ERR_QUERY, dxl_msg)
            return action_result.get_status()

        return action_result.get_status()

    def handle_action(self, param):

        ret_val = phantom.APP_SUCCESS

        action_id = self.get_action_identifier()
        self.debug_print("action_id", self.get_action_identifier())

        if (action_id == "dxl_ip"):
            ret_val = self._handle_dxl_ip(param)
        elif (action_id == "tie_md5"):
            ret_val = self._handle_tie_md5(param)
        elif (action_id == "mar_md5"):
            ret_val = self._handle_mar_md5(param)
        elif (action_id == phantom.ACTION_ID_TEST_ASSET_CONNECTIVITY):
            ret_val = self._test_connectivity(param)

        return ret_val


if __name__ == '__main__':

    import sys
    import pudb
    pudb.set_trace()

    if (len(sys.argv) < 2):
        print "No test json specified as input"
        exit(0)

    with open(sys.argv[1]) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = DXLConnector()
        connector.print_progress_message = True
        ret_val = connector._handle_action(json.dumps(in_json), None)
        print (json.dumps(json.loads(ret_val), indent=4))

    exit(0)

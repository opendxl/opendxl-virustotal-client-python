import json

from dxlbootstrap.util import MessageUtils
from dxlclient.callbacks import RequestCallback
from dxlclient.message import Response, ErrorResponse
from dxlvtapiclient import VirusTotalApiClient
from tests.test_value_constants import *

class FakeVTServiceCallback(RequestCallback):
    # The format for request topics that are associated with the ePO DXL service
    vt_request_topic_base = "/opendxl-virustotal/service/vtapi"
    vt_basic_test_topic = vt_request_topic_base + "/basictest"

    # UTF-8 encoding (used for encoding/decoding payloads)
    UTF_8 = "utf-8"

    def __init__(self, client):
        """
        Constructor parameters:

        :param app: The application this handler is associated with
        """
        super(FakeVTServiceCallback, self).__init__()

        self._client = client
        #self._callbacks = {
        #    self.vt_request_topic_base: self.on_request
        #}

    def on_request(self, request):
        try:
            # Build dictionary from the request payload
            req_dict = json.loads(request.payload.decode(encoding=self.UTF_8))

            response = Response(request)

            if request.destination_topic == self.vt_basic_test_topic:
                self.basic_test(response)
            elif request.destination_topic == VirusTotalApiClient._REQ_TOPIC_DOMAIN_REPORT:
                self.domain_report(response, req_dict)

            elif request.destination_topic == VirusTotalApiClient._REQ_TOPIC_FILE_REPORT:
                self.file_report(response, req_dict)

            elif request.destination_topic == VirusTotalApiClient._REQ_TOPIC_FILE_RESCAN:
                self.file_rescan(response, req_dict)

            elif request.destination_topic == VirusTotalApiClient._REQ_TOPIC_IP_ADDRESS_REPORT:
                self.ip_report(response, req_dict)

            elif request.destination_topic == VirusTotalApiClient._REQ_TOPIC_URL_SCAN:
                self.url_scan(response, req_dict)

            elif request.destination_topic == VirusTotalApiClient._REQ_TOPIC_URL_REPORT:
                self.url_report(response, req_dict)

            self._client.send_response(response)

        except Exception as ex:
            # Send error response
            self._client.send_response(
                ErrorResponse(request,
                              error_message=str(ex).encode(
                                  encoding=self.UTF_8)))


    @staticmethod
    def basic_test(response):
        response.payload = MessageUtils.dict_to_json(BASIC_SERVICE_RESPONSE, True)

        return response


    @staticmethod
    def domain_report(response, req_dict):

        response.payload = '{ status: failed }'

        rules = [
            VirusTotalApiClient._PARAM_DOMAIN in req_dict,
            req_dict[VirusTotalApiClient._PARAM_DOMAIN] == SAMPLE_DOMAIN
        ]

        if all(rules):
            response.payload = MessageUtils.dict_to_json(SAMPLE_DOMAIN_REPORT, True)

        return response


    @staticmethod
    def file_report(response, req_dict):
        response.payload = '{ status: failed }'

        rules = [
            VirusTotalApiClient._PARAM_RESOURCE in req_dict,
            req_dict[VirusTotalApiClient._PARAM_RESOURCE] == SAMPLE_FILE
        ]

        if all(rules):
            res_payload = SAMPLE_FILE_REPORT
            received_params = {}

            if VirusTotalApiClient._PARAM_ALLINFO in req_dict:
                received_params[VirusTotalApiClient._PARAM_ALLINFO] = \
                    req_dict[VirusTotalApiClient._PARAM_ALLINFO]

            res_payload[RECEIVED_PARAMS_KEY] = received_params
            response.payload = MessageUtils.dict_to_json(res_payload, True)

        return response


    @staticmethod
    def file_rescan(response, req_dict):
        response.payload = '{ status: failed }'

        rules = [
            VirusTotalApiClient._PARAM_RESOURCE in req_dict,
            req_dict[VirusTotalApiClient._PARAM_RESOURCE] == SAMPLE_FILE
        ]

        if all(rules):
            res_payload = SAMPLE_FILE_RESCAN
            received_params = {}

            if VirusTotalApiClient._PARAM_DATE in req_dict:
                received_params[VirusTotalApiClient._PARAM_DATE] = \
                    req_dict[VirusTotalApiClient._PARAM_DATE]

            if VirusTotalApiClient._PARAM_PERIOD in req_dict:
                received_params[VirusTotalApiClient._PARAM_PERIOD] = \
                    req_dict[VirusTotalApiClient._PARAM_PERIOD]

            if VirusTotalApiClient._PARAM_REPEAT in req_dict:
                received_params[VirusTotalApiClient._PARAM_REPEAT] = \
                    req_dict[VirusTotalApiClient._PARAM_REPEAT]

            if VirusTotalApiClient._PARAM_NOTIFY_URL in req_dict:
                received_params[VirusTotalApiClient._PARAM_NOTIFY_URL] = \
                    req_dict[VirusTotalApiClient._PARAM_NOTIFY_URL]

            if VirusTotalApiClient._PARAM_NOTIFY_CHANGES_ONLY in req_dict:
                received_params[VirusTotalApiClient._PARAM_NOTIFY_CHANGES_ONLY] = \
                    req_dict[VirusTotalApiClient._PARAM_NOTIFY_CHANGES_ONLY]

            res_payload[RECEIVED_PARAMS_KEY] = received_params
            response.payload = MessageUtils.dict_to_json(res_payload, True)

        return response


    @staticmethod
    def ip_report(response, req_dict):
        response.payload = '{ status: failed }'

        rules = [
            VirusTotalApiClient._PARAM_IP in req_dict,
            req_dict[VirusTotalApiClient._PARAM_IP] == SAMPLE_IP
        ]

        if all(rules):
            response.payload = MessageUtils.dict_to_json(SAMPLE_IP_ADDRESS_REPORT, True)

        return response


    @staticmethod
    def url_report(response, req_dict):
        response.payload = '{ status: failed }'

        rules = [
            VirusTotalApiClient._PARAM_RESOURCE in req_dict,
            req_dict[VirusTotalApiClient._PARAM_RESOURCE] == SAMPLE_URL
        ]

        if all(rules):
            res_payload = SAMPLE_URL_REPORT
            received_params = {}

            if VirusTotalApiClient._PARAM_SCAN in req_dict:
                received_params[VirusTotalApiClient._PARAM_SCAN] = \
                    req_dict[VirusTotalApiClient._PARAM_SCAN]

            if VirusTotalApiClient._PARAM_ALLINFO in req_dict:
                received_params[VirusTotalApiClient._PARAM_ALLINFO] = \
                    req_dict[VirusTotalApiClient._PARAM_ALLINFO]

            res_payload[RECEIVED_PARAMS_KEY] = received_params
            response.payload = MessageUtils.dict_to_json(res_payload, True)

        return response


    @staticmethod
    def url_scan(response, req_dict):
        response.payload = '{ status: failed }'

        rules = [
            VirusTotalApiClient._PARAM_URL in req_dict,
            req_dict[VirusTotalApiClient._PARAM_URL] == SAMPLE_URL
        ]

        if all(rules):
            response.payload = MessageUtils.dict_to_json(SAMPLE_URL_SCAN, True)

        return response

from dxlclient.service import ServiceRegistrationInfo
from dxlvtapiclient import VirusTotalApiClient
from tests.mock_requesthandlers import *


class MockVtService(object):

    mockvt_basic_test_topic = FakeVTServiceCallback.vt_basic_test_topic

    def __init__(self, client):
        self._client = client

        # Create DXL Service Registration object
        self._service_registration_info = ServiceRegistrationInfo(
            self._client,
            VirusTotalApiClient._SERVICE_TYPE,
        )
        self._service_registration_info._ttl_lower_limit = 5
        self._service_registration_info.ttl = 5


    def __enter__(self):
        mock_callback = FakeVTServiceCallback(self._client)

        self._service_registration_info.add_topic(
            MockVtService.mockvt_basic_test_topic,
            mock_callback
        )

        self._service_registration_info.add_topic(
            VirusTotalApiClient._REQ_TOPIC_DOMAIN_REPORT,
            mock_callback
        )
        self._service_registration_info.add_topic(
            VirusTotalApiClient._REQ_TOPIC_FILE_REPORT,
            mock_callback
        )
        self._service_registration_info.add_topic(
            VirusTotalApiClient._REQ_TOPIC_FILE_RESCAN,
            mock_callback
        )
        self._service_registration_info.add_topic(
            VirusTotalApiClient._REQ_TOPIC_IP_ADDRESS_REPORT,
            mock_callback
        )
        self._service_registration_info.add_topic(
            VirusTotalApiClient._REQ_TOPIC_URL_REPORT,
            mock_callback
        )
        self._service_registration_info.add_topic(
            VirusTotalApiClient._REQ_TOPIC_URL_SCAN,
            mock_callback
        )

        self._client.register_service_sync(self._service_registration_info, 10)

        return self


    def __exit__(self, exc_type, exc_val, exc_tb):
        self._client.unregister_service_sync(self._service_registration_info, 10)

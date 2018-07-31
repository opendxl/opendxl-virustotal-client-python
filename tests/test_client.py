from dxlvtapiclient import VirusTotalApiClient
from tests.test_base import BaseClientTest
from tests.test_value_constants import *
from tests.mock_vtservice import MockVtService


class TestRunCommand(BaseClientTest):

    def test_invoke_service(self):
        with self.create_client(max_retries=0) as dxl_client:
            # Set up client, and register mock service
            vt_client = VirusTotalApiClient(dxl_client)
            dxl_client.connect()

            with MockVtService(dxl_client):

                result = vt_client._invoke_service(
                    req_dict={'serve': 'ping'},
                    topic=MockVtService.mockvt_basic_test_topic
                )

                self.assertDictEqual(result, BASIC_SERVICE_RESPONSE)

            dxl_client.disconnect()


    def test_domainreport(self):
        with self.create_client(max_retries=0) as dxl_client:
            # Set up client, and register mock service
            vt_client = VirusTotalApiClient(dxl_client)
            dxl_client.connect()

            with MockVtService(dxl_client):

                result = vt_client.domain_report(SAMPLE_DOMAIN)

                self.assertDictEqual(result, SAMPLE_DOMAIN_REPORT)

            dxl_client.disconnect()


    def test_filereport(self):
        with self.create_client(max_retries=0) as dxl_client:
            # Set up client, and register mock service
            vt_client = VirusTotalApiClient(dxl_client)
            dxl_client.connect()

            with MockVtService(dxl_client):

                result = vt_client.file_report(SAMPLE_FILE)

                # Mock server always provides received params for this API call
                del result[RECEIVED_PARAMS_KEY]
                self.assertDictEqual(result, SAMPLE_FILE_REPORT)

            dxl_client.disconnect()


    def test_filereport_params(self):
        with self.create_client(max_retries=0) as dxl_client:
            # Set up client, and register mock service
            vt_client = VirusTotalApiClient(dxl_client)
            dxl_client.connect()

            with MockVtService(dxl_client):

                result = vt_client.file_report(
                    SAMPLE_FILE,
                    all_info="Anything"
                )

                self.assertTrue(
                    result[RECEIVED_PARAMS_KEY][VirusTotalApiClient._PARAM_ALLINFO]
                )

                # Mock server always provides received params for this API call
                del result[RECEIVED_PARAMS_KEY]
                self.assertDictEqual(result, SAMPLE_FILE_REPORT)

            dxl_client.disconnect()


    def test_filerescan(self):
        with self.create_client(max_retries=0) as dxl_client:
            # Set up client, and register mock service
            vt_client = VirusTotalApiClient(dxl_client)
            dxl_client.connect()

            with MockVtService(dxl_client):

                result = vt_client.file_rescan(SAMPLE_FILE)

                # Mock server always provides received params for this API call
                del result[RECEIVED_PARAMS_KEY]
                self.assertDictEqual(result, SAMPLE_FILE_RESCAN)

            dxl_client.disconnect()


    def test_filerescan_params(self):
        with self.create_client(max_retries=0) as dxl_client:
            # Set up client, and register mock service
            vt_client = VirusTotalApiClient(dxl_client)
            dxl_client.connect()

            with MockVtService(dxl_client):

                sample_period = "Sample Period"
                sample_repeat = "Sample Repeat"
                sample_notifyurl = "http://www.notifyurl.com"

                result = vt_client.file_rescan(
                    SAMPLE_FILE,
                    date=SAMPLE_DATE,
                    period=sample_period,
                    repeat=sample_repeat,
                    notify_url=sample_notifyurl,
                    notify_changes_only="Anything"
                )

                self.assertEqual(
                    result[RECEIVED_PARAMS_KEY][VirusTotalApiClient._PARAM_DATE],
                    SAMPLE_DATE.strftime("%Y%m%d%H%M%S")
                )
                self.assertEqual(
                    result[RECEIVED_PARAMS_KEY][VirusTotalApiClient._PARAM_PERIOD],
                    sample_period
                )
                self.assertEqual(
                    result[RECEIVED_PARAMS_KEY][VirusTotalApiClient._PARAM_REPEAT],
                    sample_repeat
                )
                self.assertEqual(
                    result[RECEIVED_PARAMS_KEY][VirusTotalApiClient._PARAM_NOTIFY_URL],
                    sample_notifyurl
                )
                self.assertTrue(
                    result[RECEIVED_PARAMS_KEY][VirusTotalApiClient._PARAM_NOTIFY_CHANGES_ONLY]
                )

                # Mock server always provides received params for this API call
                del result[RECEIVED_PARAMS_KEY]
                self.assertDictEqual(result, SAMPLE_FILE_RESCAN)

            dxl_client.disconnect()


    def test_ipreport(self):
        with self.create_client(max_retries=0) as dxl_client:
            # Set up client, and register mock service
            vt_client = VirusTotalApiClient(dxl_client)
            dxl_client.connect()

            with MockVtService(dxl_client):

                result = vt_client.ip_report(SAMPLE_IP)

                self.assertDictEqual(result, SAMPLE_IP_ADDRESS_REPORT)

            dxl_client.disconnect()


    def test_urlreport(self):
        with self.create_client(max_retries=0) as dxl_client:
            # Set up client, and register mock service
            vt_client = VirusTotalApiClient(dxl_client)
            dxl_client.connect()

            with MockVtService(dxl_client):
                result = vt_client.url_report(SAMPLE_URL)

                # Mock server always provides received params for this API call
                del result[RECEIVED_PARAMS_KEY]
                self.assertDictEqual(result, SAMPLE_URL_REPORT)

            dxl_client.disconnect()


    def test_urlreport_params(self):
        with self.create_client(max_retries=0) as dxl_client:
            # Set up client, and register mock service
            vt_client = VirusTotalApiClient(dxl_client)
            dxl_client.connect()

            with MockVtService(dxl_client):
                result = vt_client.url_report(
                    SAMPLE_URL,
                    scan="Anything",
                    all_info="Anything"
                )

                self.assertTrue(
                    result[RECEIVED_PARAMS_KEY][VirusTotalApiClient._PARAM_SCAN]
                )

                self.assertTrue(
                    result[RECEIVED_PARAMS_KEY][VirusTotalApiClient._PARAM_ALLINFO]
                )

                # Mock server always provides received params for this API call
                del result[RECEIVED_PARAMS_KEY]
                self.assertDictEqual(result, SAMPLE_URL_REPORT)

            dxl_client.disconnect()


    def test_urlscan(self):
        with self.create_client(max_retries=0) as dxl_client:
            # Set up client, and register mock service
            vt_client = VirusTotalApiClient(dxl_client)
            dxl_client.connect()

            with MockVtService(dxl_client):

                result = vt_client.url_scan(SAMPLE_URL)

                self.assertDictEqual(result, SAMPLE_URL_SCAN)

            dxl_client.disconnect()


class TestAddParams(BaseClientTest):
    def test_addparam_date(self):
        sample_dict = {'date': None}
        sample_date = SAMPLE_DATE
        VirusTotalApiClient._add_date_param(sample_dict, sample_date)

        self.assertEqual(
            sample_dict['date'],
            sample_date.strftime("%Y%m%d%H%M%S")
        )


    def test_addparam_url(self):
        sample_dict = {'test': ""}
        test_url = 'http://www.test.com'
        VirusTotalApiClient._add_url_param(sample_dict, test_url, 'test')
        self.assertEqual(sample_dict['test'], test_url)

        test_url_list = [
            'http://www.verify.com',
            'http://www.evaluate.com',
            'http://www.examine.com'
        ]

        VirusTotalApiClient._add_url_param(sample_dict, test_url_list, 'test')
        for url in test_url_list:
            self.assertIn(url, sample_dict['test'])


    def test_addparam_allinfo(self):
        sample_dict = {'test': None}

        VirusTotalApiClient._add_all_info_param(
            sample_dict,
            "Anything",
        )
        self.assertEqual(sample_dict[VirusTotalApiClient._PARAM_ALLINFO], "1")


    def test_addparam_notifychangesonly(self):
        sample_dict = {'test': None}

        VirusTotalApiClient._add_notify_changes_only_param(
            sample_dict,
            "Anything",
        )
        self.assertEqual(sample_dict[VirusTotalApiClient._PARAM_NOTIFY_CHANGES_ONLY], "1")


    def test_addparam_period(self):
        sample_dict = {'test': None}

        test_period = "Test Period"

        VirusTotalApiClient._add_period_param(
            sample_dict,
            test_period
        )
        self.assertEqual(sample_dict[VirusTotalApiClient._PARAM_PERIOD], test_period)


    def test_addparam_repeat(self):
        sample_dict = {'test': None}

        test_repeat = "Test Repeat"

        VirusTotalApiClient._add_repeat_param(
            sample_dict,
            test_repeat
        )
        self.assertEqual(sample_dict[VirusTotalApiClient._PARAM_REPEAT], test_repeat)


    def test_addparam_notifyurl(self):
        sample_dict = {'test': None}

        test_notify_url = "http://www.notifyurl.com"

        VirusTotalApiClient._add_notify_url_param(
            sample_dict,
            test_notify_url
        )
        self.assertEqual(sample_dict[VirusTotalApiClient._PARAM_NOTIFY_URL], test_notify_url)


    def test_addparam_scan(self):
        sample_dict = {'test': None}

        VirusTotalApiClient._add_scan_param(
            sample_dict,
            "Anything",
        )
        self.assertTrue(sample_dict[VirusTotalApiClient._PARAM_SCAN])


    def test_addparam_domain(self):
        sample_dict = {'test': None}

        test_domain = "testdomain.com"

        VirusTotalApiClient._add_domain_param(
            sample_dict,
            test_domain
        )
        self.assertEqual(sample_dict[VirusTotalApiClient._PARAM_DOMAIN], test_domain)


    def test_addparambyname_date(self):
        sample_dict = {'date': None}
        sample_date = SAMPLE_DATE
        VirusTotalApiClient._add_date_param_by_name(sample_dict, 'date', sample_date)

        self.assertEqual(
            sample_dict['date'],
            sample_date.strftime("%Y%m%d%H%M%S")
        )


    def test_addparambyname_bool_dne(self):
        sample_dict = {'test': None}
        VirusTotalApiClient._add_boolean_param_by_name(sample_dict, 'does_not_exist', False)
        with self.assertRaises(KeyError):
            sample_dict['does_not_exist'] #pylint: disable=pointless-statement


    def test_addparambyname_boolfalse(self):
        sample_dict = {'test': None}
        VirusTotalApiClient._add_boolean_param_by_name(sample_dict, 'test', False)
        self.assertIsNone(sample_dict['test'])


    def test_addparambyname_bool(self):
        sample_dict = {'test': None}
        VirusTotalApiClient._add_boolean_param_by_name(sample_dict, 'test', True)
        self.assertEqual(sample_dict['test'], "1")


    def test_addparambyname_string_dne(self):
        sample_dict = {'test': None}
        VirusTotalApiClient._add_string_param_by_name(sample_dict, 'does_not_exist', None)
        with self.assertRaises(KeyError):
            sample_dict['does_not_exist'] #pylint: disable=pointless-statement


    def test_addparambyname_string_null(self):
        sample_dict = {'test': 'unchanged'}
        VirusTotalApiClient._add_string_param_by_name(sample_dict, 'test', None)
        self.assertEqual(sample_dict['test'], "unchanged")


    def test_addparambyname_string(self):
        sample_dict = {'test': 'unchanged'}
        VirusTotalApiClient._add_string_param_by_name(sample_dict, 'test', "updated")
        self.assertEqual(sample_dict['test'], "updated")


    def test_addparambyname_resource(self):
        sample_dict = {VirusTotalApiClient._PARAM_RESOURCE: ""}
        VirusTotalApiClient._add_resource_param(sample_dict, ['1', '2', '3', '4'])
        self.assertEqual(
            sample_dict[VirusTotalApiClient._PARAM_RESOURCE],
            '1,2,3,4'
        )

from tests.test_base import *
from tests.test_value_constants import *
from tests.mock_vtservice import MockVtService

class TestSamples(BaseClientTest):

    def test_basicdomainreport_example(self):
        # Modify sample file to include necessary sample data
        sample_filename = self.BASIC_FOLDER + "/basic_domain_report_example.py"

        with self.create_client(max_retries=0) as dxl_client:
            # Set up client, and register mock service
            dxl_client.connect()

            with MockVtService(dxl_client):
                mock_print = self.run_sample(sample_filename)

                mock_print.assert_any_call(
                    StringDoesNotContain("Error")
                )

                # Validate whois_timestamp from report
                mock_print.assert_any_call(
                    StringContains(
                        str(SAMPLE_DOMAIN_REPORT["whois_timestamp"])
                    )
                )

            dxl_client.disconnect()


    def test_basicfilereport_example(self):
        # Modify sample file to include necessary sample data
        sample_filename = self.BASIC_FOLDER + "/basic_file_report_example.py"

        with self.create_client(max_retries=0) as dxl_client:
            # Set up client, and register mock service
            dxl_client.connect()

            with MockVtService(dxl_client):
                mock_print = self.run_sample(sample_filename)

                mock_print.assert_any_call(
                    StringDoesNotContain("Error")
                )

                # Validate md5 from report
                mock_print.assert_any_call(
                    StringContains(
                        str(SAMPLE_FILE_REPORT["md5"])
                    )
                )

            dxl_client.disconnect()


    def test_basicfilerescan_example(self):
        # Modify sample file to include necessary sample data
        sample_filename = self.BASIC_FOLDER + "/basic_file_rescan_example.py"

        with self.create_client(max_retries=0) as dxl_client:
            # Set up client, and register mock service
            dxl_client.connect()

            with MockVtService(dxl_client):
                mock_print = self.run_sample(sample_filename)

                mock_print.assert_any_call(
                    StringDoesNotContain("Error")
                )

                # Validate scan_id from report
                mock_print.assert_any_call(
                    StringContains(
                        str(SAMPLE_FILE_RESCAN["scan_id"])
                    )
                )

            dxl_client.disconnect()


    def test_basicipreport_example(self):
        # Modify sample file to include necessary sample data
        sample_filename = self.BASIC_FOLDER + "/basic_ip_address_report_example.py"

        with self.create_client(max_retries=0) as dxl_client:
            # Set up client, and register mock service
            dxl_client.connect()

            with MockVtService(dxl_client):
                mock_print = self.run_sample(sample_filename)

                mock_print.assert_any_call(
                    StringDoesNotContain("Error")
                )

                # Validate asn from report
                mock_print.assert_any_call(
                    StringContains(
                        str(SAMPLE_IP_ADDRESS_REPORT["asn"])
                    )
                )

            dxl_client.disconnect()


    def test_basicurlreport_example(self):
        # Modify sample file to include necessary sample data
        sample_filename = self.BASIC_FOLDER + "/basic_url_report_example.py"

        with self.create_client(max_retries=0) as dxl_client:
            # Set up client, and register mock service
            dxl_client.connect()

            with MockVtService(dxl_client):
                mock_print = self.run_sample(sample_filename)

                mock_print.assert_any_call(
                    StringDoesNotContain("Error")
                )

                # Validate scan_id from report
                mock_print.assert_any_call(
                    StringContains(
                        str(SAMPLE_URL_REPORT["scan_id"])
                    )
                )

            dxl_client.disconnect()


    def test_basicurlscan_example(self):
        # Modify sample file to include necessary sample data
        sample_filename = self.BASIC_FOLDER + "/basic_url_scan_example.py"

        with self.create_client(max_retries=0) as dxl_client:
            # Set up client, and register mock service
            dxl_client.connect()

            with MockVtService(dxl_client):
                mock_print = self.run_sample(sample_filename)

                mock_print.assert_any_call(
                    StringDoesNotContain("Error")
                )

                # Validate scan_id from report
                mock_print.assert_any_call(
                    StringContains(
                        str(SAMPLE_URL_SCAN["scan_id"])
                    )
                )

            dxl_client.disconnect()

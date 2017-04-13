Basic Domain Report Example
===========================

This sample invokes and displays the results of a VirusTotal "domain report" via DXL.

For more information see:
    https://www.virustotal.com/en/documentation/public-api/#getting-domain-reports

Prerequisites
*************
* The samples configuration step has been completed (see :doc:`sampleconfig`)
* The VirusTotal API DXL service is running and available on the DXL fabric (see `VirusTotal API DXL Service <https://github.com/opendxl/opendxl-virustotal-service-python>`_)

Running
*******

To run this sample execute the ``sample/basic/basic_domain_report_example.py`` script as follows:

    .. parsed-literal::

        python sample/basic/basic_domain_report_example.py

The output should appear similar to the following:

    .. code-block:: python

        {
            "BitDefender category": "parked",
            "Dr.Web category": "known infection source",
            "Websense ThreatSeeker category": "uncategorized",
            "Webutation domain info": {
                "Adult content": "yes",
                "Safety score": 40,
                "Verdict": "malicious"
            },
            "categories": [
                "parked",
                "uncategorized"
            ],
            "detected_downloaded_samples": [
                {
                    "date": "2013-06-20 18:51:30",
                    "positives": 2,
                    "sha256": "cd8553d9b24574467f381d13c7e0e1eb1e58d677b9484bd05b9c690377813e54",
                    "total": 46
                }
            ],
            "detected_urls": [
                {
                    "positives": 1,
                    "scan_date": "2017-03-31 00:16:29",
                    "total": 64,
                    "url": "http://027.ru/"
                },

                ...

                {
                    "positives": 2,
                    "scan_date": "2015-02-18 08:54:52",
                    "total": 62,
                    "url": "http://027.ru/index.html"
                }
            ],
            "domain_siblings": [],
            "resolutions": [
                {
                    "ip_address": "185.53.177.31",
                    "last_resolved": "2017-02-02 00:00:00"
                },

                ...

                {
                    "ip_address": "90.156.201.97",
                    "last_resolved": "2013-06-20 00:00:00"
                }
            ],
            "response_code": 1,
            "subdomains": [
                "www.027.ru"
            ],
            "undetected_referrer_samples": [
                {
                    "positives": 0,
                    "sha256": "b8f5db667431d02291eeec61cf9f0c3d7af00798d0c2d676fde0efb0cedb7741",
                    "total": 53
                }
            ],

            ...
        }


The received results are displayed.

Details
*******

The majority of the sample code is shown below:

    .. code-block:: python

        # Create the client
        with DxlClient(config) as dxl_client:

            # Connect to the fabric
            dxl_client.connect()

            logger.info("Connected to DXL fabric.")

            # Create client wrapper
            client = VirusTotalApiClient(dxl_client)

            # Invoke 'domain report' method on service
            resp_dict = client.domain_report("027.ru")

            # Print out the response (convert dictionary to JSON for pretty printing)
            print "Response:\n{0}".format(
                MessageUtils.dict_to_json(resp_dict, pretty_print=True))


Once a connection is established to the DXL fabric, a :class:`dxlvtapiclient.client.VirusTotalApiClient` instance is
created which will be used to invoke remote commands on the VirusTotal API DXL service.

Next, the :func:`dxlvtapiclient.client.VirusTotalApiClient.domain_report` method is invoked with the domain to
report on.

The final step is to display the contents of the returned dictionary (``dict``) which contains the results of the
domain report.


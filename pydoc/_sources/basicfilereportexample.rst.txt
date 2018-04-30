Basic File Report Example
=========================

This sample invokes and displays the results of a VirusTotal "file report" via DXL.

For more information see:
    https://www.virustotal.com/en/documentation/public-api/#getting-file-scans

Prerequisites
*************
* The samples configuration step has been completed (see :doc:`sampleconfig`)
* The VirusTotal API DXL service is running and available on the DXL fabric (see `VirusTotal API DXL Service <https://github.com/opendxl/opendxl-virustotal-service-python>`_)

Running
*******

To run this sample execute the ``sample/basic/basic_file_report_example.py`` script as follows:

    .. parsed-literal::

        python sample/basic/basic_file_report_example.py

The output should appear similar to the following:

    .. code-block:: python

        {
            "md5": "7657fcb7d772448a6d8504e4b20168b8",
            "permalink": "https://www.virustotal.com/file/54bc950d46a0d1aa72048a17c8275743209e6c17bdacfc4cb9601c9ce3ec9a71/analysis/1491516000/",
            "positives": 61,
            "resource": "7657fcb7d772448a6d8504e4b20168b8",
            "response_code": 1,
            "scan_date": "2017-04-06 22:00:00",
            "scan_id": "54bc950d46a0d1aa72048a17c8275743209e6c17bdacfc4cb9601c9ce3ec9a71-1491516000",
            "scans": {
                "ALYac": {
                    "detected": true,
                    "result": "Gen:Variant.Kazy.8782",
                    "update": "20170406",
                    "version": "1.0.1.9"
                },
                "AVG": {
                    "detected": true,
                    "result": "SHeur3.BNDF",
                    "update": "20170406",
                    "version": "16.0.0.4769"
                },

                ...

                "nProtect": {
                    "detected": true,
                    "result": "Trojan-Spy/W32.ZBot.109056.AR",
                    "update": "20170406",
                    "version": "2017-04-06.02"
                }
            },
            "sha1": "84c7201f7e59cb416280fd69a2e7f2e349ec8242",
            "sha256": "54bc950d46a0d1aa72048a17c8275743209e6c17bdacfc4cb9601c9ce3ec9a71",
            "total": 62,
            "verbose_msg": "Scan finished, information embedded"
        }

The scan results from the various providers are listed.

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

            # Invoke 'file report' method on service
            resp_dict = client.file_report("7657fcb7d772448a6d8504e4b20168b8")

            # Print out the response (convert dictionary to JSON for pretty printing)
            print("Response:\n{0}".format(
                MessageUtils.dict_to_json(resp_dict, pretty_print=True)))


Once a connection is established to the DXL fabric, a :class:`dxlvtapiclient.client.VirusTotalApiClient` instance is
created which will be used to invoke remote commands on the VirusTotal API DXL service.

Next, the :func:`dxlvtapiclient.client.VirusTotalApiClient.file_report` method is invoked with the resource to
report on (in this case, an MD5 hash).

The final step is to display the contents of the returned dictionary (``dict``) which contains the results of the
file report.


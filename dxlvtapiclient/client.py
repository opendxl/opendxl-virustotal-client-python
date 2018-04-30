from __future__ import absolute_import
from datetime import datetime
from dxlclient.message import Request
from dxlbootstrap.util import MessageUtils
from dxlbootstrap.client import Client


class VirusTotalApiClient(Client):
    """
    The VirusTotal DXL Python client library provides a high level wrapper for
    invoking the VirusTotal API via the Data Exchange Layer (DXL) fabric.
    """

    #: The DXL service type for the VirusTotal API
    _SERVICE_TYPE = "/opendxl-virustotal/service/vtapi"

    #: The "file rescan" DXL request topic
    _REQ_TOPIC_FILE_RESCAN = "{0}/file/rescan".format(_SERVICE_TYPE)
    #: The "file report" DXL request topic
    _REQ_TOPIC_FILE_REPORT = "{0}/file/report".format(_SERVICE_TYPE)
    #: The "url scan" DXL request topic
    _REQ_TOPIC_URL_SCAN = "{0}/url/scan".format(_SERVICE_TYPE)
    #: The "url report" DXL request topic
    _REQ_TOPIC_URL_REPORT = "{0}/url/report".format(_SERVICE_TYPE)
    #: The "ip address report" DXL request topic
    _REQ_TOPIC_IP_ADDRESS_REPORT = "{0}/ip-address/report".format(_SERVICE_TYPE)
    #: The "domain report" DXL request topic
    _REQ_TOPIC_DOMAIN_REPORT = "{0}/domain/report".format(_SERVICE_TYPE)

    #: The resource request parameter
    _PARAM_RESOURCE = "resource"
    #: The URL request parameter
    _PARAM_URL = "url"
    #: The IP address request parameter
    _PARAM_IP = "ip"
    #: The domain request parameter
    _PARAM_DOMAIN = "domain"
    #: The all info request parameter
    _PARAM_ALLINFO = "allinfo"
    #: The period request parameter
    _PARAM_PERIOD = "period"
    #: The repeat request parameter
    _PARAM_REPEAT = "repeat"
    #: The notify url request parameter
    _PARAM_NOTIFY_URL = "notify_url"
    #: The notify changes only request parameter
    _PARAM_NOTIFY_CHANGES_ONLY = "notify_changes_only"
    #: The date request parameter
    _PARAM_DATE = "date"
    #: The scan request parameter
    _PARAM_SCAN = "scan"

    @staticmethod
    def _add_date_param_by_name(req_dict, param_name, param_value):
        """
        Adds the specified date parameter to the dictionary

        :param req_dict: The dictionary
        :param param_name: The name of the parameter
        :param param_value: The value for the parameter
        """
        if param_value:
            req_dict[param_name] = param_value.strftime("%Y%m%d%H%M%S") \
                    if isinstance(param_value, datetime) else param_value

    @staticmethod
    def _add_boolean_param_by_name(req_dict, param_name, param_value):
        """
        Adds the specified boolean parameter to the dictionary

        :param req_dict: The dictionary
        :param param_name: The name of the parameter
        :param param_value: The value for the parameter
        """
        if param_value:
            req_dict[param_name] = "1"

    @staticmethod
    def _add_string_param_by_name(req_dict, param_name, param_value):
        """
        Adds the specified string parameter to the dictionary

        :param req_dict: The dictionary
        :param param_name: The name of the parameter
        :param param_value: The value for the parameter
        """
        if param_value:
            req_dict[param_name] = str(param_value)

    @staticmethod
    def _add_resource_param(req_dict, resource):
        """
        Adds the specified resource parameter to the dictionary

        :param req_dict: The dictionary
        :param resource: The resource value
        """
        req_dict[VirusTotalApiClient._PARAM_RESOURCE] = \
            ",".join(resource) if isinstance(resource, list) else resource

    @staticmethod
    def _add_url_param(req_dict, url, param_name=_PARAM_URL):
        """
        Adds the specified URL parameter to the dictionary

        :param req_dict: The dictionary
        :param url: The URL value
        :param param_name: The name for the parameter
        """
        req_dict[param_name] = \
            "\n".join(url) if isinstance(url, list) else url

    @staticmethod
    def _add_all_info_param(req_dict, all_info):
        """
        Adds the specified all info parameter to the dictionary

        :param req_dict: The dictionary
        :param all_info: The all info value
        """
        VirusTotalApiClient._add_boolean_param_by_name(
            req_dict, VirusTotalApiClient._PARAM_ALLINFO, all_info)

    @staticmethod
    def _add_notify_changes_only_param(req_dict, notify_changes_only):
        """
        Adds the specified notify changes only parameter to the dictionary

        :param req_dict: The dictionary
        :param notify_changes_only: The notify changes only value
        """
        VirusTotalApiClient._add_boolean_param_by_name(
            req_dict, VirusTotalApiClient._PARAM_NOTIFY_CHANGES_ONLY,
            notify_changes_only)

    @staticmethod
    def _add_period_param(req_dict, period):
        """
        Adds the specified period parameter to the dictionary

        :param req_dict: The dictionary
        :param period: The period value
        """
        VirusTotalApiClient._add_string_param_by_name(
            req_dict, VirusTotalApiClient._PARAM_PERIOD, period)

    @staticmethod
    def _add_repeat_param(req_dict, repeat):
        """
        """
        VirusTotalApiClient._add_string_param_by_name(
            req_dict, VirusTotalApiClient._PARAM_REPEAT, repeat)

    @staticmethod
    def _add_notify_url_param(req_dict, notify_url):
        """
        Adds the specified notify URL parameter to the dictionary

        :param req_dict: The dictionary
        :param notify_url: The notify URL value
        """
        VirusTotalApiClient._add_string_param_by_name(
            req_dict, VirusTotalApiClient._PARAM_NOTIFY_URL, notify_url)

    @staticmethod
    def _add_date_param(req_dict, date):
        """
        Adds the specified date parameter to the dictionary

        :param req_dict: The dictionary
        :param date: The date value
        """
        VirusTotalApiClient._add_date_param_by_name(
            req_dict, VirusTotalApiClient._PARAM_DATE, date)

    @staticmethod
    def _add_scan_param(req_dict, scan):
        """
        Adds the specified scan parameter to the dictionary

        :param req_dict: The dictionary
        :param scan: The scan value
        """
        VirusTotalApiClient._add_boolean_param_by_name(
            req_dict, VirusTotalApiClient._PARAM_SCAN, scan)

    @staticmethod
    def _add_ip_param(req_dict, ip): # pylint: disable=invalid-name
        """
        Adds the specified ip parameter to the dictionary

        :param req_dict: The dictionary
        :param ip: The ip value
        """
        VirusTotalApiClient._add_string_param_by_name(
            req_dict, VirusTotalApiClient._PARAM_IP, ip)

    @staticmethod
    def _add_domain_param(req_dict, domain):
        """
        Adds the specified domain parameter to the dictionary

        :param req_dict: The dictionary
        :param domain: The domain value
        """
        VirusTotalApiClient._add_string_param_by_name(
            req_dict, VirusTotalApiClient._PARAM_DOMAIN, domain)

    def _invoke_service(self, req_dict, topic):
        """
        Invokes the VirusTotal DXL service.

        :param req_dict: Dictionary containing request information
        :param topic: The VirusTotal DXL topic to invoke
        :return: A dictionary containing the response
        """

        # Create the DXL request message
        request = Request(topic)

        # Set the payload on the request message (Python dictionary to JSON payload)
        MessageUtils.dict_to_json_payload(request, req_dict)

        # Perform a synchronous DXL request
        response = self._dxl_sync_request(request)

        # Convert the JSON payload in the DXL response message to a Python dictionary
        # and return it.
        return MessageUtils.json_payload_to_dict(response)

    def file_report(self, resource, all_info=None):
        """
        Retrieves an existing file scan report for the specified file(s). See
        `this page <https://github.com/opendxl/opendxl-virustotal-service-python/wiki/Service-Methods#file-report>`__
        for more information.

        :param resource: An md5/sha1/sha256 hash of a file for which to retrieve
            the most recent antivirus report. A scan identifier
            (sha256-timestamp as returned by the scan API) can be specified to
            access a specific report. Multiple hashes/identifiers can be
            specified via a Python ``list``.
        :param all_info: [``private api`` ``optional``] : Specifying ``True``
            will cause additional information to be included with the response
            (This includes the output of several tools acting on the file).
        :return: Returns a dictionary (``dict``) containing the response
            information. See
            `this page <https://github.com/opendxl/opendxl-virustotal-service-python/wiki/Service-Methods#file-report>`__
            for more information.
        """
        req_dict = {}
        self._add_resource_param(req_dict, resource)
        self._add_all_info_param(req_dict, all_info)

        return self._invoke_service(req_dict, self._REQ_TOPIC_FILE_REPORT)

    def file_rescan(self, resource, date=None, period=None, repeat=None,
                    notify_url=None, notify_changes_only=None):
        """
        Rescans existing files in VirusTotal's file store without resubmitting them. See `this page <https://github.com/opendxl/opendxl-virustotal-service-python/wiki/Service-Methods#file-rescan>`__
        for more information.

        :param resource: An md5/sha1/sha256 hash. Multiple hashes can be
            specified via a Python ``list``.
        :param date: [``private api`` ``optional``] : When the rescan should be
            performed. If not specified the rescan will be performed immediately.
            This can be specified as a ``datetime.datetime`` value or as a string.
            If specified as a string, the date must be specified using the
            ``%Y%m%d%H%M%S`` format (For example: ``20120725170000``).
        :param period: [``private api`` ``optional``] : Periodicity (in days)
            with which the file should be rescanned. If this argument is
            provided the file will be rescanned periodically every period days,
            if not, the rescan is performed once and not repeated again.
        :param repeat: [``private api`` ``optional``] : Used in conjunction with
            period to specify the number of times the file should be rescanned.
            If this argument is provided the file will be rescanned the given
            amount of times in coherence with the chosen periodicity, if not,
            the file will be rescanned indefinitely.
        :param notify_url: [``private api`` ``optional``] : A URL to which a
            POST notification should be sent when the rescan finishes.
        :param notify_changes_only: [``private api`` ``optional``] : Used in
            conjunction with ``notify_url``. Specifying ``True`` indicates that
            POST notifications should only be sent if the scan results differ
            from the previous one.
        :return: Returns a dictionary (``dict``) containing the response
            information. See `this page
            <https://github.com/opendxl/opendxl-virustotal-service-python/wiki/Service-Methods#file-rescan>`__
            for more information.
        """
        req_dict = {}
        self._add_resource_param(req_dict, resource)
        self._add_date_param(req_dict, date)
        self._add_period_param(req_dict, period)
        self._add_repeat_param(req_dict, repeat)
        self._add_notify_url_param(req_dict, notify_url)
        self._add_notify_changes_only_param(req_dict, notify_changes_only)

        return self._invoke_service(req_dict, self._REQ_TOPIC_FILE_RESCAN)

    def url_report(self, resource, scan=None, all_info=None):
        """
        Retrieves an existing scan report for the specified URL(s). See
        `this page <https://github.com/opendxl/opendxl-virustotal-service-python/wiki/Service-Methods#url-report>`_
        for more information.

        :param resource: Retrieves the most recent report for the specified URL.
            A scan identifier (sha256-timestamp as returned by the URL submission
            API) can be specified to access a specific report. Multiple
            URLs/identifiers can be specified via a Python ``list``.
        :param scan: [``optional``] : Specifying ``True`` will automatically
            submit the URL for analysis if no report is found for it in the
            VirusTotal database. In this case the result will contain a ``scan_id``
            field that can be used to query the analysis report later on.
        :param all_info: [``private api`` ``optional``] : Specifying ``True``
            will cause additional information to be included with the response (This
            includes the output of several tools acting on the URL).
        :return: Returns a dictionary (``dict``) containing the response
            information. See
            `this page <https://github.com/opendxl/opendxl-virustotal-service-python/wiki/Service-Methods#url-report>`__
            for more information.
        """
        req_dict = {}
        self._add_url_param(req_dict, resource, param_name=self._PARAM_RESOURCE)
        self._add_scan_param(req_dict, scan)
        self._add_all_info_param(req_dict, all_info)

        return self._invoke_service(req_dict, self._REQ_TOPIC_URL_REPORT)

    def url_scan(self, url):
        """
        Submits a URL for scanning. See
        `this page <https://github.com/opendxl/opendxl-virustotal-service-python/wiki/Service-Methods#url-scan>`__
        for more information.

        :param url: The URL to be scanned. Multiple URLs can be specified via a
            Python ``list``.
        :return: Returns a dictionary (``dict``) containing the response
            information. See
            `this page <https://github.com/opendxl/opendxl-virustotal-service-python/wiki/Service-Methods#url-scan>`__
            for more information.
        """
        req_dict = {}
        self._add_url_param(req_dict, url)

        return self._invoke_service(req_dict, self._REQ_TOPIC_URL_SCAN)

    def ip_report(self, ip): # pylint: disable=invalid-name
        """
        Retrieves a report on the specified IP address. See
        `this page <https://github.com/opendxl/opendxl-virustotal-service-python/wiki/Service-Methods#ip-address-report>`__
        for more information.

        :param ip: A valid IPv4 address in dotted quad notation.
        :return: Returns a dictionary (``dict``) containing the response
            information. See
            `this page <https://github.com/opendxl/opendxl-virustotal-service-python/wiki/Service-Methods#ip-address-report>`__
            for more information.
        """
        req_dict = {}
        self._add_ip_param(req_dict, ip)

        return self._invoke_service(req_dict, self._REQ_TOPIC_IP_ADDRESS_REPORT)

    def domain_report(self, domain):
        """
        Retrieves a report on the specified domain. See `this page
        <https://github.com/opendxl/opendxl-virustotal-service-python/wiki/Service-Methods#domain-report>`__
        for more information.

        :param domain: A domain name.
        :return: Returns a dictionary (``dict``) containing the response
            information. See
            `this page <https://github.com/opendxl/opendxl-virustotal-service-python/wiki/Service-Methods#domain-report>`__
            for more information.
        """
        req_dict = {}
        self._add_domain_param(req_dict, domain)

        return self._invoke_service(req_dict, self._REQ_TOPIC_DOMAIN_REPORT)

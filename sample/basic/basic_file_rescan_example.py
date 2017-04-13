# This sample invokes and displays the results of a VirusTotal "file rescan" via DXL.
#
# See: https://www.virustotal.com/en/documentation/public-api/#rescanning-files

import os
import sys

from dxlbootstrap.util import MessageUtils
from dxlclient.client_config import DxlClientConfig
from dxlclient.client import DxlClient

root_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(root_dir + "/../..")
sys.path.append(root_dir + "/..")

from dxlvtapiclient.client import VirusTotalApiClient

# Import common logging and configuration
from common import *

# Configure local logger
logging.getLogger().setLevel(logging.ERROR)
logger = logging.getLogger(__name__)

# Create DXL configuration from file
config = DxlClientConfig.create_dxl_config_from_file(CONFIG_FILE)

# Create the client
with DxlClient(config) as dxl_client:

    # Connect to the fabric
    dxl_client.connect()

    logger.info("Connected to DXL fabric.")

    # Create client wrapper
    client = VirusTotalApiClient(dxl_client)

    # Invoke 'file rescan' method on service
    resp_dict = client.file_rescan("7657fcb7d772448a6d8504e4b20168b8")

    # Print out the response (convert dictionary to JSON for pretty printing)
    print "Response:\n{0}".format(
        MessageUtils.dict_to_json(resp_dict, pretty_print=True))

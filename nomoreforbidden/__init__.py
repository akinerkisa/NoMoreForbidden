
import urllib3

from nomoreforbidden._version import VERSION

# The tool intentionally disables TLS verification for authorized lab and
# proxy/WAF behavior testing. Suppress only the warning caused by that choice;
# unrelated urllib3 warnings must remain visible to operators.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

__version__ = VERSION

BANNER = (
    ".__   __. .___  ___.  _______\n"
    "|  \\\\ |  | |   \\/   | |   ____|\n"
    "|   \\\\|  | |  \\\\  /  | |  |__\n"
    "|  . `  | |  |\\/|  | |   __|\n"
    "|  |\\\\   | |  |  |  | |  |\n"
    f"|__| \\\\__| |__|  |__| |__|     v{VERSION} github.com/akinerkisa/nomoreforbidden\n"
)

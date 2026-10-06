import argparse


class CustomFormatter(argparse.HelpFormatter):
    def _format_action_invocation(self, action: argparse.Action) -> str:
        if not action.option_strings:
            return super()._format_action_invocation(action)

        return ", ".join(action.option_strings)


def download_parse_args():
    parser = argparse.ArgumentParser(
        prog="download", formatter_class=CustomFormatter
    )
    parser.add_argument(
        "-v", "--verbose", action="count", default=0,
        help="increase output verbosity"
    )
    parser.add_argument(
        "-q", "--quiet", action="count", default=0,
        help="decrease output verbosity"
    )
    parser.add_argument(
        "-H", "--host", default="10.0.0.1",
        help="server IP address"
    )
    parser.add_argument(
        "-p", "--port", type=int, default=12345,
        help="server port"
    )
    parser.add_argument(
        "-d", "--dst", metavar="FILEPATH",
        help="destination file path"
    )
    parser.add_argument(
        "-n", "--name", required=True, metavar="FILENAME",
        help="file name"
    )
    parser.add_argument(
        "-r", "--protocol",
        default="stop-and-wait",
        metavar="PROTOCOL",
        choices=["stop-and-wait", "sack"],
        help="error recovery protocol",
    )
    return parser.parse_args()


def upload_parse_args():
    parser = argparse.ArgumentParser(
        prog="upload", formatter_class=CustomFormatter
    )
    parser.add_argument(
        "-v", "--verbose", action="count", default=0,
        help="increase output verbosity"
    )
    parser.add_argument(
        "-q", "--quiet", action="count", default=0,
        help="decrease output verbosity"
    )
    parser.add_argument(
        "-H", "--host", default="10.0.0.1",
        help="server IP address"
    )
    parser.add_argument(
        "-p", "--port", type=int, default=12345,
        help="server port"
    )
    parser.add_argument(
        "-s", "--src", required=True, metavar="FILEPATH",
        help="source file path"
    )
    parser.add_argument(
        "-n", "--name", metavar="FILENAME",
        help="file name"
    )
    parser.add_argument(
        "-r", "--protocol",
        default="stop-and-wait",
        metavar="PROTOCOL",
        choices=["stop-and-wait", "sack"],
        help="error recovery protocol",
    )
    return parser.parse_args()


def server_parse_args():
    parser = argparse.ArgumentParser(
        prog="start-server", formatter_class=CustomFormatter
    )
    parser.add_argument(
        "-v", "--verbose", action="count", default=0,
        help="increase output verbosity"
    )
    parser.add_argument(
        "-q", "--quiet", action="count", default=0,
        help="decrease output verbosity"
    )
    parser.add_argument(
        "-H", "--host", default="10.0.0.1",
        help="server IP address"
    )
    parser.add_argument(
        "-p", "--port", type=int, default=12345,
        help="server port"
    )
    parser.add_argument(
        "-s", "--storage", required=True, metavar="DIRPATH",
        help="source file path"
    )
    return parser.parse_args()

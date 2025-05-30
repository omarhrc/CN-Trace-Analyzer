import unittest
import trace_visualizer
import os.path

import utils.plantuml
import utils.wireshark


class Test_wireshark(unittest.TestCase):
    def test_http2_from_wireshark_wiki(self):
        file_name = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'Sample of HTTP2.pcap')
        pdml_file = utils.wireshark.call_wireshark('3.1.0', file_name, '3000')
        output_puml_files = utils.wireshark.import_pdml(pdml_file)
        utils.plantuml.output_files_as_file(output_puml_files)


if __name__ == '__main__':
    unittest.main()

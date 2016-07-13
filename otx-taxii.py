import ConfigParser
import datetime
import sys

import certukingest
from OTXv2 import OTXv2
from StixExport import StixExport

binding = 'urn:stix.mitre.org:xml:1.1.1'

config = ConfigParser.ConfigParser()
config.read('config.cfg')


otx = OTXv2(config.get('otx', 'key'))


def saveTimestamp(timestamp=None):
    mtimestamp = timestamp
    if not timestamp:
        mtimestamp = datetime.datetime.now().isoformat()

    fname = "timestamp"
    f = open(fname, "w")
    f.write(mtimestamp)
    f.close()


def readTimestamp():
    fname = "timestamp"
    f = open(fname, "r")
    mtimestamp = f.read()
    f.close()
    return mtimestamp


def sendTAXII(first=True):
    if first:
        mtimestamp = None
    else:
        mtimestamp = readTimestamp()

    if first:
        for pulse in otx.getall_iter():
            if not mtimestamp:
                mtimestamp = pulse["modified"]
            st = StixExport(pulse)
            st.build()
                certukingest.inbox_package(
                    config.get('ingest', 'uri'), st.to_xml())
        saveTimestamp(mtimestamp)
    else:
        pulses = otx.getsince(mtimestamp)
        mtimestamp = None
        for pulse in pulses:
            if not mtimestamp:
                mtimestamp = pulse["modified"]
            st = StixExport(pulse)
            st.build()
            certukingest.inbox_package(
                config.get('ingest', 'uri'), st.to_xml())
        saveTimestamp(mtimestamp)
        print "%d new pulses" % len(pulses)


def usage():
    print "Usage:\n\totx-taxii.py [first_run|check_new]"
    sys.exit(0)

if __name__ == "__main__":
    try:
        op = sys.argv[1]
    except:
        usage()
    if op == "first_run":
        sendTAXII(True)
    elif op == "check_new":
        sendTAXII(None)
    else:
        usage()

"""
Builds a STIX Package from an AlienVault OTX Pulse.

The script will build a STIX package from a given pulse.
"""

from cybox.common import Hash, Time
from cybox.core import Observable
from cybox.objects.address_object import Address
from cybox.objects.domain_name_object import DomainName
from cybox.objects.file_object import File
from cybox.objects.mutex_object import Mutex
from cybox.objects.uri_object import URI
from stix.common import Identity, InformationSource
from stix.core import STIXHeader, STIXPackage
from stix.data_marking import Marking, MarkingSpecification
from stix.extensions.marking.simple_marking import SimpleMarkingStructure
from stix.extensions.marking.tlp import TLPMarkingStructure
from stix.indicator import Indicator
from stix.report import Header, Report
from stix.utils import set_id_namespace

PULSE_SERVER_BASE = "https://otx.alienvault.com/"
STIXNAMESPACE = {"https://otx.alienvault.com": "alienvault-otx"}
set_id_namespace(STIXNAMESPACE)
IDENTITY_NAME = "Alienvault OTX"


class StixExport(object):
    """Implementation of the STIX creation."""

    def __init__(self, pulse):
        """Define the STIX Package."""
        self.stix_package = STIXPackage()
        self.stix_header = STIXHeader()
        self.pulse = pulse
        self.hash_translation = {"FileHash-MD5": Hash.TYPE_MD5,
                                 "FileHash-SHA1": Hash.TYPE_SHA1,
                                 "FileHash-SHA256": Hash.TYPE_SHA256}
        self.address_translation = {
            "IPv4": Address.CAT_IPV4, "IPv6": Address.CAT_IPV6}
        self.name_translation = {
            "domain": URI.TYPE_DOMAIN, "hostname": URI.TYPE_DOMAIN}

    def _marking(self):
        """Define the TLP marking and the inheritance."""
        marking_specification = MarkingSpecification()
        tlp = TLPMarkingStructure()
        tlp.color = self.pulse["TLP"].upper()
        marking_specification.marking_structures.append(tlp)
        marking_specification.controlled_structure = "../../../../descendant-or-self::node() | ../../../../descendant-or-self::node()/@*"
        simple = SimpleMarkingStructure()
        simple.statement = "Automated ingest from AlienVault OTX."
        marking_specification.marking_structures.append(simple)
        handling = Marking()
        handling.add_marking(marking_specification)
        return handling

    def build(self):
        """Define the STIX report."""
        self.stix_header.title = self.pulse["name"]
        self.stix_header.description = self.pulse["description"]
        self.stix_header.package_intents = "Indicators"
        self.stix_header.information_source = InformationSource()
        self.stix_header.information_source.time = Time()
        self.stix_header.information_source.time.received_time = self.pulse[
            "modified"]
        self.stix_header.information_source.time.produced_time = self.stix_package.timestamp
        self.stix_header.information_source.identity = Identity()
        self.stix_header.information_source.identity.name = IDENTITY_NAME
        # self.stix_package.stix_header = self.stix_header
        # self.stix_package.stix_header.handling = self._marking()
        # self.report = Report()
        # self.report.header = Header()
        # self.report.header.title = self.pulse["name"]
        # self.report.header.descriptions = self.pulse["description"]
        # self.report.header.intents = "Indicators"
        # self.report.header.short_description = "%spulse/%s" % (
        #     PULSE_SERVER_BASE, str(self.pulse["id"]))
        # self.report.header.information_source = InformationSource()
        # self.report.header.information_source.time = Time()
        # self.report.header.information_source.time.received_time = self.pulse[
        #     "modified"]
        # self.report.header.information_source.time.produced_time = self.report.timestamp
        # self.report.header.information_source.identity = Identity()
        # self.report.header.information_source.identity.name = IDENTITY_NAME

        hashes = False
        addresses = False
        emails = False
        domains = False
        urls = False
        mutex = False

        hash_indicator = Indicator()
        hash_indicator.set_producer_identity(IDENTITY_NAME)
        hash_indicator.set_produced_time(hash_indicator.timestamp)
        hash_indicator.set_received_time(self.pulse["modified"])
        hash_indicator.title = "[OTX] [Files] " + self.pulse["name"]
        hash_indicator.add_indicator_type("File Hash Watchlist")
        hash_indicator.confidence = "Low"

        address_indicator = Indicator()
        address_indicator.set_producer_identity(IDENTITY_NAME)
        address_indicator.set_produced_time(address_indicator.timestamp)
        address_indicator.set_received_time(self.pulse["modified"])
        address_indicator.title = "[OTX] [IP] " + self.pulse["name"]
        address_indicator.add_indicator_type("IP Watchlist")
        address_indicator.confidence = "Low"

        domain_indicator = Indicator()
        domain_indicator.set_producer_identity(IDENTITY_NAME)
        domain_indicator.set_produced_time(domain_indicator.timestamp)
        domain_indicator.set_received_time(self.pulse["modified"])
        domain_indicator.title = "[OTX] [Domain] " + self.pulse["name"]
        domain_indicator.add_indicator_type("Domain Watchlist")
        domain_indicator.confidence = "Low"

        url_indicator = Indicator()
        url_indicator.set_producer_identity(IDENTITY_NAME)
        url_indicator.set_produced_time(url_indicator.timestamp)
        url_indicator.set_received_time(self.pulse["modified"])
        url_indicator.title = "[OTX] [URL] " + self.pulse["name"]
        url_indicator.add_indicator_type("URL Watchlist")
        url_indicator.confidence = "Low"

        email_indicator = Indicator()
        email_indicator.set_producer_identity(IDENTITY_NAME)
        email_indicator.set_produced_time(email_indicator.timestamp)
        email_indicator.set_received_time(self.pulse["modified"])
        email_indicator.title = "[OTX] [Email] " + self.pulse["name"]
        email_indicator.add_indicator_type("Malicious E-mail")
        email_indicator.confidence = "Low"

        mutex_indicator = Indicator()
        mutex_indicator.set_producer_identity(IDENTITY_NAME)
        mutex_indicator.set_produced_time(mutex_indicator.timestamp)
        mutex_indicator.set_received_time(self.pulse["modified"])
        mutex_indicator.title = "[OTX] [Mutex] " + self.pulse["name"]
        mutex_indicator.add_indicator_type("Malware Artifacts")
        mutex_indicator.confidence = "Low"

        for p_indicator in self.pulse["indicators"]:
            if p_indicator["type"] in self.hash_translation:
                file_object = File()
                file_object.add_hash(Hash(p_indicator["indicator"]))
                file_object.hashes[0].simple_hash_value.condition = "Equals"
                file_object.hashes[0].type_.condition = "Equals"
                file_obs = Observable(file_object)
                file_obs.title = "File: " + \
                    str(file_object.hashes[0].type_) + \
                    " - " + p_indicator["indicator"]
                hash_indicator.add_observable(file_obs)
                hash_indicator.description = p_indicator["description"]
                hashes = True

            elif p_indicator["type"] in self.address_translation:
                ip = Address()
                ip.address_value = p_indicator["indicator"]
                ip.category = self.address_translation[p_indicator["type"]]
                ip.address_value.condition = "Equals"
                ip_obs = Observable(ip)
                ip_obs.title = "Address: " + str(ip.address_value)
                address_indicator.add_observable(ip_obs)
                address_indicator.description = p_indicator["description"]
                addresses = True

            elif p_indicator["type"] in self.name_translation:
                domain = DomainName()
                domain.value = p_indicator["indicator"]
                domain.type_ = "FQDN"
                domain.value.condition = "Equals"
                domain_obs = Observable(domain)
                domain_obs.title = "Domain: " + str(domain.value)
                domain_indicator.add_observable(domain_obs)
                domain_indicator.description = p_indicator["description"]
                domains = True

            elif p_indicator["type"] == "URL":
                url = URI()
                url.value = p_indicator["indicator"]
                url.type_ = URI.TYPE_URL
                url.value.condition = "Equals"
                url_obs = Observable(url)
                url_obs.title = "URI: " + str(url.value)
                url_indicator.add_observable(url_obs)
                url_indicator.description = p_indicator["description"]
                urls = True

            elif p_indicator["type"] == "email":
                email = Address()
                email.address_value = p_indicator["indicator"]
                email.category = "e-mail"
                email.address_value.condition = "Equals"
                email_obs = Observable(email)
                email_obs.title = "Address: " + str(email.address_value)
                email_indicator.add_observable(email_obs)
                email_indicator.description = p_indicator["indicator"]
                emails = True

            elif p_indicator["type"] == "Mutex":
                mutex = Mutex()
                mutex.name = p_indicator["indicator"]
                mutex.named = True
                mutex_obs = Observable(mutex)
                mutex_obs.title = "Mutex: " + str(mutex.name)
                mutex_indicator.add_observable(mutex_obs)
                mutex_indicator.description = p_indicator["indicator"]
                mutex = True

            else:
                continue

        if hashes:
            self.stix_package.add_indicator(hash_indicator)
        if addresses:
            self.stix_package.add_indicator(address_indicator)
        if domains:
            self.stix_package.add_indicator(domain_indicator)
        if urls:
            self.stix_package.add_indicator(url_indicator)
        if emails:
            self.stix_package.add_indicator(email_indicator)
        if mutex:
            self.stix_package.add_indicator(mutex_indicator)

        # self.stix_package.add_report(self.report)

    def to_xml(self):
        """Return XML."""
        return self.stix_package.to_xml()

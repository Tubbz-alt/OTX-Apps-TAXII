from cybox.common import Hash, Time
from cybox.core import Observable, Observables
from cybox.objects.address_object import Address
from cybox.objects.domain_name_object import DomainName
from cybox.objects.file_object import File
from cybox.objects.mutex_object import Mutex
from cybox.objects.uri_object import URI
from IPy import *
from lxml import etree as et
from stix.common import Identity, InformationSource
from stix.common.vocabs import PackageIntent
from stix.core import STIXHeader, STIXPackage
from stix.indicator import Indicator
from stix.utils import set_id_namespace

PULSE_SERVER_BASE = "https://otx.alienvault.com/"
STIXNAMESPACE = {"https://otx.alienvault.com": "alienvault-otx"}
set_id_namespace(STIXNAMESPACE)
IDENTITY_NAME = "Alienvault OTX"


class StixExport:

    def __init__(self, pulse):
        self.stix_package = STIXPackage()
        self.stix_header = STIXHeader()
        self.pulse = pulse
        self.hash_translation = {"FileHash-MD5": Hash.TYPE_MD5, "FileHash-SHA1": Hash.TYPE_SHA1,
                                 "FileHash-SHA256": Hash.TYPE_SHA256}
        self.address_translation = {
            "IPv4": Address.CAT_IPV4, "IPv6": Address.CAT_IPV6}
        self.name_translation = {
            "domain": URI.TYPE_DOMAIN, "hostname": URI.TYPE_DOMAIN}

    def build(self):
        self.stix_header.title = self.pulse["name"]
        self.stix_header.description = self.pulse["description"]
        self.stix_header.short_description = "%spulse/%s" % (
            PULSE_SERVER_BASE, str(self.pulse["id"]))
        self.stix_header.package_intents.append(PackageIntent.TERM_INDICATORS)
        self.stix_header.information_source = InformationSource()
        self.stix_header.information_source.time = Time()
        self.stix_header.information_source.description = "Alienvault OTX - https://otx.alienvault.com/"
        self.stix_header.information_source.time.produced_time = self.pulse[
            "modified"]
        self.stix_header.information_source.identity = Identity()
        self.stix_header.information_source.identity.name = IDENTITY_NAME

        self.stix_package.stix_header = self.stix_header

        hashes = False
        addresses = False
        emails = False
        domains = False
        urls = False
        mails = False
        mutex = False

        hash_indicator = Indicator()
        hash_indicator.set_producer_identity(IDENTITY_NAME)
        hash_indicator.set_produced_time(hash_indicator.timestamp)
        hash_indicator.set_received_time(self.pulse["modified"])
        hash_indicator.title = "[OTX] [Files] " + self.pulse["name"]
        hash_indicator.add_indicator_type("File Hash Watchlist")

        address_indicator = Indicator()
        address_indicator.set_producer_identity(IDENTITY_NAME)
        address_indicator.set_produced_time(address_indicator.timestamp)
        address_indicator.set_received_time(self.pulse["modified"])
        address_indicator.title = "[OTX] [IP] " + self.pulse["name"]
        address_indicator.add_indicator_type("IP Watchlist")

        domain_indicator = Indicator()
        domain_indicator.set_producer_identity(IDENTITY_NAME)
        domain_indicator.set_produced_time(domain_indicator.timestamp)
        domain_indicator.set_received_time(self.pulse["modified"])
        domain_indicator.title = "[OTX] [Domain] " + self.pulse["name"]
        domain_indicator.add_indicator_type("Domain Watchlist")

        url_indicator = Indicator()
        url_indicator.set_producer_identity(IDENTITY_NAME)
        url_indicator.set_produced_time(url_indicator.timestamp)
        url_indicator.set_received_time(self.pulse["modified"])
        url_indicator.title = "[OTX] [URL] " + self.pulse["name"]
        url_indicator.add_indicator_type("URL Watchlist")

        email_indicator = Indicator()
        email_indicator.set_producer_identity(IDENTITY_NAME)
        email_indicator.set_produced_time(email_indicator.timestamp)
        email_indicator.set_received_time(self.pulse["modified"])
        email_indicator.title = "[OTX] [Email] " + self.pulse["name"]
        email_indicator.add_indicator_type("Malicious E-mail")

        mutex_indicator = Indicator()
        mutex_indicator.set_producer_identity(IDENTITY_NAME)
        mutex_indicator.set_produced_time(mutex_indicator.timestamp)
        mutex_indicator.set_received_time(self.pulse["modified"])
        mutex_indicator.title = "[OTX] [Mutex] " + self.pulse["name"]
        mutex_indicator.add_indicator_type("Malware Artifacts")

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
                email.value = p_indicator["indicator"]
                email.category = "e-mail"
                email.address_value.condition = "Equals"
                email_obs = Observable(email)
                email_obs.title = "Address: " + str(email.address_value)
                email_indicator.add_observable(email_obs)
                email_indicator.description = p_indicator["indicator"]
                emails = True

            # elif p_indicator["type"] == "CVE":
            #    vuln_ = Vulnerability()
            #    vuln_.cveid = p_indicator["indicator"].upper()
            #    observable_ = Observable(vuln_)

            elif p_indicator["type"] == "Mutex":
                mutex = Mutex()
                mutex.name = p_indicator["indicator"]
                mutex.named = True
                mutex_obs = Observable(mutex)
                mutex_obs.title = "Mutex: " + str(mutex.name)
                mutex_indicator.add_observable(mutex_obs)
                mutex_indicator.description = p_indicator["indicator"]
                mutex = True

# elif p_indicator["type"] == "CIDR":
#     nrange = IP(p_indicator["indicator"])
#     nrange_values = nrange.strNormal(3).replace("-", ",")
#     ipv4_ = Address.from_dict(
#         {'address_value': nrange_values, 'category': Address.CAT_IPV4})
#     ipv4_.address_value.condition = "InclusiveBetween"
#     observable_ = Observable(ipv4_)


            else:
                continue

            # mind = Indicator()
# mind.description = p_indicator["description"]
# mind.title = "%s from %spulse/%s" % (
#     p_indicator["indicator"], PULSE_SERVER_BASE, str(self.pulse["id"]))
# observable_.title = "%s - %s" % (
#     p_indicator["type"], p_indicator["indicator"])
# mind.add_observable(observable_)
# self.stix_package.add_indicator(mind)

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

    def to_xml(self):
        return self.stix_package.to_xml()

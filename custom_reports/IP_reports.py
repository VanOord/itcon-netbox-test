from ipam.choices import IPAddressRoleChoices
from ipam.models import IPAddress, Prefix
from dcim.choices import DeviceStatusChoices
from dcim.models import Device
from extras.reports import Report
from django.db.models import Q

class DeviceIPReport(Report):
    """
    Check that every device has either an IPv4 or IPv6 primary address assigned
    """
    description = "Check that every device has either an IPv4 or IPv6 primary address assigned"

    def test_primary_ip4(self):
        """ Test for primary IPv4 addressen on devices """
        for device in Device.objects.filter(status=DeviceStatusChoices.STATUS_ACTIVE):
            intcount = 0
            for interface in device.interfaces.all():
                if not interface.mgmt_only:
                    intcount += 1
            # There may be dumb devices with no interfaces so no IP addresses, that's OK
            if intcount == 0:
                if device.primary_ip4_id is not None:
                    if device.primary_ip6_id is not None:
                        self.log_failure(device, "Device has primary IPv4 and IPv6 address but no interfaces")
                    else:
                        self.log_warning(device, "Device has missing primary IPv4 addresses but no interfaces")
                else:
                    self.log_success(device)
            elif device.primary_ip4_id is None:
                if device.device_type.is_child_device is True:
                    self.log_success(device)
                else:
                    if device.primary_ip6_id is None:
                        self.log_failure(device, "Device is missing primary IPv4 and IPv6 address")
                    else:
                        self.log_warning(device, "Device is missing primary IPv4 addresses")
            else:
                if device.device_type.is_child_device is True:
                    self.log_success(device)
                else:
                    if device.primary_ip6_id is None:
                        self.log_info(device, "Device is missing primary IPv6 address")
                    else:
                        self.log_success(device)

class DuplicateIPReport(Report):
    """
    Validate that we don't have an IP address allocated multiple times in the network
    """
    description = "Validate that we don't have an IP address allocated multiple times in the network"

    def test_unique_ip(self):
        """ test if very IP is indeed unique """
        already_found = []
        for ip in IPAddress.objects.exclude(Q(role=IPAddressRoleChoices.ROLE_ANYCAST) | Q(role=IPAddressRoleChoices.ROLE_VIP) | Q(role=IPAddressRoleChoices.ROLE_VRRP)):
            if str(ip.address) in already_found:
                continue
            if not ip.interface:
                continue
            duplicates = ip.get_duplicates()
            real_dup = 0
            for duplicate in duplicates:
                if duplicate.interface:
                    real_dup +=1
            if real_dup != 0:
                already_found.append(str(ip.address))
                msg = "has %s duplicate ips" % real_dup
                self.log_failure(ip, msg)
            else:
                msg = "%s is unique" % str(ip.address)
                self.log_success(ip, msg)


class DuplicatePrefixReport(Report):
    """
    Validate that we don't have a Prefix allocated multiple times in a VRF
    """
    description = "Validate that we don't have a Prefix allocated multiple times in a VRF"

    def test_unique_prefix(self):
        """ test if every prefix is indeed unique """
        already_found = []
        for prefix in Prefix.objects.all():
            if str(prefix.prefix) in already_found:
                continue
            duplicate_prefixes = Prefix.objects.filter(vrf=prefix.vrf, prefix=str(prefix.prefix)).exclude(pk=prefix.pk)
            if len(duplicate_prefixes) > 0: 
                already_found.append(str(prefix.prefix))
                msg = "has %s duplicate prefix(es)" % len(duplicate_prefixes)
                self.log_failure(prefix, msg)
            else:
                msg = "%s is unique" % str(prefix.prefix)
                self.log_success(prefix, msg)


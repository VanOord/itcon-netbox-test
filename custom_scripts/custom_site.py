from extras.scripts import *
from django.utils.text import slugify
from dcim.choices import DeviceStatusChoices, SiteStatusChoices
from dcim.models import Device, DeviceRole, DeviceType, Manufacturer, Site, SiteGroup, Region
from ipam.models import VLAN, VLANGroup
from tenancy.models import Tenant

class NewProjectSiteScript(Script):

    class Meta:
        name = "New Projct Site Script"
        description = "Provision a new Projct Site with enhanced options and updated naming conventions."

    site_name = StringVar(description="Name of the new site")
    region = ObjectVar(model=Region, required=False, description="Region for the new site")
    tenant = ObjectVar(model=Tenant, required=False, description="Tenant for the new site")
    switch_count = IntegerVar(description="Number of access switches to create")
    switch_model = ObjectVar(description="Access switch model", model=DeviceType)
    router_count = IntegerVar(description="Number of routers to create")
    router_model = ObjectVar(description="Router model", model=DeviceType)
    ap_count = IntegerVar(description="Number of APs to create")
    ap_model = ObjectVar(description="AP model", model=DeviceType)

    def run(self, data, commit):
        try:
            # Attempt to fetch the SiteGroup called 'Project Site'
            try:
                site_group = SiteGroup.objects.get(name='Project Site')
            except SiteGroup.DoesNotExist:
                self.log_failure("Site Group 'ProjectSite' does not exist.")
                return "Script execution failed due to missing Site Group."

            # Create the new site with optional region, tenant, and the site group
            site = Site(
                name=data['site_name'],
                slug=slugify(data['site_name']),
                status=SiteStatusChoices.STATUS_PLANNED,
                region=data.get('region'),
                tenant=data.get('tenant'),
                group=site_group  # Assign the site group here
            )
            site.full_clean()  # Validate the site object before saving
            site.save()
            self.log_success(f"Created new site: {site}")

            # Fetch the VLAN Group 'Project Site'
            try:
                vlan_group = VLANGroup.objects.get(name='Project Site')
            except VLANGroup.DoesNotExist:
                self.log_failure("VLAN Group 'Project Site' does not exist.")
                return "Script execution failed due to missing VLAN Group."

            # Iterate over VLANs in the 'Project Site' group and assign them to the new site
            vlans = VLAN.objects.filter(group=vlan_group)
            for vlan in vlans:
                vlan.site = site
                vlan.save()
                self.log_success(f"Assigned VLAN {vlan.name} ({vlan.vid}) to site: {site.name}")

            # Device creation logic
            roles = {
                "mx": "SDWAN-Appliance",
                "ms": "SDWAN-Switch",
                "mr": "SDWAN-AP",
            }

            for i in range(1, max(data['switch_count'], data['router_count'], data['ap_count']) + 1):
                if i <= data['router_count']:
                    self.create_device(i, "mx", data, site, roles["mx"])
                if i <= data['switch_count']:
                    self.create_device(i, "ms", data, site, roles["ms"])
                if i <= data['ap_count']:
                    self.create_device(i, "mr", data, site, roles["mr"])
                
        except Exception as e:
            self.log_failure(f"Failed to create site: {e}")
            return "Script execution failed due to an error."

    def create_device(self, i, device_type, data, site, role_name):
        try:
            device_role = DeviceRole.objects.get(name=role_name)
            device_type_model = {
                "mx": data['router_model'],
                "ms": data['switch_model'],
                "mr": data['ap_model'],
            }[device_type]
            name_format = {
                "mx": "{}-MX-FW{}",
                "ms": "{}-MS-SW{:02}",
                "mr": "{}-MR-AP{:02}",
            }[device_type]
            name = name_format.format(data['site_name'], i)
            
            device = Device(
                name=name,
                device_type=device_type_model,
                site=site,
                status=DeviceStatusChoices.STATUS_PLANNED,
                device_role=device_role,
            )
            device.full_clean()  # Validate the device object before saving
            device.save()
            self.log_success(f"Created new {device_type}: {name}")
        except Exception as e:
            self.log_failure(f"Failed to create {device_type} {i}: {e}")

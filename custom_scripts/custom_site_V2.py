from extras.scripts import *
from django.utils.text import slugify
from dcim.choices import DeviceStatusChoices, SiteStatusChoices
from dcim.models import Device, DeviceRole, DeviceType, Manufacturer, Site, SiteGroup, Region
from ipam.models import VLAN, VLANGroup, Prefix
from tenancy.models import Tenant
import ipaddress
from netaddr import IPNetwork, IPSet, cidr_merge
from typing import Dict, Set
from ipaddress import ip_network
from typing import Dict, Set
import pytz
class NewProjectSiteScript(Script):

    class Meta:
        name = "New Project Site Script"
        description = "Provision a new Project Site with VLANs based on the 'Project Site' VLAN group."

    site_name = StringVar(description="Name of the new site")
    region = ObjectVar(model=Region, required=False, description="Region for the new site")

    # Default tenant set to 'Connectivity'
    tenant = ObjectVar(
        model=Tenant,
        required=False,
        description="Tenant for the new site",
        default=Tenant.objects.get(name='Connectivity').id if Tenant.objects.filter(name='Connectivity').exists() else None
    )

    timezone = ChoiceVar(
        choices=[(tz, tz) for tz in pytz.all_timezones],
        required=False,
        description="Optional: Timezone of the new site"
    )

    routers = MultiObjectVar(
        description="Select Routers from Inventory",
        model=Device,
        query_params={'site': 'inventory', 'role': 'sdwan-appliance'}
    )

    # Switches are optional
    switches = MultiObjectVar(
        description="Select Switches from Inventory",
        model=Device,
        query_params={'site': 'inventory', 'role': 'sdwan-switch'},
        required=False
    )
    # Access points are optional
    access_points = MultiObjectVar(
        description="Select Access Points from Inventory",
        model=Device,
        query_params={'site': 'inventory', 'role': 'sdwan-ap'},
        required=False
    )

    def run(self, data, commit):

        timezone = data['timezone']
        if timezone:
            self.log_info(f"Timezone specified: {timezone}")
        else:
            self.log_info("No timezone specified.")

        # Initialize counters
        device_counters = {
            "SDWAN-Appliance": 0,
            "SDWAN-AP": 0,
            "SDWAN-Switch": 0,
        }

        # Create Site
        site = self.create_site(data)
        if not site:
            return "Script execution failed due to an error in site creation."

        # Create VLANs in the new site based on the 'Project Site' VLAN group
        self.create_vlans_in_site(site)

        # Assign selected devices to the new site
        if data['routers']:
            self.assign_devices_to_site(data['routers'], site, 'Router', device_counters)
        if data['switches']:
            self.assign_devices_to_site(data['switches'], site, 'Switch', device_counters)
        if data['access_points']:
            self.assign_devices_to_site(data['access_points'], site, 'Access Point', device_counters)

        # New step: Check and log available /24 prefixes for each VLAN
        vlan_prefix_mappings = {
            1: '10.100.0.0/15',
            400: '10.84.0.0/16',
            500: '10.85.0.0/16',
            600: '10.86.0.0/16',
            700: '10.87.0.0/16',
        }
        available_prefixes_for_vlans: Dict[str, Set[str]] = {
            "1": set(),
            "400": set(),
            "500": set(),
            "600": set(),
            "700": set(),
        }

        # Iterate over each VLAN and its corresponding subnet
        for vlan_id, subnet in vlan_prefix_mappings.items():
            self.log_info(f"Checking available /24 prefixes for VLAN {vlan_id} in subnet {subnet}")
            available_prefixes = self.find_available_prefixes(subnet)
            
            # Apply the common octet filtering if necessary
            if str(vlan_id) in ['400', '500', '600', '700']:
                filtered_prefixes = self.filter_prefixes_for_vlan(vlan_id, available_prefixes)
            else:
                filtered_prefixes = available_prefixes
            
            # Convert filtered_prefixes to a set, if not already
            available_prefixes_for_vlans[str(vlan_id)] = set(filtered_prefixes)
            

        common_third_octets = self.find_common_octets_for_vlans(available_prefixes_for_vlans)
        selected_prefixes = self.select_prefixes_based_on_common_third_octet(available_prefixes_for_vlans, common_third_octets)
        # Log each selected prefix for VLANs
        for vlan_id, prefix in selected_prefixes.items():
            self.log_info(f"VLAN{vlan_id} Selected Prefix: {prefix}")

        # Call the method to attach selected prefixes to VLANs in the site
        self.attach_and_assign_prefixes(site, selected_prefixes)

    def create_site(self, data):
        try:
            site_group, _ = SiteGroup.objects.get_or_create(name='Project Site')
            self.log_info(f"Site TZ : {data.get('timezone')}")
            site = Site.objects.create(
                name=data['site_name'],
                slug=slugify(data['site_name']),
                status=SiteStatusChoices.STATUS_PLANNED,
                region=data.get('region'),
                tenant=data.get('tenant'),
                time_zone = data.get('timezone'),
                group=site_group
            )

            self.log_success(f"Created new site: {site}")
            return site
        except Exception as e:
            self.log_failure(f"Failed to create site: {e}")
            return None

    def create_vlans_in_site(self, site):
        try:
            vlan_group = VLANGroup.objects.get(name='Project Site')
            project_site_vlans = VLAN.objects.filter(group=vlan_group)
            for vlan in project_site_vlans:
                VLAN.objects.create(
                    name=vlan.name,
                    vid=vlan.vid,
                    site=site,
                )
                self.log_success(f"Created VLAN {vlan.name} ({vlan.vid}) in site: {site.name}")
        except VLANGroup.DoesNotExist:
            self.log_failure("VLAN Group 'Project Site' does not exist.")
        except Exception as e:
            self.log_failure(f"Failed to create VLANs: {e}")

    def rename_device_based_on_role(self, device, site_code, device_counters):
        device_role_name = device.device_role.name
        index = device_counters.get(device_role_name, 0) + 1
        device_counters[device_role_name] = index

        if device_role_name == "SDWAN-Appliance":
            new_name = f"{site_code}-MX-FW{index}".upper()
        elif device_role_name == "SDWAN-Switch":
            new_name = f"{site_code}-MS-SW{index:02}".upper()
        elif device_role_name == "SDWAN-AP":
            new_name = f"{site_code}-MR-AP{index:02}".upper()
        else:
            new_name = device.name

        device.name = new_name
        device.save()
        self.log_success(f"Renamed device {device.name} based on its role: {device_role_name}")

    def assign_devices_to_site(self, devices, site, device_type, device_counters):
        for device in devices:
            self.rename_device_based_on_role(device, site.slug, device_counters)
            device.site = site
            device.status = DeviceStatusChoices.STATUS_ACTIVE
            device.save()
            self.log_success(f"Assigned and renamed {device_type} {device.name} to site {site.name}")


    def find_available_prefixes(self, container_prefix_str, desired_prefix_len=24):
        parent_prefix_net = IPNetwork(container_prefix_str)
        all_prefixes = Prefix.objects.all()

        # Convert child_prefixes to a list of strings to make them comparable
        child_prefixes_str = []
        for prefix in all_prefixes:
            child_prefix_net = IPNetwork(prefix.prefix)
            if child_prefix_net in parent_prefix_net and child_prefix_net.prefixlen == desired_prefix_len:
                child_prefixes_str.append(str(prefix.prefix))

        self.log_info(f"Used prefix number: {len(child_prefixes_str)}")

        # Generate all possible /24 prefixes within the container prefix
        network = ipaddress.ip_network(container_prefix_str)
        all_available_prefixes = [str(subnet) for subnet in network.subnets(new_prefix=desired_prefix_len)]

        self.log_info(f"All possible /{desired_prefix_len} prefix number: {len(all_available_prefixes)}")

        # Find the difference between all_available_prefixes and child_prefixes_str
        available_prefixes_set = set(all_available_prefixes)
        used_prefixes_set = set(child_prefixes_str)
        truly_available_prefixes = list(available_prefixes_set - used_prefixes_set)

        self.log_info(f"Truly available /{desired_prefix_len} prefixes: {len(truly_available_prefixes)}")

        return truly_available_prefixes


    def filter_prefixes_for_vlan(self, vlan_id, available_prefixes):

        # Filter the prefixes so the 3rd octet is between 50-252
        filtered_prefixes = [
            prefix for prefix in available_prefixes
            if 50 <= int(prefix.split('.')[2]) <= 252
        ]
        
        return filtered_prefixes
    
    def find_common_octets_for_vlans(self, available_prefixes_for_vlans: Dict[str, Set[str]]) -> Set[int]:
        """Finds common third octets for VLANs 400, 500, 600, and 700."""
        def extract_third_octets(subnets: Set[str]) -> Set[int]:
            """Extracts and returns the third octet from each subnet in the provided set of subnets."""
            return {int(ip_network(subnet).network_address.exploded.split('.')[2]) for subnet in subnets}

        # Extract third octets for each of the specific VLANs
        third_octets_by_vlan = {vlan_id: extract_third_octets(subnets) for vlan_id, subnets in available_prefixes_for_vlans.items() if int(vlan_id) in [400, 500, 600, 700]}

        # Find common third octets across VLANs 400, 500, 600, and 700
        common_third_octets = set.intersection(*third_octets_by_vlan.values())

        return common_third_octets
    
    def select_prefixes_based_on_common_third_octet(self, available_prefixes_for_vlans: Dict[str, Set[str]], common_third_octets: Set[int]) -> Dict[str, str]:
        selected_prefixes = {}

        # Step 1: Select the first prefix from VLAN 1
        vlan1_prefixes = list(available_prefixes_for_vlans.get("1", []))
        if vlan1_prefixes:
            selected_prefixes["1"] = vlan1_prefixes[0]  # Assume the list is not empty and select the first prefix
        
        # Step 2: If there are common third octets, proceed to find matching prefixes in other VLANs
        if common_third_octets:
            # Convert the set to a sorted list to consistently select the first common third octet
            sorted_common_third_octets = sorted(list(common_third_octets))
            first_common_third_octet = sorted_common_third_octets[0]
            
            # Step 3: Select prefixes from VLANs 400, 500, 600, and 700 with the first common third octet
            for vlan_id in ["400", "500", "600", "700"]:
                for prefix in available_prefixes_for_vlans.get(vlan_id, []):
                    third_octet = int(ip_network(prefix).network_address.exploded.split('.')[2])
                    if third_octet == first_common_third_octet:
                        selected_prefixes[vlan_id] = prefix
                        break  # Stop after finding the first matching prefix in the current VLAN

        return selected_prefixes
    
    def attach_and_assign_prefixes(self, site, selected_prefixes):
        for vlan_id_str, prefix_str in selected_prefixes.items():
            vlan_id = int(vlan_id_str)  # Convert VLAN ID to integer if it's not already
            try:
                # Retrieve the existing VLAN object for the given VLAN ID and site
                vlan = VLAN.objects.get(vid=vlan_id, site=site)

                # Retrieve or create the Prefix object
                prefix, created = Prefix.objects.get_or_create(
                    prefix=prefix_str,
                    defaults={
                        'vlan': vlan,
                        'site': site,  # Assign the site directly if your Prefix model supports it
                        'status': 'active'  # Set the correct status as per your requirements
                    }
                )
                
                # Check if an existing prefix needs updating
                if not created:
                    update_required = False
                    if prefix.vlan != vlan:
                        prefix.vlan = vlan
                        update_required = True
                    if hasattr(prefix, 'site') and prefix.site != site:  # Check if Prefix model has a 'site' field and update it if necessary
                        prefix.site = site
                        update_required = True
                    if update_required:
                        prefix.save()
                        self.log_info(f"Updated prefix {prefix} for VLAN {vlan_id} in site: {site.name}")
                    else:
                        self.log_info(f"Prefix {prefix} already correctly assigned to VLAN {vlan_id} in site: {site.name}")
                    
            except VLAN.DoesNotExist:
                self.log_failure(f"VLAN {vlan_id} does not exist in site: {site.name}")
            except Exception as e:
                self.log_failure(f"Failed to attach or update prefix {prefix_str} for VLAN {vlan_id}: {e}")


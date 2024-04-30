import yaml
import pathlib
import ipaddress
import logging
import sys
import os
from netaddr import IPNetwork 
from extras.scripts import *
from dcim.models import *
from dcim.choices import *
from ipam.models import VLAN, Prefix
from extras.models import ConfigContext, Tag
from meraki import DashboardAPI, APIError
from django.core.exceptions import ValidationError, MultipleObjectsReturned, ObjectDoesNotExist

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

class ProjectSiteRolloutMERAKI(Script):
    class Meta:
        name = "Project Site Rollout Meraki"
        description = "Planned Project-Site will be rolled out with MERAKI devices."
        field_order = ['site', 'meraki_api_key', 'servers', 'region_scope', 'region_location']

    # Define your variables

    site = ObjectVar(
        model=Site,
        description="Select the Project-Site to be rolled-out to process",
        query_params={"status": "planned"}
    )

    meraki_api_key = StringVar(
        label="Meraki API Key",
        description="Enter your Meraki Dashboard API key."
    )
    servers = BooleanVar(
        label="Servers on site",
        description="Check if there are servers on this site to determine port configurations.",
        default=True
    )
    region_scope = ChoiceVar(
        label="Region Scope",
        description="Select the scope of the region. It will used for Local or Global NPS Configuration",
        choices=(
            ('local', 'Local'),
            ('global', 'Global'),
        ),
        default='local'
    )
    region_location = ChoiceVar(
        label="Region Location",
        description="Select the location of the site.",
        choices=(
            ('WE', 'West Europe'),
            ('SA', 'Southeast Asia'),
            ('BS', 'Brazil South'),
            ('WI', 'West India'),
            ('AF', 'Africa'),
            ('ME', 'Middle East'),
        ),
        default='WE'
    )

    def run(self, data, commit):
        dashboard = DashboardAPI(api_key=data['meraki_api_key'], suppress_logging=True, wait_on_rate_limit=True, maximum_retries=100 )
        organization_id = self.fetch_organization_id(dashboard)

        network_id = self.new_network(dashboard, organization_id, data['site'].name, data['site'].time_zone)

        # Device management
        self.set_device_names(data['site'], network_id, dashboard)

        # Set network defaults
        self.set_network_defaults(dashboard, network_id)

        # Set VLANs from NetBox site prefixes
        self.set_network_vlans(dashboard, network_id, data['site'])

        # Configure SD-WAN port defaults after network creation
        self.set_mx_port_defaults(dashboard, organization_id, network_id)

        # Set SD-WAN firewall settings
        self.set_mx_services_acl(dashboard, network_id)

        # Configure SD-WAN VPN with hubs based on region closeness
        self.set_mx_s2s_vpn(dashboard, organization_id, network_id, data['site'], data['region_location'])

        # Configure SD-WAN Layer3 Firewall Rules
        self.set_mx_l3_firewall(dashboard, network_id, data['site'])

        # Configure SD-WAN Layer7 Firewall Rules
        self.set_mx_l7_firewall(dashboard, network_id, data['site'])

        # Configure SD-WAN Switch Access Policies
        self.set_ms_access_policy(dashboard, network_id, data['site'], data['region_scope'], data['region_location'])

        # Configure SD-WAN Switch Port Defaults
        self.set_ms_port_defaults(dashboard, network_id, data['site'], data['servers'])

        # Configure RF Profile for Access Points
        self.set_mr_rf_profile(dashboard, network_id, data['site'])
        
        # Configure WiFi SSIDs
        self.set_mr_defaults(dashboard, network_id, data['site'], data['region_scope'], data['region_location'])

        # At the end of the script, set the site status to 'active'
        self.set_site_status(data['site'], SiteStatusChoices.STATUS_ACTIVE)

        # Update the custom fields
        self.set_site_custom_fields(dashboard, data['site'], network_id)

        self.log_success("Script completed successfully.")

    def fetch_organization_id(self, client: DashboardAPI):
        self.log_info("Fetching organization ID")
        organizations = client.organizations.getOrganizations()
        if len(organizations) != 1:
            self.log_failure("Multiple or no organizations found. Specify an organization ID.")
            sys.exit(1)
        return organizations[0]['id']

    def new_network(self, client: DashboardAPI, org_id: str, network_name: str, timezone: str):
        self.log_info("Checking for existing network.")
        networks = client.organizations.getOrganizationNetworks(org_id)
        for network in networks:
            if network["name"] == network_name:
                self.log_info(f"Network '{network_name}' already exists.")
                return network["id"]

        self.log_info(f"Network TZ: {timezone}")
        self.log_info(f"Creating new network: {network_name}")
        params = {
            "name": network_name,
            "productTypes": ["appliance", "switch", "wireless"],
            "tags": ["appliance", "switch", "wireless", "Project-Site"],
            "timeZone": str(timezone),
        }
        try:
            network = client.organizations.createOrganizationNetwork(org_id, **params)
            return network["id"]
        except APIError as e:
            self.log_failure(f"Failed to create network: {e}")
            sys.exit(1)

    def claim_network_device(self, client: DashboardAPI, network_id: str, serial: str):
        try:
            # Since the API expects a list of serials, we provide the serial in a list
            client.networks.claimNetworkDevices(network_id, serials=[serial])
            self.log_info(f"Device with serial {serial} claimed in network {network_id}.")
            return True
        except APIError as e:
            self.log_failure(f"Error claiming device with serial {serial}: {e}")
            return False

    def set_device_names(self, site, network_id, client: DashboardAPI):
        sdwan_tag = Tag.objects.get(slug='sdwan-devices-meraki')
        netbox_meraki_devices = Device.objects.filter(site=site, tags=sdwan_tag)
        for device in netbox_meraki_devices:
            serial = device.serial
            if self.claim_network_device(client, network_id, serial):
                # Proceed to name the device only if the claim was successful
                name = device.name
                try:
                    params = {"serial": serial, "name": name}
                    client.devices.updateDevice(**params)
                    self.log_info(f"Device {name} with serial {serial} successfully named in Meraki.")
                except APIError as e:
                    self.log_failure(f"Error naming device {name} with serial {serial} : {e}")

    def set_network_defaults(self, client: DashboardAPI, network_id: str):
        # SNMP Configuration
        snmp = {"access": "community", "communityString": "C888P211"}
        try:
            self.log_info("Configuring SNMP settings")
            client.networks.updateNetworkSnmp(network_id, **snmp)
        except APIError:
            self.log_warning("Failed to configure SNMP settings", exc_info=True)

        # Syslog Configuration
        syslog = [{
            "host": "10.180.12.52",
            "port": "514",
            "roles": ["Security events", "Appliance event log", "Switch event log", "Wireless event log", "Flows", "URLs"]
        }]
        try:
            self.log_info("Configuring syslog settings")
            client.networks.updateNetworkSyslogServers(network_id, servers=syslog)
        except APIError:
            self.log_warning("Failed to configure syslog settings", exc_info=True)

        # Traffic Analysis Configuration
        traffic = {
            "mode": "detailed",
            "customPieChartItems": [{"name": "Office365 Outlook", "type": "host", "value": "outlook.office365.com"}]
        }
        try:
            self.log_info("Configuring traffic analysis settings")
            client.networks.updateNetworkTrafficAnalysis(network_id, **traffic)
        except APIError:
            self.log_warning("Failed to configure traffic analysis settings", exc_info=True)

        # Enable VLANs
        try:
            self.log_info("Enabling appliance VLANs")
            client.appliance.updateNetworkApplianceVlansSettings(network_id, vlansEnabled=True)
        except APIError:
            self.log_warning("Failed to enable appliance VLANs", exc_info=True)

    def set_network_vlans(self, client: DashboardAPI, network_id: str, site):
        prefixes = Prefix.objects.filter(site=site, vlan__isnull=False)
        # Step 1: Create all VLANs first
        for prefix in prefixes:
            vlan = prefix.vlan
            subnet = IPNetwork(prefix.prefix)
            appliance_ip = str(subnet[-2])  # Second to last IP of the subnet

            if vlan.vid == 1:  # Special handling for VLAN 1
                update_param = {
                    "id": "1",
                    "name": vlan.name,
                    "subnet": str(subnet.cidr),
                    "applianceIp": appliance_ip,
                }
                try:
                    client.appliance.updateNetworkApplianceVlan(network_id, vlanId='1', **update_param)
                    self.log_info(f"Successfully updated default VLAN 1 with gateway {appliance_ip}")
                except APIError as e:
                    self.log_failure(f"Failed to update VLAN 1: {e}")
            else:
                create_param = {
                    "id": vlan.vid,
                    "name": vlan.name,
                    "subnet": str(subnet.cidr),
                    "applianceIp": appliance_ip,
                }
                try:
                    client.appliance.createNetworkApplianceVlan(network_id, **create_param)
                    self.log_info(f"Successfully created VLAN {vlan.vid} - {vlan.name} with gateway {appliance_ip}")
                except APIError as e:
                    self.log_failure(f"Failed to create VLAN {vlan.vid} - {vlan.name}: {e}")

        # Step 2: Update specific VLANs with additional configurations
        for prefix in prefixes:
            vlan = prefix.vlan
            subnet = IPNetwork(prefix.prefix)
            update_param = {}

            if vlan.vid in [500, 600]:
                update_param["dnsNameservers"] = "10.111.36.70\n10.24.16.151"
                start_ip1 = str(subnet[1])
                end_ip1 = str(subnet[99])
                start_ip2 = str(subnet[200])
                end_ip2 = str(subnet[254])
                update_param["reservedIpRanges"] = [
                    {"start": start_ip1, "end": end_ip1, "comment": "IT Reserved"},
                    {"start": start_ip2, "end": end_ip2, "comment": "IT Reserved"},
                ]

            if vlan.vid == 500:
                update_param["dhcpOptions"] = [
                    {"type": "text", "code": "15", "value": "vanoord.org"}
                ]

            if vlan.vid == 600:
                update_param["dhcpOptions"] = [
                    {"type": "ip", "code": "150", "value": "10.24.75.11, 10.9.8.11"}
                ]

            if update_param:  # Check if there's anything to update
                try:
                    client.appliance.updateNetworkApplianceVlan(network_id, vlanId=str(vlan.vid), **update_param)
                    self.log_info(f"Successfully updated VLAN {vlan.vid} with custom configurations.")
                except APIError as e:
                    self.log_failure(f"Failed to update VLAN {vlan.vid}: {e}")

    def set_mx_port_defaults(self, client: DashboardAPI, org_id: str, network_id: str):
        """
        Configure default downlink port settings for MX appliances based on the model type.
        """
        try:
            devices = client.appliance.getOrganizationApplianceUplinkStatuses(
                org_id, total_pages=-1, networkIds=[network_id]
            )
        except APIError as err:
            self.log_failure(f"Failed to retrieve appliance information for network {network_id}: {err}")
            return  # Exit the function on failure

        port = 3  # Default downlink port for most MX devices
        for device in devices:
            if device["model"].startswith("MX85"):
                port = 5
                break

            if device["model"].startswith("MX95"):
                port = 5
                break

        params = {
            "portId": str(port),  # Ensure port ID is string if API requires
            "enabled": True,
            "type": "trunk",
            "dropUntaggedTraffic": False,
            "vlan": 1,
            "allowedVlans": "all",
        }

        self.log_info(f"Updating appliance downlink port for network {network_id} with params: {params}")
        try:
            client.appliance.updateNetworkAppliancePort(network_id, **params)
            self.log_info(f"Successfully updated appliance port settings for network {network_id}.")
        except APIError as err:
            self.log_failure(f"Failed to update appliance port for network {network_id}: {err}")
            return
        
    def set_mx_services_acl(self, client: DashboardAPI, network_id: str):
        """
        Configures the MX/appliance exposed services firewalls.
        """
        services = {
            "ICMP": {"service": "ICMP", "access": "unrestricted"},
            "Web": {"service": "web", "access": "restricted", "allowedIps": ["10.24.34.0/24"]},
            "SNMP": {"service": "SNMP", "access": "restricted", "allowedIps": ["10.115.5.73/32"]}
        }

        for service_name, params in services.items():
            try:
                client.appliance.updateNetworkApplianceFirewallFirewalledService(network_id, **params)
                self.log_info(f"Successfully updated appliance firewall for {service_name}.")
            except APIError as err:
                self.log_failure(f"Failed to update appliance firewall for {service_name}: {err}")

    def set_mx_s2s_vpn(self, client: DashboardAPI, org_id: str, network_id: str, site, region_location: str):
    
        # First, filter the Prefix objects for the given site and check if they have associated VLANs.
        # We exclude VLAN ID 700 explicitly from the filtering process
        valid_prefixes = Prefix.objects.filter(site=site, vlan__isnull=False).exclude(vlan__vid=700)
        vlans = {}
        for prefix in valid_prefixes:
            subnet = str(IPNetwork(prefix.prefix))
            vlan_id = prefix.vlan.vid
            vlans[vlan_id] = {"subnet": subnet}

        region_to_hub_mapping = {
            "WE": ("vMX weu001 - ACF Europe", "vMX sea001 - ACF Asia"),
            "SA": ("vMX sea001 - ACF Asia", "vMX cei001 - ACF India"),
            "BS": ("vMX brs001 - ACF Brazil", "vMX weu001 - ACF Europe"),
            "WI": ("vMX cei001 - ACF India", "vMX weu001 - ACF Europe"),
            "AF": ("vMX san001 - ACF Africa", "vMX weu001 - ACF Europe"),
            "ME": ("vMX uan001 - ACF UAE", "vMX weu001 - ACF Europe")
        }

        primary_hub_name, secondary_hub_name = region_to_hub_mapping.get(region_location, (None, None))

        net_params = {"tags": ["VPN-HUB"], "tagsFilterType": "withAnyTags"}
        try:
            hub_networks = client.organizations.getOrganizationNetworks(org_id, total_pages=-1, **net_params)
            selected_hubs = [network for network in hub_networks if network['name'] == primary_hub_name or network['name'] == secondary_hub_name]
            if len(selected_hubs) < 2:
                self.log_failure("Not enough VPN hubs found for the selected region.")
                return
        except APIError as err:
            self.log_failure(f"Failed to retrieve the hub networks: {err}")
            return

        # Log the names of the selected hubs
        selected_hub_names = [hub['name'] for hub in selected_hubs]
        self.log_info(f"Selected VPN hubs for configuration: {', '.join(selected_hub_names)}")

        vpn_params = {
            "hubs": [{"hubId": hub['id'], "useDefaultRoute": False} for hub in selected_hubs],
            "subnets": [{"localSubnet": vlan["subnet"], "useVpn": True} for vlan in vlans.values()]
        }

        self.log_info(f"Configuring auto VPN for the site with params: {vpn_params}")
        try:
            client.appliance.updateNetworkApplianceVpnSiteToSiteVpn(network_id, "spoke", **vpn_params)
            self.log_info("Successfully configured auto VPN for the site.")
        except APIError as err:
            self.log_failure(f"Failed to configure the auto VPN: {err}")

    def set_mx_l3_firewall(self, client: DashboardAPI, network_id: str, site):
        try:
            # Retrieve the SDWAN-appliance device from the given site
            device = Device.objects.get(role__slug="sdwan-appliance", site=site)
        except ObjectDoesNotExist:
            self.log_failure(f"No SDWAN-Appliance found at site {site}")
            return
        except MultipleObjectsReturned:
            self.log_failure(f"Multiple SDWAN-Appliance devices found at site {site}")
            return

        # Retrieve the aggregated config context for the device
        config_context = device.get_config_context()
        self.log_info(f"L3 Config context data: {config_context['project']['l3_rules']}")
        try:
            # Assuming L3 firewall rules are defined within the device's config context
            l3_rules = config_context['project']['l3_rules']
        except KeyError as err:
            self.log_failure(f"Firewall rules not defined in config context for device at site {site}: {err}")
            return

        # Fetching prefixes and preparing IP replacements
        vlans = {prefix.vlan.vid: {"subnet": str(IPNetwork(prefix.prefix))} for prefix in Prefix.objects.filter(site=site)}

        subnet = ipaddress.ip_network(vlans[500]["subnet"])
        printer_ips = ",".join(str(ip) for ip in list(subnet.hosts())[199:202])  # Capture specific printer IPs

        # Construct the replacements dictionary
        replacements = {
            f"VLAN{vid}": info["subnet"] for vid, info in vlans.items()
        }
        replacements.update({
            "PRINT500": printer_ips,
            "SURVEY": "192.168.0.0/24",
            "VANOORD_DC": "10.24.0.0/16,10.12.160.0/20",
            "VANOORD_AZURE": "10.111.0.0/16",
            "VANOORD_WAN": "10.0.0.0/8",
        })

        # Log the replacements dictionary
        self.log_info(f"Replacements dictionary: {replacements}")

        # Replace source and destination IPs in certain strings with the values calculated above.
        rules = []
        for rule in l3_rules:
            # Replace source strings with IPs
            s_cidr = rule["srcCidr"]
            for var, value in replacements.items():
                s_cidr = s_cidr.replace(var, value)
            rule["srcCidr"] = s_cidr

            # Replace destination strings with IPs
            d_cidr = rule["destCidr"]
            for var, value in replacements.items():
                d_cidr = d_cidr.replace(var, value)
            rule["destCidr"] = d_cidr

            rules.append(rule)

            self.log_info(f"Configured rule: {rule}")

        # Attempt to configure L3 firewall rules
        try:
            client.appliance.updateNetworkApplianceFirewallL3FirewallRules(network_id, rules=rules)
            self.log_info("Successfully configured L3 firewall rules.")
        except APIError as err:
            self.log_failure(f"Failed to configure L3 firewall rules: {err}")

    def set_mx_l7_firewall(self, client: DashboardAPI, network_id: str, site):
        """
        Configure default MX L7 firewall rules.
        """
        try:
            # Retrieve the SDWAN-appliance device from the given site
            device = Device.objects.get(role__slug="sdwan-appliance", site=site)
        except ObjectDoesNotExist:
            self.log_failure(f"No SDWAN-Appliance found at site {site}")
            return
        except MultipleObjectsReturned:
            self.log_failure(f"Multiple SDWAN-Appliance devices found at site {site}")
            return

        # Retrieve the aggregated config context for the device
        config_context = device.get_config_context()
        self.log_info(f"L7 Config context data: {config_context['project']['l7_rules']}")
        try:
            # Assuming L3 firewall rules are defined within the device's config context
            l7_rules = config_context['project']['l7_rules']
        except KeyError as err:
            self.log_failure(f"Firewall rules not defined in config context for device at site {site}: {err}")
            return

        # Log each rule's details
        for rule in l7_rules:
            self.log_info(
                f"Configuring L7 Rule - Network: {network_id}, Policy: {rule['policy']}, "
                f"Type: {rule['type']}, Value ID: {rule['value']['id']}, Value Name: {rule['value']['name']}"
            )

        try:
            client.appliance.updateNetworkApplianceFirewallL7FirewallRules(
                network_id, rules=l7_rules
            )
            self.log_info("Successfully configured L7 firewall rules.")
        except APIError as err:
            self.log_failure(
                f"Failed to configure L7 firewall rules: {err}, Rules: {l7_rules}"
            )

    def set_ms_access_policy(self, client: DashboardAPI, network_id: str, site, scope, location):
        """
        Configures MS Access Policy based on the provided regional information and network details.
        """
        # Load access policy configurations from template
        device = Device.objects.filter(role__slug="sdwan-switch", site=site).first()
        if not device:
            self.log_failure(f"No suitable SDWAN-Switch found at site {site}")
            return

        # Retrieve the aggregated config context for the device
        config_context = device.get_config_context()
        self.log_info(f"MS Port Access Policy Config context data: {config_context['project']['ms_access_profile_data']}")
        try:
            # Assuming Port Access Policy rules are defined within the device's config context
            policies = config_context['project']['ms_access_profile_data']
        except KeyError as err:
            self.log_failure(f"Access policy data not defined in config context for device at site {site}: {err}")
            return

        # Define regional IP addresses and policy details based on the site's region and scope
        region_ips = {
            "WE": ["10.111.36.68", "10.111.36.69"],
            "SA": ["10.160.2.68", "10.160.2.69"],
            "BS": ["10.140.2.68", "10.140.2.69"],
            "WI": ["10.150.2.68", "10.150.2.69"],
            "AF": ["10.180.12.68", "10.180.12.69"],  # Example IPs for Africa
            "ME": ["10.190.22.68", "10.190.22.69"],  # Example IPs for Middle East
        }

        closest_regions = {
            "WE": "SA",
            "SA": "WI",
            "WI": "WE",
            "BS": "WE",
        }


        # Fetching prefixes and preparing VLAN subnet information
        vlans = {prefix.vlan.vid: {"subnet": str(IPNetwork(prefix.prefix))} for prefix in Prefix.objects.filter(site=site)}
        vlan_500 = ipaddress.ip_network(vlans[500]["subnet"])  # Assuming VLAN 500 is present

        # Determine primary and secondary RADIUS server IPs based on scope
        if scope == 'local':
            # For local scope, use an IP from VLAN 500's subnet for the primary RADIUS server
            primary_ip = str(list(vlan_500.hosts())[44])  # Example: taking the 45th host IP in VLAN 500
            secondary_ip = region_ips[location][0]  # Use the first regional IP as secondary
        else:
            primary_ip = region_ips[location][0]
            # Use the first IP of the closest region for the secondary IP
            closest_region = closest_regions[location]
            secondary_ip = region_ips[closest_region][0]

        radius_secret = 'YourRadiusSecret'  # This should be securely handled
        radius_servers = [
            {"host": primary_ip, "port": 1812, "secret": radius_secret},
            {"host": secondary_ip, "port": 1812, "secret": radius_secret}
        ]

        radius_accounting_servers = [
            {"host": primary_ip, "port": 1812, "secret": radius_secret},
            {"host": secondary_ip, "port": 1812, "secret": radius_secret}
        ]


        # Dictionary for placeholder replacement
        radius_config_map = {
            'VON_DATA_RADIUS': radius_servers,
            'VON_DATA_ACC': radius_accounting_servers,
            # Add more mappings as necessary
        }

        # Check for SD-WAN switch devices at the site
        switches = Device.objects.filter(role__slug='sdwan-switch', site=site)
        if not switches.exists():
            self.log_info(f"No SD-WAN switch devices found at site {site.name}. Skipping access policy configuration.")
            return


        # Check for SD-WAN switch devices at the site
        switches = Device.objects.filter(role__slug='sdwan-switch', site=site)
        if not switches.exists():
            self.log_info(f"No SD-WAN switch devices found at site {site.name}. Skipping access policy configuration.")
            return

        for policy_config in policies:
            # Replace placeholder keys in the policy configuration with actual server configurations
            policy_config['radiusServers'] = radius_config_map.get(policy_config.get('radiusServers', []), [])
            policy_config['radiusAccountingServers'] = radius_config_map.get(policy_config.get('radiusAccountingServers', []), [])

            # Apply the access policy
            try:
                existing_policies = client.switch.getNetworkSwitchAccessPolicies(network_id)
                policy_exists = any(policy['accessPolicyNumber'] == str(policy_config['accessPolicyNumber']) for policy in existing_policies)

                # Remove the 'accessPolicyNumber' from policy_config to avoid multiple values error
                access_policy_number = policy_config.pop('accessPolicyNumber', None)

                if policy_exists:
                    # Pass 'accessPolicyNumber' explicitly and use the modified policy_config
                    response = client.switch.updateNetworkSwitchAccessPolicy(
                        network_id, access_policy_number, **policy_config
                    )
                    self.log_info(f"Updated existing Access Policy {access_policy_number} on Network ID: {network_id}")
           
                else:
                    # Since we popped 'accessPolicyNumber', we need to reinsert it if creating a new policy
                    policy_config['accessPolicyNumber'] = access_policy_number
                    response = client.switch.createNetworkSwitchAccessPolicy(
                        network_id, **policy_config
                    )
                    self.log_info(f"Created new Access Policy on Network ID: {network_id}")

                self.log_info(f"Policy details: {response}")

            except APIError as err:
                self.log_error(f"Failed to configure Access Policy on Network ID: {network_id}. Error: {err}")
                return

        self.log_success(f"Access Policies successfully configured on Network ID: {network_id}")

    def set_mr_rf_profile(self, client: DashboardAPI, network_id: str, site):
        """
        Load RF profile settings from a YAML file and apply them to the specified network if relevant APs are present.
        """
        # Check for access points with the specified role at the site
        access_points = Device.objects.filter(role__slug='sdwan-ap', site=site)
        if not access_points.exists():
            self.log_info(f"No access points with role 'sdwan-ap' found at site {site.name}. Skipping RF profile configuration.")
            return

       # Load access policy configurations from template
        device = Device.objects.filter(role__slug="sdwan-ap", site=site).first()
        if not device:
            self.log_failure(f"No suitable SDWAN-AP found at site {site}")
            return

        # Retrieve the aggregated config context for the device
        config_context = device.get_config_context()
        self.log_info(f"WiFi RF Profile Config context data: {config_context['project']['wifi_rf_profiles'][0]}")
        try:
            # Assuming WiFi RF Profile is defined within the device's config context
            rf_profile_data = config_context['project']['wifi_rf_profiles'][0]
        except KeyError as err:
            self.log_failure(f"Failed to read the Wireless RF profile file: {err}")
            return


        rf_profile_params = {
            "name": rf_profile_data['name'],
            "bandSelectionType": rf_profile_data['bandSelectionType'],
            "clientBalancingEnabled": rf_profile_data.get('clientBalancingEnabled', True),
            "minBitrateType": rf_profile_data.get('minBitrateType', 'band'),
            "apBandSettings": rf_profile_data.get('apBandSettings', {}),
            "twoFourGhzSettings": rf_profile_data.get('twoFourGhzSettings', {}),
            "fiveGhzSettings": rf_profile_data.get('fiveGhzSettings', {}),
            "sixGhzSettings": rf_profile_data.get('sixGhzSettings', {}),
            "transmission": rf_profile_data.get('transmission', {}),
            "perSsidSettings": rf_profile_data.get('perSsidSettings', {})
        }

        # Logging the configuration details before applying
        self.log_info(f"Applying RF Profile Configuration: {rf_profile_params}")

        try:
            existing_profiles = client.wireless.getNetworkWirelessRfProfiles(network_id)
            profile_id = next((p['id'] for p in existing_profiles if p['name'] == rf_profile_data['name']), None)

            if profile_id:
                response = client.wireless.updateNetworkWirelessRfProfile(
                    network_id, profile_id, **rf_profile_data
                )
                self.log_info(f"Updated existing RF profile '{rf_profile_data['name']}' on Network ID: {network_id}.")
            else:
                response = client.wireless.createNetworkWirelessRfProfile(
                    network_id, **rf_profile_data
                )
                profile_id = response['id']
                self.log_success(f"Created new RF profile '{rf_profile_data['name']}' on Network ID: {network_id}.")

            # Applying the RF profile to all APs
            for ap in access_points:
                client.wireless.updateDeviceWirelessRadioSettings(
                    ap.serial, rfProfileId=profile_id
                )
                self.log_info(f"Applied RF Profile '{rf_profile_data['name']}' to AP {ap.name} with serial {ap.serial}.")

        except Exception as err:
            self.log_failure(f"Failed to create/update RF Profile '{rf_profile_data['name']}' on Network ID: {network_id}. Error details: {err}")

    def set_mr_defaults(self, client: DashboardAPI, network_id: str, site, scope, location):
        """
        Configure SSIDs for the network based on regional settings and existing VLANs.
        """

        function_name = self.set_mr_defaults.__qualname__  # Get the function's qualified name
        # Check if there are any access points with the role 'sdwan-ap'
        access_points = Device.objects.filter(role__slug='sdwan-ap', site=site)
        if not access_points.exists():
            self.log_info(f"[{function_name}] No SD-WAN access points found at site {site.name}. Skipping WiFi configuration.")
            return

        # Define regional IPs and their closest counterparts
        region_ips = {
            "WE": ["10.111.36.68", "10.111.36.69"],
            "SA": ["10.160.2.68", "10.160.2.69"],
            "BS": ["10.140.2.68", "10.140.2.69"],
            "WI": ["10.150.2.68", "10.150.2.69"],
            "AF": ["10.180.12.68", "10.180.12.69"],
            "ME": ["10.190.22.68", "10.190.22.69"],
        }

        closest_regions = {
            "WE": "SA",  # Western Europe's closest is South Asia
            "SA": "WI",  # South Asia's closest is West India
            "WI": "WE",  # West India's closest is Western Europe
            "BS": "WE",  # Brazil's closest is Western Europe
        }

        # Fetching VLAN information
        vlans = {prefix.vlan.vid: {"subnet": str(IPNetwork(prefix.prefix))} for prefix in Prefix.objects.filter(site=site)}
        vlan_500 = ipaddress.ip_network(vlans[500]["subnet"]) if 500 in vlans else None

        # Determine RADIUS IPs for VON DATA
        primary_ip = region_ips[location][0]
        secondary_ip = region_ips[closest_regions[location]][0] if scope == 'global' else str(list(vlan_500.hosts())[44])

        radius_secret = 'YourRadiusSecret'  # This should be securely handled
        von_data_radius_servers = [
            {"host": primary_ip, "port": 1812, "secret": radius_secret},
            {"host": secondary_ip, "port": 1812, "secret": radius_secret}
        ]

        von_data_accounting_servers = [
            {"host": primary_ip, "port": 1813, "secret": radius_secret},
            {"host": secondary_ip, "port": 1813, "secret": radius_secret}
        ]

        self.log_info(f"VON Data RADIUS Servers: {von_data_radius_servers}")
        self.log_info(f"VON Data RADIUS Accounting Servers: {von_data_accounting_servers}")

        # Determine RADIUS IPs for VON Employee
        emp_primary_ip = region_ips[location][1]  # Assuming second IP for primary in employee scenario
        emp_secondary_ip = region_ips[closest_regions[location]][1] if scope == 'global' else str(list(vlan_500.hosts())[44])

        von_emp_radius_servers = [
            {"host": emp_primary_ip, "port": 1812, "secret": radius_secret},
            {"host": emp_secondary_ip, "port": 1812, "secret": radius_secret}
        ]

        von_emp_accounting_servers = [
            {"host": emp_primary_ip, "port": 1813, "secret": radius_secret},
            {"host": emp_secondary_ip, "port": 1813, "secret": radius_secret}
        ]

        self.log_info(f"VON Employee RADIUS Servers: {von_emp_radius_servers}")
        self.log_info(f"VON Employee RADIUS Accounting Servers: {von_emp_accounting_servers}")

        # Example API call to configure SSIDs would go here
        # Implement SSID configuration using von_data_radius_servers and von_emp_radius_servers
        config_context = access_points[0].get_config_context()
        self.log_info(f"WiFi SSIDs Profile Config context data: {config_context['project']['wifi_ssid_data']}")
        try:
            ssids = config_context['project']['wifi_ssid_data']
            self.log_info("Loaded WiFi SSID profile settings successfully.")
        except Exception as err:
            self.log_failure(f"Failed to read the Wireless SSID file: {err}")
            return
        
        self.log_info("SSID configuration completed successfully.")

        l3_fw_rule = {"allowLanAccess": True}

        # Dictionary for placeholder replacement
        radius_config_map = {
            'VON_DATA_RADIUS': von_data_radius_servers,
            'VON_DATA_ACC': von_data_radius_servers,
            'VON_EMPLOYEE_RADIUS': von_emp_accounting_servers,
            'VON_EMPLOYEE_ACC': von_emp_radius_servers,
            # Add more mappings as necessary
        }

        for i, ssid in enumerate(ssids):
            # Replace placeholder text with actual server configurations
            ssid['radiusServers'] = radius_config_map[ssid['radiusServers']]
            ssid['radiusAccountingServers'] = radius_config_map[ssid['radiusAccountingServers']]

            self.log_info(f"Configuring ssid ---> {ssid}")

            try:
                client.wireless.updateNetworkWirelessSsid(network_id, str(i), **ssid)
                self.log_info(f"Configured SSID '{ssid['name']}' successfully on Network ID: {network_id}.")

                client.wireless.updateNetworkWirelessSsidFirewallL3FirewallRules(
                    network_id, str(i), **l3_fw_rule)
                
                self.log_info(f"Configured SSID L3 firewall rules '{ssid['name']}' '{l3_fw_rule}' successfully on Network ID: {network_id}.")

            except APIError as err:
                self.log_error(f"Failed to configure SSID '{ssid['name']}' on Network ID: {network_id}. Error: {err}")

        self.log_info("SSID configuration completed successfully.")

    def set_ms_port_defaults(self, client: DashboardAPI, network_id: str, site, servers: bool):        
        """
        Configures Meraki switch ports based on the role 'sdwan-switch' at the specified site.
        """
        # Fetch switches with 'sdwan-switch' role at the site
        switches = Device.objects.filter(role__slug='sdwan-switch', site=site)
        if not switches.exists():
            self.log_info(f"No SD-WAN switch devices found at site {site.name}. Skipping port configuration.")
            return

        # Fetch APs with 'sdwan-ap' role at the site
        access_points = Device.objects.filter(role__slug='sdwan-ap', site=site)
        num_aps = access_points.count()

        for switch in switches:
            serial = switch.serial
            switch_name = switch.name
            device_ports = client.switch.getDeviceSwitchPorts(serial)
            port_count = len(device_ports)

            for port_number in range(1, port_count + 1):
                port_config = {
                    "enabled": True,
                    "type": "access",
                    "vlan": 500,
                    "voiceVlan": 600,
                    "stpGuard": "bpdu guard",
                    "name": f"Data/VoIP {port_number}"
                }

                if port_number == 1:
                    port_config.update({
                        "name": "Uplink to MX",
                        "type": "trunk",
                        "vlan": 1,
                        "stpGuard": "loop guard",
                    })

                if servers and port_number in range(2, 16):
                    specific_configs = {
                        2: {"enabled": False},
                        3: {"enabled": False},
                        4: {"enabled": False},
                        5: {"name": f"{site.name}-UP1", "type": "access", "vlan": 400},
                        6: {"name": f"ILO-{site.name}-VE1", "type": "access", "vlan": 400},
                        7: {"name": f"{site.name}-VE1 NIC1", "type": "trunk", "vlan": 400, "stpGuard": "loop guard"},
                        8: {"name": f"{site.name}-VE1 NIC2", "type": "trunk", "vlan": 400, "stpGuard": "loop guard"},
                        9: {"name": f"{site.name}-VE1 NIC3", "type": "trunk", "vlan": 400, "stpGuard": "loop guard"},
                        10: {"name": f"{site.name}-VE1 NIC4", "type": "trunk", "vlan": 400, "stpGuard": "loop guard"},
                        11: {"name": f"ILO-{site.name}-BK5", "type": "access", "vlan": 400},
                        12: {"name": f"{site.name}-BK5 NIC1", "type": "access", "vlan": 400},
                        13: {"name": f"{site.name}-BK5 NIC2", "type": "access", "vlan": 400},
                        14: {"name": f"{site.name}-BK5 NIC3", "type": "access", "vlan": 500},
                        15: {"name": f"{site.name}-BK5 NIC4", "type": "access", "vlan": 500}
                    }
                    port_config.update(specific_configs.get(port_number, {}))

                if num_aps > 0 and port_number > port_count - num_aps:
                    port_config.update({
                        "name": f"AP Connection Port {port_number - (port_count - num_aps)}",
                        "type": "trunk",
                        "vlan": 1,
                        "stpGuard": "loop guard",
                    })

                client.switch.updateDeviceSwitchPort(serial, port_number, **port_config)
                self.log_info(f"Configured port {port_number} on switch {switch_name} {serial} with settings: {port_config}")

        self.log_success("Completed port configurations for all eligible switches at the site.")

    def set_site_status(self, site, status):
        try:
            site.status = status
            site.save()
            self.log_info(f"Site {site.name} status updated to {status}.")
        except Exception as e:
            self.log_failure(f"Failed to update site status: {e}")

    def set_site_custom_fields(self, client: DashboardAPI, site, network_id):
        # Assuming the URL for the Meraki dashboard network page is standard
        try:
            response = client.networks.getNetwork(network_id)
            self.log_info(f"Retrieved network details for {network_id}.")
        except APIError as e:
            self.log_failure(f"Failed to retrieve network details for {network_id}: {e}")

        try:
            site.custom_field_data['meraki_networkid'] = network_id
            site.custom_field_data['url'] = response['url']
            site.save()
            self.log_info(f"Updated custom fields: Meraki Network ID set to {network_id} and URL to {response['url']}.")
        except Exception as e:
            self.log_failure(f"Failed to update custom fields for site {site.name}: {e}")
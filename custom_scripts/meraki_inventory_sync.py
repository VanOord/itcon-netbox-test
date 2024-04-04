from collections import Counter
from extras.scripts import Script, StringVar
from dcim.models import Device, DeviceType, Manufacturer, Platform, Site, DeviceRole
from dcim.choices import DeviceStatusChoices
from extras.models import Tag
from meraki import DashboardAPI
import json

class MerakiInventorySync(Script):
    class Meta:
        name = "Sync Meraki Inventory"
        description = "Sync devices from Meraki to NetBox 'Inventory' site."
        field_order = ['meraki_api_key']

    meraki_api_key = StringVar(
        description="Enter your Meraki Dashboard API key",
    )

    def run(self, data, commit):
        dashboard = DashboardAPI(api_key=data['meraki_api_key'], suppress_logging=True)

        # Fetch organization ID
        try:
            organizations = dashboard.organizations.getOrganizations()
            if len(organizations) != 1:
                raise ValueError("There must be exactly one organization associated with this API key.")
            organization_id = organizations[0]['id']
        except Exception as e:
            self.log_failure(f"Failed to fetch organizations: {e}")
            return

        # Fetch devices from Meraki, excluding certain product types
        try:
            all_meraki_devices = dashboard.organizations.getOrganizationInventoryDevices(organizationId=organization_id, total_pages='all')
            excluded_product_types = ['sensor', 'camera', 'systemsmanager']
            meraki_devices = [device for device in all_meraki_devices if device.get('productType', '').lower() not in excluded_product_types]
        except Exception as e:
            self.log_failure(f"Failed to fetch devices from Meraki: {e}")
            return

        # Define a mapping of Meraki product types to more general device categories if needed
        product_type_to_category = {
            'appliance': "Appliances",
            'switch': "Switches",
            'wireless': "Access Points",
            'cellulargateway': "CellularGateways Appliances"
        }

        # Process the devices to count by model and by product type
        device_categories = [product_type_to_category.get(device['productType'].lower(), "Other") for device in meraki_devices if device['productType'].lower() not in excluded_product_types]
        category_counts = Counter(device_categories)

        device_models = [device['model'] for device in meraki_devices if device['productType'].lower() not in excluded_product_types]
        model_counts = Counter(device_models)

        total_devices = sum(model_counts.values())

        self.log_info(f"Excluding Sensors, Cameras, and System Managers")
        self.log_info(f"Total Devices: {total_devices}")

        # Log the counts of each device category
        for category, count in category_counts.items():
            self.log_info(f"{count} {category}")

        # Optionally, sort and log models based on count in descending order for detailed breakdown
        for model, count in sorted(model_counts.items(), key=lambda item: item[1], reverse=True):
            self.log_info(f"Found {count} devices with model name {model}")


        # Fetch predefined objects from NetBox
        try:
            manufacturer = Manufacturer.objects.get(name="Cisco")
            platform = Platform.objects.get(name="Cisco Meraki")
            inventory_site = Site.objects.get(name="Inventory")
            sdwan_tag, _ = Tag.objects.get_or_create(name="SDWAN Devices Meraki", defaults={'slug': 'sdwan-devices-meraki'})
        except (Manufacturer.DoesNotExist, Platform.DoesNotExist, Site.DoesNotExist) as e:
            self.log_failure(f"Predefined object not found: {e}")
            return

        # Device roles mapping
        product_type_to_role = {
            'appliance': "SDWAN-Appliance",
            'switch': "SDWAN-Switch",
            'wireless': "SDWAN-AP",
            'cellulargateway': "SDWAN-CellularGateway",
        }

        # Add missing devices to NetBox
        self.add_missing_devices(meraki_devices, manufacturer, platform, inventory_site, sdwan_tag, product_type_to_role, commit)

        # Verify devices in inventory site don't have a networkId
        self.verify_devices_in_inventory(meraki_devices, inventory_site, platform, commit)

        # Check for devices with a networkId matching NetBox sites
        self.check_for_site_matches(meraki_devices, inventory_site)

    def add_missing_devices(self, meraki_devices, manufacturer, platform, inventory_site, sdwan_tag, product_type_to_role, commit):
        for device in meraki_devices:
            serial = device.get('serial')
            model_from_meraki = device.get('model').upper()
            model = f"Meraki {model_from_meraki}"
            product_type = device.get('productType', '').lower()
            role_name = product_type_to_role.get(product_type)

            if not role_name:
                self.log_warning(f"No role defined for Meraki product type '{product_type}'. Skipping device {serial}.")
                continue

            try:
                device_role = DeviceRole.objects.get(name=role_name)
                device_type = DeviceType.objects.get(model=model, manufacturer=manufacturer)
            except (DeviceRole.DoesNotExist, DeviceType.DoesNotExist):
                self.log_failure(f"Required configuration for device {serial} not found. Skipping.")
                continue

            if not Device.objects.filter(serial=serial).exists() and commit:
                new_device = Device.objects.create(
                    name=device.get('name', serial),
                    serial=serial,
                    device_type=device_type,
                    site=inventory_site,
                    platform=platform,
                    device_role=device_role,
                    status=DeviceStatusChoices.STATUS_INVENTORY,  # Set device status to "Inventory"
                )
                new_device.tags.add(sdwan_tag)
                self.log_success(f"Added device {serial} to NetBox with role {role_name}.")


    def verify_devices_in_inventory(self, meraki_devices, inventory_site, platform, commit):
        try:
            # Fetch the "Site Mismatched Device" tag
            site_mismatch_tag = Tag.objects.get(name="Site Mismatched Device")
        except Tag.DoesNotExist:
            self.log_failure("Tag 'site-mismatched-device' not found.")
            return

        # Fetch devices from NetBox in the inventory site with the "Cisco Meraki" platform
        netbox_meraki_devices = Device.objects.filter(site=inventory_site, platform=platform)

        for nb_device in netbox_meraki_devices:
            # Find the corresponding device in the Meraki devices list by serial number
            corresponding_meraki_device = next((d for d in meraki_devices if d['serial'] == nb_device.serial), None)

            if corresponding_meraki_device:
                if corresponding_meraki_device.get('networkId'):
                    # Device has a networkId, consider it as "Active"
                    new_status = DeviceStatusChoices.STATUS_ACTIVE
                    tag_action = "Adding"
                else:
                    # Device does not have a networkId, consider it as "Inventory"
                    new_status = DeviceStatusChoices.STATUS_INVENTORY
                    tag_action = "Checking"
                    
                # Update device status and optionally add "Site Mismatched Device" tag
                if commit:
                    nb_device.status = new_status
                    if new_status == DeviceStatusChoices.STATUS_ACTIVE:
                        nb_device.tags.add(site_mismatch_tag)
                    nb_device.save()
                    
                self.log_info(f"{tag_action} 'Site Mismatched Device' tag and updating status for device {nb_device.serial} to {new_status}.")
            else:
                # If there's no matching device in Meraki, ensure it's marked as "Inventory"
                if commit and nb_device.status != DeviceStatusChoices.STATUS_INVENTORY:
                    nb_device.status = DeviceStatusChoices.STATUS_INVENTORY
                    nb_device.save()
                    self.log_info(f"Device {nb_device.serial} set to Inventory status as no corresponding Meraki device was found.")


    def check_for_site_matches(self, meraki_devices, inventory_site):
        other_sites = Site.objects.exclude(pk=inventory_site.pk)
        # Correctly access custom fields
        site_by_meraki_networkid = {site.custom_field_data.get('meraki_networkid'): site for site in other_sites if 'meraki_networkid' in site.custom_field_data}
        devices_with_networkid = [device for device in meraki_devices if device.get('networkId')]

        for device in devices_with_networkid:
            network_id = device['networkId']
            # Properly fetch the NetBox device, if exists
            netbox_meraki_device = Device.objects.filter(serial=device['serial']).first()
            
            netbox_device_name = "Not Found in NetBox"
            if netbox_meraki_device:
                netbox_device_name = netbox_meraki_device.name

            corresponding_site = site_by_meraki_networkid.get(network_id)
            if corresponding_site:
                meraki_device_name = device.get('name', 'No Name Available')
                
                log_message = (
                    f"Device Serial       : {device['serial']}\n\n"
                    f"Meraki DeviceName   : {meraki_device_name}\n\n"
                    f"NetBox DeviceName   : {netbox_device_name}\n\n"
                    f"NetBox Site         : {corresponding_site.name}\n\n"
                    f"Network ID          : {network_id}")
                self.log_info(log_message)
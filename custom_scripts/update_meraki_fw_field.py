from extras.scripts import *
from dcim.models import Device
from meraki import DashboardAPI

class UpdateFirmwareField(Script):
    class Meta:
        name = "Update Firmware field on Netbox from Meraki Dashboard"
        description = "Automatically fetches the organization ID if there's only one, and updates the 'firmware' custom field for devices based on Meraki inventory."
    
    meraki_api_key = StringVar(
        description="Meraki API Key",
    )
    
    def run(self, data, commit):
        # Initialize Meraki Dashboard API session
        dashboard = DashboardAPI(api_key=data['meraki_api_key'], suppress_logging=True)

        # Fetch organizations
        try:
            organizations = dashboard.organizations.getOrganizations()
            if len(organizations) == 1:
                organization_id = organizations[0]['id']
                self.log_success(f"Automatically selected Organization ID: {organization_id}")
            else:
                self.log_failure("Multiple organizations found. Please specify an organization ID.")
                return
        except Exception as e:
            self.log_failure(f"Failed to fetch organizations: {e}")
            return

        # Fetch organization devices
        try:
            inventory_devices = dashboard.organizations.getOrganizationDevices(
                organization_id, total_pages='all'
            )
        except Exception as e:
            self.log_failure(f"Failed to fetch Meraki inventory for organization {organization_id}: {e}")
            return
        
        # Iterate over inventory devices and update NetBox
        updated_devices = 0
        for device in inventory_devices:
            # Assume the serial number is used to match devices between Meraki and NetBox
            serial = device['serial']
            firmware = device.get('firmware', 'Unknown')  # Use 'Unknown' if firmware information is missing
            
            try:
                nb_device = Device.objects.get(serial=serial)
                # Check if firmware is already up-to-date
                if nb_device.custom_field_data.get('firmware') == firmware:
                    self.log_info(f"Skipped {nb_device.name} as firmware is already up-to-date")
                    continue
                # Update the 'firmware' custom field
                nb_device.custom_field_data['firmware'] = firmware
                nb_device.save()
                updated_devices += 1
                self.log_success(f"Updated {nb_device.name} firmware to {firmware}")
            except Device.DoesNotExist:
                self.log_info(f"No matching device found in NetBox for serial: {serial}")
            except Exception as e:
                self.log_failure(f"Error updating device {serial}: {e}")
                
        self.log_success(f"Completed. {updated_devices} devices updated.")

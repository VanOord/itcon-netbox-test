from extras.scripts import *
from django.utils.text import slugify
from dcim.models import Device, Site
from dcim.choices import DeviceStatusChoices
from ipam.models import VLAN, Prefix

class DeleteSiteAndMoveDevicesToInventory(Script):
    class Meta:
        name = "Move Retired Site Devices to Inventory"
        description = "Moves devices from a specified RETIRED site to the 'Inventory' site, changes their status, cleans custom fields, deassociates VLANs from the site, and optionally deletes the site after confirming each step."

    site = ObjectVar(
        model=Site,
        description="Select the RETIRED site to process",
        query_params={"status": "retired"}
    )
    move_confirmation = BooleanVar(description="Confirm moving devices to inventory")
    delete_confirmation = BooleanVar(description="Confirm deletion of the site")

    def run(self, data, commit):
        site = data['site']
        inventory_site = Site.objects.get(name="Inventory")

        if not data.get('move_confirmation'):
            self.log_warning("Move to inventory not confirmed. Operation cancelled.")
            return

        # Fetch devices from the site
        devices = Device.objects.filter(site=site)
        for device in devices:
            self.log_info(f"Moving and updating device: {device.name}")
            for field in device.custom_field_data:
                device.custom_field_data[field] = None
            device.site = inventory_site
            device.status = DeviceStatusChoices.STATUS_INVENTORY
            device.save()

        # Re-fetch or re-count the devices to check if any are still associated with the original site
        devices_left = Device.objects.filter(site=site).count()
        self.log_info(f"Devices remaining at site '{site.name}': {devices_left}")

        # Fetch, deassociate, and log VLANs
        vlans = VLAN.objects.filter(site=site)
        for vlan in vlans:
            self.log_info(f"Deassociating VLAN: {vlan.name} (ID: {vlan.pk}, VID: {vlan.vid})")
            vlan.site = None
            vlan.save()
        vlan_count = vlans.count()
        self.log_success(f"Deassociated {vlan_count} VLANs from '{site.name}'.")

        prefixes = Prefix.objects.filter(site=site)
        for prefix in prefixes:
            self.log_info(f"Deleting prefix: {prefix.prefix} (ID: {prefix.pk})")
        prefixes.delete()
        prefix_count = prefixes.count()
        self.log_success(f"Deleted {prefix_count} prefixes associated with '{site.name}'.")

        if data.get('delete_confirmation'):
            if devices_left == 0:
                site.delete()
                self.log_success(f"Site '{site.name}' deleted as no devices were left after reassignment.")
            else:
                self.log_warning("Site not deleted because there are still devices associated with it.")
        else:
            self.log_warning("Site deletion not confirmed.")

from extras.scripts import *
from extras.reports import Report
from dcim.models import Device, Site
from ipam.models import VLAN

class DeleteSiteAndDevicesScript(Script):
    class Meta:
        name = "Delete Retired Site and Its Devices"
        description = "Deletes a specified site in RETIRED status and all associated devices, deassociates VLANs from the site, and logs all actions."
    
    site = ObjectVar(
        model=Site,
        description="Select the RETIRED site to delete",
        query_params={
            "status": "retired"  # Adjust the value according to the actual status value in your database
        },
    )
    confirmation = BooleanVar(description="Confirm deletion")

    def run(self, data, commit):
        site = data['site']

        # Ensure confirmation is given to proceed with deletion
        if not data.get('confirmation'):
            self.log_warning("Deletion not confirmed. Operation cancelled.")
            return

        # Fetch and log devices before deletion
        devices = Device.objects.filter(site=site)
        for device in devices:
            self.log_info(f"Deleting device: {device.name}")
        device_count = devices.count()
        devices.delete()
        self.log_success(f"Deleted {device_count} devices associated with '{site.name}'.")

        # Fetch, deassociate, and log VLANs before site deletion
        vlans = VLAN.objects.filter(site=site)
        for vlan in vlans:
            self.log_info(f"Deassociating VLAN: {vlan.name} (ID: {vlan.pk}, VID: {vlan.vid}) from site: '{site.name}'")
            vlan.site = None
            vlan.save()
        vlan_count = vlans.count()
        self.log_success(f"Deassociated {vlan_count} VLANs from '{site.name}'.")

        # Delete the site
        site_name = site.name
        site.delete()
        self.log_success(f"Site '{site_name}' and all its devices have been successfully deleted.")

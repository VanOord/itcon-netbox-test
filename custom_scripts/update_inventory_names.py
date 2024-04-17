from dcim.models import Device, DeviceRole, DeviceType, Manufacturer, Site
from dcim.choices import *
from taggit.models import Tag
from extras.scripts import *


class UpdateDeviceNames(Script):
    class Meta:
        name = "Update SDWAN Device Names with Multiple Tags"
        description = "Updates device names for devices in a specific site with multiple inclusion tags and excludes those with any of the specified exclusion tags."
        field_order = ['site_name', 'include_tags', 'exclude_tags']

    site_name = StringVar(
        description="Name of the site",
        default="Inventory"
    )
    include_tags = StringVar(
        description="Comma-separated tags to include (leave blank to include all within site)",
        default="SDWAN Devices Meraki"
    )
    exclude_tags = StringVar(
        description="Comma-separated tags to exclude (leave blank to exclude none)",
        default="Site Mismatched Device"
    )

    def run(self, data, commit):
        # Convert comma-separated string to list and strip spaces
        include_tags_list = [tag.strip() for tag in data['include_tags'].split(',')] if data['include_tags'] else []
        exclude_tags_list = [tag.strip() for tag in data['exclude_tags'].split(',')] if data['exclude_tags'] else []

        # Start querying all devices in the specified site
        devices = Device.objects.filter(site__name=data['site_name'])

        # Filter by include tags if any
        if include_tags_list:
            devices = devices.filter(tags__name__in=include_tags_list).distinct()

        # Exclude by tags if any
        if exclude_tags_list:
            devices = devices.exclude(tags__name__in=exclude_tags_list)

        updated_devices = 0

        # Loop through each device and update the name
        for device in devices:
            new_name = f"{device.device_type} | {device.serial}"
            if device.name != new_name:
                device.name = new_name
                if commit:
                    device.save()
                self.log_success(f"Updated device {device.name} to new name {new_name}")
                updated_devices += 1
            else:
                self.log_info(f"No update required for {device.name}")

        return f"Total devices updated: {updated_devices}"


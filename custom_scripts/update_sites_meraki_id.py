from extras.scripts import *
from dcim.models import Device, Site
from meraki import DashboardAPI

class UpdateNetBoxSiteFromMeraki(Script):
    class Meta:
        name = "Update NetBox Site from Meraki"
        description = ("Fetches network devices and networks from the Meraki Dashboard, enriches the devices with "
                       "network names and URLs, updates NetBox sites with meraki_networkid, optionally updates "
                       "meraki_clientcrew_networkid for 'Client-Crew' networks, and then updates corresponding sites' "
                       "custom URLs based on device matches.")

    meraki_api_key = StringVar(description="Meraki API Key")
    
    def run(self, data, commit):
        dashboard = DashboardAPI(api_key=data['meraki_api_key'], suppress_logging=True)

        # Initialize logging and fetch organization ID
        self.log_info("Initializing Meraki Dashboard API session and fetching organization ID.")
        try:
            organizations = dashboard.organizations.getOrganizations()
            if len(organizations) != 1:
                self.log_failure("Multiple or no organizations found. Specify an organization ID.")
                return
            organization_id = organizations[0]['id']
        except Exception as e:
            self.log_failure(f"Failed to fetch organizations: {e}")
            return

        # Fetch network devices and networks from Meraki
        try:
            network_devices = dashboard.organizations.getOrganizationInventoryDevices(
                organization_id, total_pages='all')
            networks = dashboard.organizations.getOrganizationNetworks(
                organization_id, total_pages='all')
        except Exception as e:
            self.log_failure(f"Failed to fetch data from Meraki: {e}")
            return

        # Enrich devices with network names and URLs
        network_id_to_info = {network['id']: {'name': network['name'], 'url': network.get('url', 'Unknown')}
                              for network in networks}
        enriched_devices = [
            {
                **device,
                'networkName': network_id_to_info.get(device['networkId'], {}).get('name', 'Unknown'),
                'networkUrl': network_id_to_info.get(device['networkId'], {}).get('url', 'Unknown'),
                'networkId': device['networkId']
            } for device in network_devices if device.get('networkId')
        ]

        updated_sites_count = 0
        for site in Site.objects.all():
            # Flags to ensure each custom field is updated only once per site
            updated_networkid = False
            updated_clientcrew_networkid = False

            for device in Device.objects.filter(site=site):
                if updated_networkid and updated_clientcrew_networkid:
                    break  # Skip further processing if both fields are already updated

                matched_device = next((d for d in enriched_devices if d['serial'] == device.serial), None)
                if not matched_device:
                    continue  # Skip to the next device if there's no match

                # Handling 'meraki_networkid'
                if 'Client-Crew' not in matched_device['networkName'] and not updated_networkid:
                    site.custom_field_data['meraki_networkid'] = matched_device['networkId']
                    updated_networkid = True
                    self.log_success(f"Updated 'meraki_networkid' for site {site.name} with device {device.serial}.")

                # Handling 'meraki_clientcrew_networkid'
                elif 'Client-Crew' in matched_device['networkName'] and not updated_clientcrew_networkid:
                    site.custom_field_data['meraki_clientcrew_networkid'] = matched_device['networkId']
                    updated_clientcrew_networkid = True
                    self.log_success(f"Updated 'meraki_clientcrew_networkid' for site {site.name} with device {device.serial}.")

            if updated_networkid or updated_clientcrew_networkid:
                if commit:
                    site.save()
                    updated_sites_count += 1

        self.log_success(f"Completed updating Meraki network IDs for {updated_sites_count} sites.")

        self.log_info("Updating NetBox sites with custom URLs based on 'ClientCrew' presence.")
        updated_urls_count = 0
        for site in Site.objects.all():
            # Initialize flags to track updates to prevent redundant operations
            update_url = True
            update_clientcrew_url = True

            for device in Device.objects.filter(site=site):
                matched_device = next((d for d in enriched_devices if d['serial'] == device.serial), None)
                if matched_device:
                    if 'Client-Crew' in matched_device['networkName'] and update_clientcrew_url:
                        site.custom_field_data['clientcrew_url'] = matched_device['networkUrl']
                        self.log_success(f"Updated 'clientcrew_url' for site {site.name} based on device {device.serial}.")
                        update_clientcrew_url = False  # Prevent further updates for 'clientcrew_url'

                    elif 'Client-Crew' not in matched_device['networkName'] and update_url:
                        site.custom_field_data['url'] = matched_device['networkUrl']
                        self.log_success(f"Updated 'url' for site {site.name} based on device {device.serial}.")
                        update_url = False  # Prevent further updates for 'url'

                    elif not update_url and not update_clientcrew_url:
                        # Both 'url' and 'clientcrew_url' are updated, no need to check more devices
                        break

            if not update_url or not update_clientcrew_url:
                if commit:
                    site.save()
                    updated_urls_count += 1

        self.log_success(f"Completed updating custom URLs for {updated_urls_count} sites.")


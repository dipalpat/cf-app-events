import requests
import json
import argparse
import os
from getpass import getpass

def get_verify_param(verify_ssl, ca_bundle_path):
    """
    Helper to determine verify parameter for requests ---
    """
    if ca_bundle_path:
        return ca_bundle_path
    return verify_ssl

def get_uaa_endpoint(cf_api_url, verify_ssl, ca_bundle_path):
    """
    Step 1: Get UAA Endpoint
    """
    info_url = f"{cf_api_url}/v2/info"
    try:
        response = requests.get(info_url, verify=get_verify_param(verify_ssl, ca_bundle_path))
        response.raise_for_status()
        info_data = response.json()
        return info_data["authorization_endpoint"]
    except requests.exceptions.RequestException as e:
        print(f"Error getting UAA endpoint from {info_url}: {e}")
        return None

def get_access_token(uaa_url, username, password, client_id, client_secret, verify_ssl, ca_bundle_path):
    """
    Step 2: Authenticate and Get Access Token ---
    """
    token_url = f"{uaa_url}/oauth/token"
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json"
    }
    data = {
        "grant_type": "password",
        "username": username,
        "password": password,
        "client_id": client_id,
        "client_secret": client_secret
    }
    try:
        response = requests.post(token_url, headers=headers, data=data, verify=get_verify_param(verify_ssl, ca_bundle_path))
        response.raise_for_status()
        token_data = response.json()
        return token_data["access_token"]
    except requests.exceptions.RequestException as e:
        print(f"Error getting access token from {token_url}: {e}")
        return None

def fetch_all_paginated_resources(url, headers, verify_ssl, ca_bundle_path, resource_name="resources"):
    """
    Function to fetch all pages of a paginated API endpoint ---
    """
    all_resources = []
    current_url = url
    while current_url:
        try:
            response = requests.get(current_url, headers=headers, verify=get_verify_param(verify_ssl, ca_bundle_path))
            response.raise_for_status()
            data = response.json()
            all_resources.extend(data["resources"])
            current_url = data["pagination"]["next"]["href"] if "next" in data["pagination"] and data["pagination"]["next"] and data["pagination"]["next"]["href"] else None
        except requests.exceptions.RequestException as e:
            print(f"Error fetching {resource_name} from {current_url or url}: {e}")
            break
    return all_resources

def get_apps_and_instances_detailed(cf_api_url, access_token, verify_ssl, ca_bundle_path, suppress_console_output=False):
    """
    Function to get App and Instance Counts ---
    """
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/json"
    }

    if not suppress_console_output:
        print("\n--- Collecting Application Information ---")
    all_apps_raw = fetch_all_paginated_resources(
        f"{cf_api_url}/v3/apps", headers, verify_ssl, ca_bundle_path, "applications"
    )
    
    detailed_apps_info = []
    
    for app in all_apps_raw:
        app_name = app["name"]
        app_guid = app["guid"]
        
        running_instances_for_app = 0
        desired_instances_for_app = 0
        
        processes = fetch_all_paginated_resources(
            f"{cf_api_url}/v3/apps/{app_guid}/processes", headers, verify_ssl, ca_bundle_path, f"processes for app {app_name}"
        )
        
        process_details_for_json = [] # To store details for JSON output
        for process in processes:
            process_guid = process["guid"]
            process_type = process.get("type", "unknown")
            
            process_desired_instances = process.get("instances", 0)
            desired_instances_for_app += process_desired_instances

            # --- Get Running Instances from /v3/processes/:guid/stats ---
            stats_url = f"{cf_api_url}/v3/processes/{process_guid}/stats"
            actual_running_process_instances = 0
            try:
                stats_response = requests.get(stats_url, headers=headers, verify=get_verify_param(verify_ssl, ca_bundle_path))
                stats_response.raise_for_status()
                stats_data = stats_response.json()
                
                actual_running_process_instances = sum(1 for instance_stat in stats_data.get("resources", []) if instance_stat.get("state") == "RUNNING")
                running_instances_for_app += actual_running_process_instances
                
            except requests.exceptions.RequestException as e:
                if not suppress_console_output:
                    print(f"  Warning: Could not fetch stats for process '{process_type}' (GUID: {process_guid}): {e}")

            process_details_for_json.append({
                "guid": process_guid,
                "type": process_type,
                "desired_instances": process_desired_instances,
                "running_instances": actual_running_process_instances,
                # You can add more raw process data here if needed for JSON
                "raw_process_object_excerpt": {
                    "memory_in_mb": process.get("memory_in_mb"),
                    "disk_in_mb": process.get("disk_in_mb")
                }
            })

        detailed_apps_info.append({
            "name": app_name,
            "guid": app_guid,
            "state": app.get("state", "UNKNOWN"), # Include app state from /v3/apps
            "running_instances": running_instances_for_app,
            "desired_instances": desired_instances_for_app,
            "processes": process_details_for_json # Add collected process details
        })
        
        if not suppress_console_output:
            print(f"  App: '{app_name}' (GUID: {app_guid})")
            print(f"    Running Instances (sum from process stats): {running_instances_for_app}")
            print(f"    Desired Instances (sum from processes): {desired_instances_for_app}")
            if app.get("state") == "STOPPED":
                print("    (Note: App is STOPPED, running instances will likely be 0)")

    return detailed_apps_info

def get_services_info_detailed(cf_api_url, access_token, verify_ssl, ca_bundle_path, suppress_console_output=False):
    """
    Function to get Service Offerings and Service Instances ---
    """
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/json"
    }

    if not suppress_console_output:
        print("\n--- Collecting Service Information ---")
    
    # Get Service Offerings
    service_offerings = fetch_all_paginated_resources(
        f"{cf_api_url}/v3/service_offerings", headers, verify_ssl, ca_bundle_path, "service offerings"
    )
    if not suppress_console_output:
        print(f"Total number of service offerings (available marketplace services): {len(service_offerings)}")

    # Get Service Instances
    service_instances = fetch_all_paginated_resources(
        f"{cf_api_url}/v3/service_instances", headers, verify_ssl, ca_bundle_path, "service instances"
    )
    if not suppress_console_output:
        print(f"Total number of provisioned service instances: {len(service_instances)}")

    return service_offerings, service_instances



def fetch_all_audit_events(cf_api_url, access_token, verify_ssl, ca_bundle_path, suppress_console_output=False):
    """
    Function to get Audit event which will be filtered based on evaculation
    """
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/json"
    }

    if not suppress_console_output:
        print("\n--- Collecting Audit Events ---")
    
    # Get Service Offerings
    events = fetch_all_paginated_resources(
        f"{cf_api_url}/v3/audit_events", headers, verify_ssl, ca_bundle_path, "audit events"
    )

    evac_events = []
    for event in events:
        if (event.get("type") == "audit.app.process.rescheduling" and
            event.get("data", {}).get("reason") == "Cell is being evacuated"):
            evac_events.append(event)
    if not suppress_console_output:
        print(f"Total number of auditable events (related to app evacuation): {len(evac_events)}")

    return evac_events


def main():
    parser = argparse.ArgumentParser(
        description="Get Cloud Foundry app, instance, service, and service instance counts.\n"
                    "Output can be saved to a JSON file for later parsing.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument(
        '-e', '--endpoint',
        required=True,
        help='Cloud Foundry API endpoint (e.g., https://api.example.com)'
    )
    parser.add_argument(
        '-u', '--username',
        required=True,
        help='Cloud Foundry username'
    )
    parser.add_argument(
        '-p', '--password',
        help='Cloud Foundry password. If not provided, will prompt or use CF_PASSWORD env var.\n'
             'NOTE: Using --password directly on the command line is INSECURE for production.',
        default=argparse.SUPPRESS
    )
    parser.add_argument(
        '--no-verify-ssl',
        action='store_false',
        dest='verify_ssl',
        default=True,
        help='Do not verify SSL certificates (use for self-signed certificates or development environments).'
    )
    parser.add_argument(
        '--ca-certs',
        help='Path to a custom CA certificate bundle (e.g., /etc/ssl/certs/ca-certificates.crt).'
    )
    parser.add_argument(
        '-o', '--output-file',
        help='Path to a JSON file where the output will be saved. If not specified, output to console.'
    )

    args = parser.parse_args()

    CLOUD_CONTROLLER_URL = args.endpoint
    USERNAME = args.username
    VERIFY_SSL = args.verify_ssl
    CA_BUNDLE_PATH = args.ca_certs
    OUTPUT_FILE = args.output_file

    password = None
    if 'password' in args:
        password = args.password
    elif os.getenv("CF_PASSWORD"):
        password = os.getenv("CF_PASSWORD")
    else:
        password = getpass("Enter your Cloud Foundry password: ")

    if not password:
        print("Password is required and was not provided via command line, environment variable, or interactive prompt.")
        exit(1)

    if not VERIFY_SSL and not CA_BUNDLE_PATH:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        print("WARNING: SSL verification is disabled. This is NOT recommended for production.")
    elif CA_BUNDLE_PATH and VERIFY_SSL:
        print(f"INFO: Using custom CA bundle: {CA_BUNDLE_PATH}")


    uaa_endpoint = get_uaa_endpoint(CLOUD_CONTROLLER_URL, VERIFY_SSL, CA_BUNDLE_PATH)
    if not uaa_endpoint:
        print("Failed to get UAA endpoint. Exiting.")
        exit(1)
    print(f"\nUAA Endpoint: {uaa_endpoint}")

    access_token = get_access_token(uaa_endpoint, USERNAME, password, "cf", "", VERIFY_SSL, CA_BUNDLE_PATH)
    if not access_token:
        print("Failed to get access token. Exiting.")
        exit(1)
    print("Successfully obtained access token.")

    # Determine if console output should be suppressed
    suppress_console_output = OUTPUT_FILE is not None

    # Fetch Apps and Instances
    detailed_apps_info = get_apps_and_instances_detailed(
        CLOUD_CONTROLLER_URL, access_token, VERIFY_SSL, CA_BUNDLE_PATH, suppress_console_output
    )
    num_apps = len(detailed_apps_info)
    total_running_instances_agg = sum(app_info['running_instances'] for app_info in detailed_apps_info)
    total_desired_instances_agg = sum(app_info['desired_instances'] for app_info in detailed_apps_info)


    # Fetch Services and Service Instances
    service_offerings_list, service_instances_list = get_services_info_detailed(
        CLOUD_CONTROLLER_URL, access_token, VERIFY_SSL, CA_BUNDLE_PATH, suppress_console_output
    )
    num_service_offerings = len(service_offerings_list)
    num_service_instances = len(service_instances_list)

    # Fetch Audit Events
    events = fetch_all_audit_events(
        CLOUD_CONTROLLER_URL, access_token, VERIFY_SSL, CA_BUNDLE_PATH, suppress_console_output
    )
    num_audit_events = len(events)

    # --- Prepare Output Data ---
    output_data = {
        "summary": {
            "total_apps": num_apps,
            "total_running_app_instances": total_running_instances_agg,
            "total_desired_app_instances": total_desired_instances_agg,
            "total_service_offerings": num_service_offerings,
            "total_provisioned_service_instances": num_service_instances,
            "total_audit_events": num_audit_events
        },
        "detailed_data": {
            "apps": detailed_apps_info,
            "service_offerings": service_offerings_list,
            "service_instances": service_instances_list,
            "audit_events": events
        },
        "metadata": {
            "timestamp": requests.utils.default_headers()["User-Agent"] # Placeholder for system time
        }
    }
    # Update timestamp with current time
    import datetime
    output_data["metadata"]["timestamp"] = datetime.datetime.now(datetime.timezone.utc).isoformat()


    # --- Output Results ---
    if OUTPUT_FILE:
        try:
            with open(OUTPUT_FILE, 'w') as f:
                json.dump(output_data, f, indent=4)
            print(f"\nData successfully written to {OUTPUT_FILE}")
        except IOError as e:
            print(f"Error writing to file {OUTPUT_FILE}: {e}")
    else:
        print("\n--- Final Summary ---")
        print(f"Overall Apps: {num_apps}")
        print(f"Overall Running App Instances: {total_running_instances_agg}")
        print(f"Overall Desired App Instances: {total_desired_instances_agg}")
        print(f"Overall Service Offerings (marketplace services): {num_service_offerings}")
        print(f"Overall Provisioned Service Instances: {num_service_instances}")
        print(f"Total audit event with evacution: {num_audit_events}")


if __name__ == "__main__":
    main()

import requests
import json
import argparse
import os
import threading
import time
import datetime
from getpass import getpass
from concurrent.futures import ThreadPoolExecutor, as_completed
from queue import Queue
import urllib3
from pathlib import Path

class TokenManager:
    """Thread-safe token manager with automatic refresh"""
    
    def __init__(self, uaa_url, username=None, password=None, client_id="cf", client_secret="", 
                 verify_ssl=True, ca_bundle_path=None, access_token=None, refresh_token=None):
        self.uaa_url = uaa_url
        self.username = username
        self.password = password
        self.client_id = client_id
        self.client_secret = client_secret
        self.verify_ssl = verify_ssl
        self.ca_bundle_path = ca_bundle_path
        
        self._token = access_token
        self._refresh_token = refresh_token
        self._token_expiry = None
        self._lock = threading.Lock()
        self._refresh_thread = None
        self._stop_refresh = threading.Event()
        
        # Initial token acquisition or validation
        if self._token:
            self._token_expiry = time.time() + 1800
            print("Using existing access token from CF CLI config")
        else:
            # Fallback to username/password authentication
            self._refresh_token_with_credentials()
        
        self._start_refresh_thread()
    
    def _refresh_token_with_credentials(self):
        """Refresh the access token using username/password"""
        if not self.username or not self.password:
            raise Exception("No existing token and no credentials provided for authentication")
            
        token_url = f"{self.uaa_url}/oauth/token"
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json"
        }
        data = {
            "grant_type": "password",
            "username": self.username,
            "password": self.password,
            "client_id": self.client_id,
            "client_secret": self.client_secret
        }
        
        try:
            response = requests.post(
                token_url, 
                headers=headers, 
                data=data, 
                verify=get_verify_param(self.verify_ssl, self.ca_bundle_path)
            )
            response.raise_for_status()
            token_data = response.json()
            
            with self._lock:
                self._token = token_data["access_token"]
                self._refresh_token = token_data.get("refresh_token")
                # Set expiry to 10 minutes before actual expiry
                expires_in = token_data.get("expires_in", 43200)  # 12 hours?
                self._token_expiry = time.time() + expires_in - 600  # 10 minutes buffer
                
            print(f"Token refreshed using credentials at {datetime.datetime.now().isoformat()}")
            return True
        except requests.exceptions.RequestException as e:
            print(f"Error refreshing token with credentials: {e}")
            return False
    
    def _refresh_token_with_refresh_token(self):
        """Refresh the access token using refresh token"""
        if not self._refresh_token:
            print("No refresh token available, falling back to credential-based refresh")
            return self._refresh_token_with_credentials()
            
        token_url = f"{self.uaa_url}/oauth/token"
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json"
        }
        data = {
            "grant_type": "refresh_token",
            "refresh_token": self._refresh_token,
            "client_id": self.client_id,
            "client_secret": self.client_secret
        }
        
        try:
            response = requests.post(
                token_url, 
                headers=headers, 
                data=data, 
                verify=get_verify_param(self.verify_ssl, self.ca_bundle_path)
            )
            response.raise_for_status()
            token_data = response.json()
            
            with self._lock:
                self._token = token_data["access_token"]
                self._refresh_token = token_data.get("refresh_token", self._refresh_token)
                # Set expiry to 10 minutes before actual expiry
                expires_in = token_data.get("expires_in", 43200)
                self._token_expiry = time.time() + expires_in - 600  # 10 minutes buffer
                
            print(f"Token refreshed using refresh token at {datetime.datetime.now().isoformat()}")
            return True
        except requests.exceptions.RequestException as e:
            print(f"Error refreshing token with refresh token: {e}")
            print("Falling back to credential-based refresh")
            return self._refresh_token_with_credentials()
    
    def _start_refresh_thread(self):
        """Start the background token refresh thread"""
        def refresh_worker():
            while not self._stop_refresh.is_set():
                current_time = time.time()
                with self._lock:
                    time_until_refresh = self._token_expiry - current_time if self._token_expiry else 300
                
                if time_until_refresh <= 0:
                    print("Token expired, refreshing...")
                    if not self._refresh_token_with_refresh_token():
                        print("Failed to refresh token, continuing with existing token")
                    time_until_refresh = 300  # Check again in 5 minutes
                
                # Wait for the shorter of: time until refresh or 5 minutes
                wait_time = min(time_until_refresh, 300)
                if self._stop_refresh.wait(wait_time):
                    break
        
        self._refresh_thread = threading.Thread(target=refresh_worker, daemon=True)
        self._refresh_thread.start()
    
    def get_token(self):
        """Get the current valid token"""
        with self._lock:
            # Check if token needs immediate refresh
            if self._token_expiry and time.time() >= self._token_expiry:
                print("Token needs immediate refresh...")
                if not self._refresh_token_with_refresh_token():
                    print("Warning: Failed to refresh token immediately")
            return self._token
    
    def stop(self):
        """Stop the token refresh thread"""
        self._stop_refresh.set()
        if self._refresh_thread:
            self._refresh_thread.join(timeout=5)

def get_verify_param(verify_ssl, ca_bundle_path):
    """
    Helper to determine verify parameter for requests
    """
    if ca_bundle_path:
        return ca_bundle_path
    return verify_ssl

def load_cf_config():
    """
    Load configuration from CF CLI config file
    """
    cf_config_path = Path.home() / ".cf" / "config.json"
    
    if not cf_config_path.exists():
        print(f"CF CLI config file not found at {cf_config_path}")
        return None
    
    try:
        with open(cf_config_path, 'r') as f:
            config = json.load(f)
        
        # Extract relevant information
        cf_config = {
            "target": config.get("Target"),
            "access_token": config.get("AccessToken"),
            "refresh_token": config.get("RefreshToken"),
            "uaa_endpoint": config.get("UaaEndpoint"),
            "ssl_disabled": config.get("SSLDisabled", False)
        }
        
        # Validate required fields
        if not cf_config["target"]:
            print("No target found in CF CLI config")
            return None
            
        if not cf_config["access_token"]:
            print("No access token found in CF CLI config. Please run 'cf login' first.")
            return None
        
        return cf_config
        
    except (json.JSONDecodeError, IOError) as e:
        print(f"Error reading CF CLI config file: {e}")
        return None

def validate_token(cf_api_url, access_token, verify_ssl, ca_bundle_path):
    """
    Validate the access token by making a test API call
    """
    test_url = f"{cf_api_url}/v3/info"
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/json"
    }
    
    try:
        response = requests.get(
            test_url, 
            headers=headers, 
            verify=get_verify_param(verify_ssl, ca_bundle_path)
        )
            
        if response.status_code == 200:
            print("Token validation successful")
            return True
        else:
            print(f"Token validation failed with status {response.status_code}: {response.text}")
            return False
    except requests.exceptions.RequestException as e:
        print(f"Token validation error: {e}")
        return False

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

def fetch_all_paginated_resources_threaded(url, token_manager, verify_ssl, ca_bundle_path, resource_name="resources"):
    """
    Thread-safe function to fetch all pages of a paginated API endpoint
    """
    all_resources = []
    current_url = url
    retry_count = 0
    max_retries = 2
    
    while current_url:
        try:
            headers = {
                "Authorization": f"Bearer {token_manager.get_token()}",
                "Accept": "application/json"
            }
            
            response = requests.get(
                current_url, 
                headers=headers, 
                verify=get_verify_param(verify_ssl, ca_bundle_path)
            )
            
            # Handle 401 Unauthorized - try to refresh token and retry
            if response.status_code == 401 and retry_count < max_retries:
                print(f"Received 401 for {resource_name}, attempting token refresh (attempt {retry_count + 1}/{max_retries})")
                # Force token refresh
                token_manager._refresh_token_with_refresh_token()
                retry_count += 1
                continue  # Retry with new token
            
            response.raise_for_status()
            data = response.json()
            all_resources.extend(data["resources"])
            current_url = (data["pagination"]["next"]["href"] 
                          if "next" in data["pagination"] 
                          and data["pagination"]["next"] 
                          and data["pagination"]["next"]["href"] 
                          else None)
            retry_count = 0  # Reset retry count on success
            
        except requests.exceptions.RequestException as e:
            print(f"Error fetching {resource_name} from {current_url or url}: {e}")
            break
    
    return all_resources

def fetch_app_process_stats(cf_api_url, process_guid, token_manager, verify_ssl, ca_bundle_path):
    """
    Fetch process stats for a single process
    """
    stats_url = f"{cf_api_url}/v3/processes/{process_guid}/stats"
    try:
        headers = {
            "Authorization": f"Bearer {token_manager.get_token()}",
            "Accept": "application/json"
        }
        
        stats_response = requests.get(
            stats_url, 
            headers=headers, 
            verify=get_verify_param(verify_ssl, ca_bundle_path)
        )
        stats_response.raise_for_status()
        stats_data = stats_response.json()
        
        return sum(1 for instance_stat in stats_data.get("resources", []) 
                  if instance_stat.get("state") == "RUNNING")
    except requests.exceptions.RequestException as e:
        print(f"Warning: Could not fetch stats for process GUID {process_guid}: {e}")
        return 0

def process_single_app(app, cf_api_url, token_manager, verify_ssl, ca_bundle_path, max_workers):
    """
    Process a single app and its processes with threading
    """
    app_name = app["name"]
    app_guid = app["guid"]
    
    # Fetch processes for this app
    processes = fetch_all_paginated_resources_threaded(
        f"{cf_api_url}/v3/apps/{app_guid}/processes", 
        token_manager, 
        verify_ssl, 
        ca_bundle_path, 
        f"processes for app {app_name}"
    )
    
    process_details_for_json = []
    running_instances_for_app = 0
    desired_instances_for_app = 0
    
    # Use ThreadPoolExecutor for process stats fetching
    with ThreadPoolExecutor(max_workers=min(max_workers, len(processes))) as executor:
        future_to_process = {}
        
        for process in processes:
            process_guid = process["guid"]
            process_type = process.get("type", "unknown")
            process_desired_instances = process.get("instances", 0)
            desired_instances_for_app += process_desired_instances
            
            # Submit stats fetching task
            future = executor.submit(
                fetch_app_process_stats, 
                cf_api_url, 
                process_guid, 
                token_manager, 
                verify_ssl, 
                ca_bundle_path
            )
            future_to_process[future] = (process, process_type, process_desired_instances)
        
        # Collect results
        for future in as_completed(future_to_process):
            process, process_type, process_desired_instances = future_to_process[future]
            actual_running_process_instances = future.result()
            running_instances_for_app += actual_running_process_instances
            
            process_details_for_json.append({
                "guid": process["guid"],
                "type": process_type,
                "desired_instances": process_desired_instances,
                "running_instances": actual_running_process_instances,
                "raw_process_object_excerpt": {
                    "memory_in_mb": process.get("memory_in_mb"),
                    "disk_in_mb": process.get("disk_in_mb")
                }
            })
    
    return {
        #"name": app_name,
        "guid": app_guid,
        "state": app.get("state", "UNKNOWN"),
        "running_instances": running_instances_for_app,
        "desired_instances": desired_instances_for_app,
        "processes": process_details_for_json
    }

def get_apps_and_instances_detailed_threaded(cf_api_url, token_manager, verify_ssl, ca_bundle_path, 
                                           suppress_console_output=False, max_workers=5):
    """
    Multi-threaded function to get App and Instance Counts
    """
    if not suppress_console_output:
        print(f"\n--- Collecting Application Information (using {max_workers} threads) ---")
    
    # Fetch all apps
    all_apps_raw = fetch_all_paginated_resources_threaded(
        f"{cf_api_url}/v3/apps", 
        token_manager, 
        verify_ssl, 
        ca_bundle_path, 
        "applications"
    )
    
    detailed_apps_info = []
    
    # Process apps in parallel
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_app = {
            executor.submit(
                process_single_app, 
                app, 
                cf_api_url, 
                token_manager, 
                verify_ssl, 
                ca_bundle_path, 
                max_workers
            ): app for app in all_apps_raw
        }
        
        for future in as_completed(future_to_app):
            app_info = future.result()
            detailed_apps_info.append(app_info)
            
            if not suppress_console_output:
                print(f"  App: '{app_info['name']}' (GUID: {app_info['guid']})")
                print(f"    Running Instances: {app_info['running_instances']}")
                print(f"    Desired Instances: {app_info['desired_instances']}")
                if app_info.get("state") == "STOPPED":
                    print("    (Note: App is STOPPED, running instances will likely be 0)")
    
    return detailed_apps_info

def get_services_info_detailed_threaded(cf_api_url, token_manager, verify_ssl, ca_bundle_path, 
                                       suppress_console_output=False):
    """
    Function to get Service Offerings and Service Instances (with threading support)
    """
    if not suppress_console_output:
        print("\n--- Collecting Service Information ---")
    
    # Use threading for parallel fetching of service offerings and instances
    with ThreadPoolExecutor(max_workers=2) as executor:
        # Submit both tasks
        offerings_future = executor.submit(
            fetch_all_paginated_resources_threaded,
            f"{cf_api_url}/v3/service_offerings",
            token_manager,
            verify_ssl,
            ca_bundle_path,
            "service offerings"
        )
        
        instances_future = executor.submit(
            fetch_all_paginated_resources_threaded,
            f"{cf_api_url}/v3/service_instances",
            token_manager,
            verify_ssl,
            ca_bundle_path,
            "service instances"
        )
        
        # Get results
        service_offerings = offerings_future.result()
        service_instances = instances_future.result()
    
    if not suppress_console_output:
        print(f"Total number of service offerings (available marketplace services): {len(service_offerings)}")
        print(f"Total number of provisioned service instances: {len(service_instances)}")
    
    return service_offerings, service_instances

def fetch_all_audit_events_threaded(cf_api_url, token_manager, verify_ssl, ca_bundle_path, 
                                   suppress_console_output=False):
    """
    Function to get Audit events which will be filtered based on evacuation
    """
    if not suppress_console_output:
        print("\n--- Collecting Audit Events ---")
    
    # Get all events
    events = fetch_all_paginated_resources_threaded(
        f"{cf_api_url}/v3/audit_events", 
        token_manager, 
        verify_ssl, 
        ca_bundle_path, 
        "audit events"
    )
    
    # Filter evacuation events
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
                    "Uses CF CLI config by default, with fallback to username/password.\n",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument(
        '-e', '--endpoint',
        help='Cloud Foundry API endpoint (e.g., https://api.example.com). '
             'If not provided, will use target from CF CLI config.'
    )
    parser.add_argument(
        '-u', '--username',
        help='Cloud Foundry username (only needed if not using CF CLI config)'
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
        help='Path to a custom CA certificate bundle'
    )
    parser.add_argument(
        '-o', '--output-file',
        help='Path to a JSON file where the output will be saved. If not specified, output to console.'
    )
    parser.add_argument(
        '-t', '--threads',
        type=int,
        default=5,
        help='Number of threads to use for parallel processing (default: 5)'
    )
    parser.add_argument(
        '--force-credentials',
        action='store_true',
        help='Force username/password authentication instead of using CF CLI config'
    )

    args = parser.parse_args()

    VERIFY_SSL = args.verify_ssl
    CA_BUNDLE_PATH = args.ca_certs
    OUTPUT_FILE = args.output_file
    MAX_WORKERS = args.threads
    FORCE_CREDENTIALS = args.force_credentials

    # Try to load CF CLI config first (unless forced to use credentials)
    cf_config = None
    if not FORCE_CREDENTIALS:
        cf_config = load_cf_config()

    # Determine authentication method and endpoints
    if cf_config and not FORCE_CREDENTIALS:
        # Use CF CLI config
        CLOUD_CONTROLLER_URL = args.endpoint or cf_config["target"]
        uaa_endpoint = cf_config["uaa_endpoint"]
        access_token = cf_config["access_token"]
        refresh_token = cf_config["refresh_token"]
        
        # Override SSL verification if CF CLI has it disabled
        if cf_config["ssl_disabled"]:
            VERIFY_SSL = False
            print("INFO: SSL verification disabled based on CF CLI config")
        
        # Validate the token before proceeding
        print("INFO: Validating CF CLI access token...")
        if not validate_token(CLOUD_CONTROLLER_URL, access_token, VERIFY_SSL, CA_BUNDLE_PATH):
            print("WARNING: CF CLI token validation failed. Falling back to credential authentication.")
            print("This might happen if your CF session has expired. Try running 'cf login' again.")
            cf_config = None  # Force fallback to credentials
        else:
            print("INFO: Using CF CLI configuration for authentication")
            username = None
            password = None
        
    else:
        # Fall back to username/password authentication
        if not args.endpoint:
            print("ERROR: --endpoint is required when not using CF CLI config")
            exit(1)
        
        if not args.username:
            args.username = input("Enter your Cloud Foundry username: ")
            
        CLOUD_CONTROLLER_URL = args.endpoint
        username = args.username
        access_token = None
        refresh_token = None
        
        uaa_endpoint = get_uaa_endpoint(CLOUD_CONTROLLER_URL, VERIFY_SSL, CA_BUNDLE_PATH)
        if not uaa_endpoint:
            print("Failed to get UAA endpoint. Exiting.")
            exit(1)
        
        # Handle password
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
            
        print("INFO: Using username/password authentication")

    if not VERIFY_SSL and not CA_BUNDLE_PATH:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        print("WARNING: SSL verification is disabled. This is NOT recommended for production.")
    elif CA_BUNDLE_PATH and VERIFY_SSL:
        print(f"INFO: Using custom CA bundle: {CA_BUNDLE_PATH}")

    print(f"INFO: Using {MAX_WORKERS} threads for parallel processing")
    print(f"INFO: Target endpoint: {CLOUD_CONTROLLER_URL}")
    print(f"INFO: UAA endpoint: {uaa_endpoint}")

    # Initialize token manager
    token_manager = None
    try:
        token_manager = TokenManager(
            uaa_endpoint, 
            username=username, 
            password=password, 
            client_id="cf", 
            client_secret="", 
            verify_ssl=VERIFY_SSL, 
            ca_bundle_path=CA_BUNDLE_PATH,
            access_token=access_token,
            refresh_token=refresh_token
        )
        print("Successfully initialized token manager with automatic refresh.")

        # Determine if console output should be suppressed
        suppress_console_output = OUTPUT_FILE is not None

        start_time = time.time()

        with ThreadPoolExecutor(max_workers=3) as main_executor:
            # Submit main data collection tasks
            apps_future = main_executor.submit(
                get_apps_and_instances_detailed_threaded,
                CLOUD_CONTROLLER_URL, token_manager, VERIFY_SSL, CA_BUNDLE_PATH, 
                suppress_console_output, MAX_WORKERS
            )
            
            services_future = main_executor.submit(
                get_services_info_detailed_threaded,
                CLOUD_CONTROLLER_URL, token_manager, VERIFY_SSL, CA_BUNDLE_PATH, 
                suppress_console_output
            )
            
            audit_future = main_executor.submit(
                fetch_all_audit_events_threaded,
                CLOUD_CONTROLLER_URL, token_manager, VERIFY_SSL, CA_BUNDLE_PATH, 
                suppress_console_output
            )

            # Get results
            detailed_apps_info = apps_future.result()
            service_offerings_list, service_instances_list = services_future.result()
            events = audit_future.result()

        end_time = time.time()
        execution_time = end_time - start_time

        num_apps = len(detailed_apps_info)
        total_running_instances_agg = sum(app_info['running_instances'] for app_info in detailed_apps_info)
        total_desired_instances_agg = sum(app_info['desired_instances'] for app_info in detailed_apps_info)
        num_service_offerings = len(service_offerings_list)
        num_service_instances = len(service_instances_list)
        num_audit_events = len(events)

        output_data = {
            "summary": {
                "total_apps": num_apps,
                "total_running_app_instances": total_running_instances_agg,
                "total_desired_app_instances": total_desired_instances_agg,
                "total_service_offerings": num_service_offerings,
                "total_provisioned_service_instances": num_service_instances,
                "total_audit_events": num_audit_events,
                "execution_time_seconds": round(execution_time, 2),
                "threads_used": MAX_WORKERS
            },
            "detailed_data": {
                "apps": detailed_apps_info,
                "service_offerings": service_offerings_list,
                "service_instances": service_instances_list,
                "audit_events": events
            },
            "metadata": {
                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "execution_time_seconds": round(execution_time, 2),
                "threads_used": MAX_WORKERS,
                "authentication_method": "cf_cli_config" if cf_config and not FORCE_CREDENTIALS else "username_password",
                "target_endpoint": CLOUD_CONTROLLER_URL
            }
        }

        if OUTPUT_FILE:
            try:
                with open(OUTPUT_FILE, 'w') as f:
                    json.dump(output_data, f, indent=4)
                print(f"\nData successfully written to {OUTPUT_FILE}")
                print(f"Execution completed in {execution_time:.2f} seconds using {MAX_WORKERS} threads")
            except IOError as e:
                print(f"Error writing to file {OUTPUT_FILE}: {e}")
        else:
            print("\n--- Final Summary ---")
            print(f"Overall Apps: {num_apps}")
            print(f"Overall Running App Instances: {total_running_instances_agg}")
            print(f"Overall Desired App Instances: {total_desired_instances_agg}")
            print(f"Overall Service Offerings (marketplace services): {num_service_offerings}")
            print(f"Overall Provisioned Service Instances: {num_service_instances}")
            print(f"Total audit events with evacuation: {num_audit_events}")
            print(f"Execution time: {execution_time:.2f} seconds using {MAX_WORKERS} threads")

    except Exception as e:
        print(f"Error during execution: {e}")
        exit(1)
    finally:
        if token_manager:
            token_manager.stop()
            print("Token manager stopped.")

if __name__ == "__main__":
    main()

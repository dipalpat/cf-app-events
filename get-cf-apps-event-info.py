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
            # If we have an existing token, set a conservative expiry
            # CF CLI tokens are typically valid for 12 hours, but we'll be conservative
            self._token_expiry = time.time() + 1800  # 30 minutes conservative estimate
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
                # Set expiry to 10 minutes before actual expiry (default is usually 12 hours)
                expires_in = token_data.get("expires_in", 43200)  # Default 12 hours
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
                expires_in = token_data.get("expires_in", 43200)  # Default 12 hours
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
        
        # Debug: Show token format and length (don't show actual token for security)
        token_preview = cf_config["access_token"][:20] + "..." if len(cf_config["access_token"]) > 20 else cf_config["access_token"]
        print(f"Loaded CF CLI config - Target: {cf_config['target']}")
        print(f"Token preview: {token_preview} (length: {len(cf_config['access_token'])})")
        
        return cf_config
        
    except (json.JSONDecodeError, IOError) as e:
        print(f"Error reading CF CLI config file: {e}")
        return None

def validate_token(cf_api_url, access_token, verify_ssl, ca_bundle_path, debug=False):
    """
    Validate the access token by making a test API call
    """
    test_url = f"{cf_api_url}/v3/info"
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/json"
    }
    
    if debug:
        print(f"DEBUG: Testing token with URL: {test_url}")
        print(f"DEBUG: Token starts with: {access_token[:50]}...")
    
    try:
        response = requests.get(
            test_url, 
            headers=headers, 
            verify=get_verify_param(verify_ssl, ca_bundle_path)
        )
        if debug:
            print(f"DEBUG: Response status: {response.status_code}")
            print(f"DEBUG: Response headers: {dict(response.headers)}")
            
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

def fetch_all_paginated_resources(url, token_manager, verify_ssl, ca_bundle_path, resource_name="resources", show_progress=True):
    """
    Thread-safe function to fetch all pages of a paginated API endpoint
    """
    all_resources = []
    current_url = url
    retry_count = 0
    max_retries = 2
    page_count = 0
    total_fetched = 0
    start_time = time.time()
    estimated_total = None
    
    # Add per_page parameter for larger page sizes (CF API supports up to 5000)
    if "?" in current_url:
        current_url += "&per_page=5000"
    else:
        current_url += "?per_page=5000"
    
    if show_progress:
        print(f"  Fetching {resource_name}...", end="", flush=True)
    
    while current_url:
        try:
            headers = {
                "Authorization": f"Bearer {token_manager.get_token()}",
                "Accept": "application/json"
            }
            
            page_start_time = time.time()
            response = requests.get(
                current_url, 
                headers=headers, 
                verify=get_verify_param(verify_ssl, ca_bundle_path)
            )
            page_duration = time.time() - page_start_time
            
            # Handle 401 Unauthorized - try to refresh token and retry
            if response.status_code == 401 and retry_count < max_retries:
                if show_progress:
                    print(f"\n    Refreshing token for {resource_name} (attempt {retry_count + 1}/{max_retries})", end="", flush=True)
                # Force token refresh
                token_manager._refresh_token_with_refresh_token()
                retry_count += 1
                continue  # Retry with new token
            
            response.raise_for_status()
            data = response.json()
            page_resources = data["resources"]
            all_resources.extend(page_resources)
            
            page_count += 1
            total_fetched += len(page_resources)
            
            # Get pagination info for progress tracking
            pagination = data.get("pagination", {})
            total_results = pagination.get("total_results", 0)
            
            # Update estimated total on first page
            if estimated_total is None and total_results > 0:
                estimated_total = total_results
            
            # Enhanced progress display
            if show_progress:
                elapsed_time = time.time() - start_time
                avg_page_time = elapsed_time / page_count if page_count > 0 else 0
                if estimated_total and estimated_total > 0:
                    # Calculate progress percentage
                    progress_pct = (total_fetched / estimated_total) * 100
    
                    # Show different levels of detail based on page count
                    if page_count <= 5 or page_count % 10 == 0:
                        print(f"\n    Page {page_count}: {total_fetched}/{estimated_total} items ({progress_pct:.1f}%)", end="", flush=True)                
                    else:
                        print(f".", end="", flush=True)
                else:
                    # No total available, just show basic progress
                    if page_count <= 5 or page_count % 10 == 0:
                        print(f"\n    Page {page_count}: {total_fetched} items (duration: {page_duration:.2f}s)", end="", flush=True)
                    else:
                        print(f".", end="", flush=True)
                
            current_url = (pagination["next"]["href"] 
                          if "next" in pagination 
                          and pagination["next"] 
                          and pagination["next"]["href"] 
                          else None)
            
            retry_count = 0  # Reset retry count on success
            
        except requests.exceptions.RequestException as e:
            if show_progress:
                print(f"\n  Error fetching {resource_name}: {e}")
            else:
                print(f"Error fetching {resource_name} from {current_url or url}: {e}")
            break
    
    if show_progress and total_fetched > 0:
        total_time = time.time() - start_time
        items_per_second = total_fetched / total_time if total_time > 0 else 0
        print(f"\n  {resource_name} complete: {total_fetched} items, {page_count} pages ({items_per_second:.1f} items/sec)", flush=True)
    elif show_progress:
        print(f"\n  {resource_name} complete: 0 items", flush=True)
    
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
        # Suppress individual process warnings to reduce noise
        return 0

def process_single_app(app, cf_api_url, token_manager, verify_ssl, ca_bundle_path, max_workers, app_index, total_apps):
    """
    Process a single app and its processes with threading
    """
    app_name = app["name"]
    app_guid = app["guid"]
    
    # Enhanced progress display for individual apps
    if app_index % 25 == 0 or app_index in [1, 5, 10]:  # Show more frequent updates early on
        progress_pct = (app_index / total_apps) * 100
        #print(f"    Processing apps: {app_index}/{total_apps} ({progress_pct:.1f}%) - Current: {app_name[:30]}{'...' if len(app_name) > 30 else ''}", flush=True)
        print(f"    Processing apps: {app_index}/{total_apps} ({progress_pct:.1f}%)", flush=True)
    
    # Fetch processes for this app
    processes = fetch_all_paginated_resources(
        f"{cf_api_url}/v3/apps/{app_guid}/processes", 
        token_manager, 
        verify_ssl, 
        ca_bundle_path, 
        f"processes for app {app_name}",
        show_progress=False  # Don't show progress for individual app processes
    )
    
    process_details_for_json = []
    running_instances_for_app = 0
    desired_instances_for_app = 0
    
    # Use ThreadPoolExecutor for process stats fetching
    if processes:
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
        "guid": app_guid,
        "state": app.get("state", "UNKNOWN"),
        "running_instances": running_instances_for_app,
        "desired_instances": desired_instances_for_app,
        "processes": process_details_for_json
    }

def get_apps_and_instances_detailed(cf_api_url, token_manager, verify_ssl, ca_bundle_path, 
                                           suppress_console_output=False, max_workers=5):
    """
    Multi-threaded function to get App and Instance Counts
    """
    if not suppress_console_output:
        print(f"\n--- Collecting Application Information (using {max_workers} threads) ---")
    
    # Fetch all apps with progress
    all_apps_raw = fetch_all_paginated_resources(
        f"{cf_api_url}/v3/apps", 
        token_manager, 
        verify_ssl, 
        ca_bundle_path, 
        "applications",
        show_progress=not suppress_console_output
    )
    
    if not suppress_console_output:
        print(f"  Processing {len(all_apps_raw)} applications with detailed analysis...")
    
    detailed_apps_info = []
    start_time = time.time()
    
    # Process apps in parallel with progress tracking
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_app = {}
        
        for index, app in enumerate(all_apps_raw):
            future = executor.submit(
                process_single_app, 
                app, 
                cf_api_url, 
                token_manager, 
                verify_ssl, 
                ca_bundle_path, 
                max_workers,
                index + 1,
                len(all_apps_raw)
            )
            future_to_app[future] = app
        
        completed_count = 0
        last_progress_update = 0
        
        for future in as_completed(future_to_app):
            app_info = future.result()
            detailed_apps_info.append(app_info)
            completed_count += 1
            
            # Enhanced progress reporting with timing
            if not suppress_console_output:
                current_time = time.time()
                elapsed_time = current_time - start_time
                
                # Show progress at key milestones or every 30 seconds
                should_show_progress = (
                    completed_count % 50 == 0 or 
                    completed_count == len(all_apps_raw) or
                    completed_count in [1, 5, 10, 25] or
                    (current_time - last_progress_update) >= 30
                )

                if should_show_progress:
                    progress_pct = (completed_count / len(all_apps_raw)) * 100
                    apps_per_second = completed_count / elapsed_time if elapsed_time > 0 else 0
    
                    print(f"  Progress: {completed_count}/{len(all_apps_raw)} apps ({progress_pct:.1f}%) - {apps_per_second:.1f} apps/sec", flush=True)
                    last_progress_update = current_time
    
    if not suppress_console_output:
        total_time = time.time() - start_time
        total_running = sum(app['running_instances'] for app in detailed_apps_info)
        total_desired = sum(app['desired_instances'] for app in detailed_apps_info)
        avg_processing_time = total_time / len(all_apps_raw) if all_apps_raw else 0
        
        print(f"  Applications complete: {total_running} running / {total_desired} desired instances")
        print(f"  Processing time: {total_time:.2f}s total ({avg_processing_time:.3f}s per app)")
    
    return detailed_apps_info

def get_services_info_detailed(cf_api_url, token_manager, verify_ssl, ca_bundle_path, 
                                       suppress_console_output=False):
    """
    Function to get Service Offerings and Service Instances
    """
    if not suppress_console_output:
        print("\n--- Collecting Service Information ---")
    
    # Use threading for parallel fetching of service offerings and instances
    with ThreadPoolExecutor(max_workers=2) as executor:
        start_time = time.time()
        
        # Submit both tasks
        offerings_future = executor.submit(
            fetch_all_paginated_resources,
            f"{cf_api_url}/v3/service_offerings",
            token_manager,
            verify_ssl,
            ca_bundle_path,
            "service offerings",
            show_progress=not suppress_console_output
        )
        
        instances_future = executor.submit(
            fetch_all_paginated_resources,
            f"{cf_api_url}/v3/service_instances",
            token_manager,
            verify_ssl,
            ca_bundle_path,
            "service instances",
            show_progress=not suppress_console_output
        )
        
        # Get results
        service_offerings = offerings_future.result()
        service_instances = instances_future.result()
        
        total_time = time.time() - start_time
    
    if not suppress_console_output:
        print(f"  Service data complete: {len(service_offerings)} offerings, {len(service_instances)} instances")
        print(f"  Collection time: {total_time:.2f}s")
    
    return service_offerings, service_instances

def fetch_all_audit_events(cf_api_url, token_manager, verify_ssl, ca_bundle_path, 
                                   suppress_console_output=False):
    """
    Function to get Audit events
    """
    if not suppress_console_output:
        print("\n--- Collecting Audit Events ---")
    
    start_time = time.time()
    
    # Get all events with progress
    events = fetch_all_paginated_resources(
        f"{cf_api_url}/v3/audit_events", 
        token_manager, 
        verify_ssl, 
        ca_bundle_path, 
        "audit events",
        show_progress=not suppress_console_output
    )
    
    # Filter evacuation events with progress indication
    if not suppress_console_output:
        print("  Filtering evacuation events...", end="", flush=True)
    
    filter_start_time = time.time()
    evac_events = []
    
    for i, event in enumerate(events):
        if (event.get("type") == "audit.app.process.rescheduling" and
            event.get("data", {}).get("reason") == "Cell is being evacuated"):
            evac_events.append(event)
        
        # Show progress for large event sets
        if not suppress_console_output and len(events) > 1000 and i % 1000 == 0 and i > 0:
            print(f"\n    Filtered {i}/{len(events)} events...", end="", flush=True)
    
    filter_time = time.time() - filter_start_time
    total_time = time.time() - start_time
    
    if not suppress_console_output:
        print(f"\n  Audit analysis complete: {len(evac_events)} evacuation events found from {len(events)} total events")
        print(f"  Processing time: {total_time:.2f}s (filtering: {filter_time:.2f}s)")
    
    return evac_events

def main():
    parser = argparse.ArgumentParser(
        description="Get Cloud Foundry app, instance, service, and service instance counts.\n",
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
        help='Path to a custom CA certificate bundle (e.g., /etc/ssl/certs/ca-certificates.crt).'
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
    parser.add_argument(
        '--debug',
        action='store_true',
        help='Enable debug output for troubleshooting'
    )
    parser.add_argument(
        '--include-audit-events',
        action='store_true',
        help='Skip collecting audit events to speed up execution'
    )

    args = parser.parse_args()

    VERIFY_SSL = args.verify_ssl
    CA_BUNDLE_PATH = args.ca_certs
    OUTPUT_FILE = args.output_file
    MAX_WORKERS = args.threads
    FORCE_CREDENTIALS = args.force_credentials
    DEBUG = args.debug
    SKIP_AUDIT_EVENTS = not args.include_audit_events

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
        if not validate_token(CLOUD_CONTROLLER_URL, access_token, VERIFY_SSL, CA_BUNDLE_PATH, DEBUG):
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
        
        # Get UAA endpoint
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

    print(f"INFO: Using {MAX_WORKERS} threads")
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
        suppress_console_output = False #OUTPUT_FILE is not None

        start_time = time.time()

        print("Starting Cloud Foundry data collection...")

        # Determine how many main executor threads to use based on what we're collecting
        main_executor_workers = 2 if SKIP_AUDIT_EVENTS else 3

        # Fetch all data using threading
        with ThreadPoolExecutor(max_workers=main_executor_workers) as main_executor:
            # Submit main data collection tasks
            apps_future = main_executor.submit(
                get_apps_and_instances_detailed,
                CLOUD_CONTROLLER_URL, token_manager, VERIFY_SSL, CA_BUNDLE_PATH, 
                suppress_console_output, MAX_WORKERS
            )
            
            services_future = main_executor.submit(
                get_services_info_detailed,
                CLOUD_CONTROLLER_URL, token_manager, VERIFY_SSL, CA_BUNDLE_PATH, 
                suppress_console_output
            )
            
            # Only submit audit events collection if not skipped
            if not SKIP_AUDIT_EVENTS:
                audit_future = main_executor.submit(
                    fetch_all_audit_events,
                    CLOUD_CONTROLLER_URL, token_manager, VERIFY_SSL, CA_BUNDLE_PATH, 
                    suppress_console_output
                )

            # Get results with progress indication
            if not suppress_console_output:
                print("\nWaiting for data collection to complete...")
                
            detailed_apps_info = apps_future.result()
            service_offerings_list, service_instances_list = services_future.result()
            
            # Only get audit events if we collected them
            if not SKIP_AUDIT_EVENTS:
                events = audit_future.result()
            else:
                events = []
                if not suppress_console_output:
                    print("Audit events collection skipped per --skip-audit-events flag")


        print(" ************************************************************************")
        end_time = time.time()
        execution_time = end_time - start_time

        if not suppress_console_output:
            print(f"\nData collection complete in {execution_time:.2f} seconds!")
            print(f"Performance summary:")
            print(f"   - Total execution time: {execution_time:.2f}s")
            print(f"   - Threads utilized: {MAX_WORKERS}")
            print(f"   - Authentication method: {'CF CLI config' if cf_config and not FORCE_CREDENTIALS else 'Username/Password'}")
            if SKIP_AUDIT_EVENTS:
                print(f"   - Audit events: Skipped")
            else:
                print(f"   - Audit events: Collected")

        # Calculate aggregates
        print("Calculating aggregates...")
        num_apps = len(detailed_apps_info)
        total_running_instances_agg = sum(app_info['running_instances'] for app_info in detailed_apps_info)
        total_desired_instances_agg = sum(app_info['desired_instances'] for app_info in detailed_apps_info)
        num_service_offerings = len(service_offerings_list)
        num_service_instances = len(service_instances_list)
        num_audit_events = len(events)

        # Prepare output data
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
                "target_endpoint": CLOUD_CONTROLLER_URL,
                "progress_tracking_enabled": True,
                "audit_events_collected": not SKIP_AUDIT_EVENTS
            }
        }

        # Output results
        if OUTPUT_FILE:
            try:
                print(f"\nWriting data to {OUTPUT_FILE}...")
                print(f"  - Total apps: {num_apps}")
                print(f"  - Service offerings: {num_service_offerings}")
                print(f"  - Service instances: {num_service_instances}")
                print(f"  - Audit events: {num_audit_events}")
                print(f"  Serializing data to JSON format...")
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
            
            # Additional performance insights
            if num_apps > 0:
                apps_per_second = num_apps / execution_time
                print(f"Performance: {apps_per_second:.1f} apps processed per second")

    except Exception as e:
        print(f"Error during execution: {e}")
        exit(1)
    finally:
        # Clean up token manager
        if token_manager:
            token_manager.stop()
            print("Token manager stopped.")

if __name__ == "__main__":
    main()

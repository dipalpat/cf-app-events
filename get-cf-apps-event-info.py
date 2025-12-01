import requests
import json
import argparse
import os
import threading
import time
import datetime
from getpass import getpass
from concurrent.futures import ThreadPoolExecutor, as_completed
import urllib3
from pathlib import Path
import base64

class TokenManager:
    """token manager with refresh"""

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
            # Parse the actual expiry from the token
            expiry = self._get_token_expiry_from_jwt(self._token)
            if expiry:
                # Set expiry to 5 minutes before actual expiry for safety buffer
                self._token_expiry = expiry - 300
                expiry_dt = datetime.datetime.fromtimestamp(expiry)
                time_left = expiry - time.time()
                print(f"Using existing access token (expires: {expiry_dt.isoformat()}, {time_left/60:.1f} minutes left)")
            else:
                # Fallback if we can't parse the token
                self._token_expiry = time.time() + 1800  # 30 minutes conservative estimate
                print("Using existing access token (could not parse expiry, using conservative 30min estimate)")
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
                expiry = self._get_token_expiry_from_jwt(self._token)

                if expiry:
                    self._token_expiry = expiry - 300
                    expiry_dt = datetime.datetime.fromtimestamp(expiry)
                    time_until_expiry = expiry - time.time()
                    print(f"Token refreshed using credentials. Valid until: {expiry_dt.isoformat()} ({time_until_expiry/60:.1f} minutes)")
                else:
                    # Set expiry to 10 minutes before actual expiry (default is usually 12 hours)
                    expires_in = token_data.get("expires_in", 43200)  # Default 12 hours
                    self._token_expiry = time.time() + expires_in - 600  # 10 minutes buffer
                    print(f"Token refreshed using credentials at {datetime.datetime.now().isoformat()}")

            return True
        except requests.exceptions.RequestException as e:
            print(f"Error refreshing token with credentials: {e}")
            return False

    def _start_refresh_thread(self):
        """Start the background token refresh thread"""
        def refresh_worker():
            while not self._stop_refresh.is_set():
                current_time = time.time()
                with self._lock:
                    time_until_refresh = self._token_expiry - current_time if self._token_expiry else 300

                if time_until_refresh <= 0:
                    print("Token expired, refreshing...")
                    if not self._refresh_token_with_cf_cli():
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
        # First check if refresh is needed (with lock)
        needs_refresh = False
        with self._lock:
            if self._token_expiry and time.time() >= self._token_expiry:
                needs_refresh = True

        # Refresh outside the lock to avoid deadlock
        if needs_refresh:
            print("Token needs immediate refresh...")
            if not self._refresh_token_with_cf_cli():
                print("Warning: Failed to refresh token immediately")

        # Get the token (with lock)
        with self._lock:
            return self._token


    def _get_token_expiry_from_jwt(self, token):
        """Extract expiry timestamp from JWT token"""
        try:
            # JWT structure: header.payload.signature
            parts = token.split('.')
            if len(parts) < 2:
                return None

            # Base64Url decode the payload
            payload = parts[1]
            # Add padding if needed
            payload += '=' * (-len(payload) % 4)

            decoded_bytes = base64.urlsafe_b64decode(payload)
            decoded_str = decoded_bytes.decode('utf-8')
            token_data = json.loads(decoded_str)

            # Return the 'exp' claim if present
            return token_data.get('exp')
        except Exception as e:
            print(f"Error parsing token expiry: {e}")
            return None

    def _refresh_token_with_cf_cli(self):
        """Refresh the access token using cf oauth-token command"""
        import subprocess

        try:
            # Run cf oauth-token command
            result = subprocess.run(
                ['cf', 'oauth-token'],
                capture_output=True,
                text=True,
                check=True
            )

            # The output is in format: "bearer <token>"
            token_output = result.stdout.strip()

            if not token_output.startswith('bearer '):
                print(f"Unexpected token format from cf oauth-token: {token_output}")
                return False

            # Extract the token (remove "bearer " prefix)
            new_token = token_output[7:]  # Skip "bearer " (7 characters)

            with self._lock:
                self._token = new_token
                # CF CLI manages the refresh token internally, so we don't need to track it
                expiry = self._get_token_expiry_from_jwt(new_token)

                if expiry:
                    current_time = time.time()
                    time_until_expiry = expiry - current_time

                    # Check if token has reasonable validity left
                    if time_until_expiry < 600:  # Less than 10 minutes
                        print(f"WARNING: Token from cf oauth-token expires in {time_until_expiry/60:.1f} minutes!")
                        # Use the token anyway but with minimal buffer
                        self._token_expiry = expiry - 60  # Just 1 minute buffer
                    else:
                        # Set local expiry to 5 minutes before actual expiry
                        self._token_expiry = expiry - 300

                    expiry_dt = datetime.datetime.fromtimestamp(expiry)
                    print(f"Token refreshed. Valid until: {expiry_dt.isoformat()} ({time_until_expiry/60:.1f} minutes)")
                else:
                    # Fallback if we can't parse the token
                    print("Could not parse token expiry, defaulting to 12 hours")
                    self._token_expiry = time.time() + 43200 - 300

            print(f"Token refreshed using cf oauth-token at {datetime.datetime.now().isoformat()}")
            return True

        except subprocess.CalledProcessError as e:
            print(f"Error running cf oauth-token: {e}")
            print(f"stderr: {e.stderr}")
            if self.username and self.password:
                print("Falling back to credential-based refresh")
                return self._refresh_token_with_credentials()
            return False
        except FileNotFoundError:
            print("cf CLI not found in PATH")
            if self.username and self.password:
                print("Falling back to credential-based refresh")
                return self._refresh_token_with_credentials()
            return False

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
                token_manager._refresh_token_with_cf_cli()
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

def process_single_app(app, cf_api_url, token_manager, verify_ssl, ca_bundle_path, max_workers, app_index, total_apps):
    """
    Process a single app and collect its metadata
    """
    app_name = app["name"]
    app_guid = app["guid"]

    # Enhanced progress display for individual apps
    if app_index % 25 == 0 or app_index in [1, 5, 10]:
        progress_pct = (app_index / total_apps) * 100
        print(f"    Processing apps: {app_index}/{total_apps} ({progress_pct:.1f}%)", flush=True)

    # Fetch processes for this app
    processes = fetch_all_paginated_resources(
        f"{cf_api_url}/v3/apps/{app_guid}/processes",
        token_manager,
        verify_ssl,
        ca_bundle_path,
        f"processes for app {app_name}",
        show_progress=False
    )

    # Extract process details from the first process (typically 'web')
    process_type = "unknown"
    memory_mb = None
    disk_mb = None

    if processes and len(processes) > 0:
        first_process = processes[0]
        process_type = first_process.get("type", "unknown")
        memory_mb = first_process.get("memory_in_mb")
        disk_mb = first_process.get("disk_in_mb")

    # Extract space GUID from relationships or href
    space_guid = None
    if "relationships" in app and "space" in app["relationships"]:
        space_guid = app["relationships"]["space"]["data"]["guid"]
    elif "space" in app and "href" in app["space"]:
        space_guid = extract_guid_from_href(app["space"]["href"])

    # Extract lifecycle information (buildpacks and stack)
    buildpacks = []
    stack = "unknown"

    if "lifecycle" in app:
        lifecycle = app["lifecycle"]
        lifecycle_type = lifecycle.get("type", "")

        if lifecycle_type == "buildpack":
            # Extract buildpacks from lifecycle.data.buildpacks
            if "data" in lifecycle and "buildpacks" in lifecycle["data"]:
                buildpacks = lifecycle["data"]["buildpacks"]

            # Extract stack - try multiple locations
            if "data" in lifecycle and "stack" in lifecycle["data"]:
                stack = lifecycle["data"]["stack"]
            elif "relationships" in app and "stack" in app["relationships"]:
                stack_data = app["relationships"]["stack"].get("data", {})
                if "name" in stack_data:
                    stack = stack_data["name"]

    # Build the result dictionary
    return {
        "guid": app_guid,
        "state": app.get("state", "UNKNOWN"),
        "running_instances": 0,  # Add this field (set to 0 since not fetching stats)
        "desired_instances": app.get("total_desired_instances", 0),
        "build_packs": buildpacks,
        "stack": stack,
        "space_guid": space_guid,
        "type": process_type,
        "memory_in_mb": memory_mb,
        "disk_in_mb": disk_mb
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
        total_desired = sum(app['desired_instances'] for app in detailed_apps_info)
        avg_processing_time = total_time / len(all_apps_raw) if all_apps_raw else 0

        print(f"  Applications complete: {total_desired} desired instances")
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
    with ThreadPoolExecutor(max_workers=3) as executor:
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

        brokers_future = executor.submit(
            fetch_all_paginated_resources,
            f"{cf_api_url}/v3/service_brokers",
            token_manager,
            verify_ssl,
            ca_bundle_path,
            "service brokers",
            show_progress=not suppress_console_output
        )

        # Get results
        service_offerings = offerings_future.result()
        service_instances = instances_future.result()
        service_brokers = brokers_future.result()

        total_time = time.time() - start_time

    if not suppress_console_output:
        print(f"  Service data complete: {len(service_offerings)} offerings, {len(service_instances)} instances, {len(service_brokers)} brokers")
        print(f"  Collection time: {total_time:.2f}s")

    return service_offerings, service_instances, service_brokers

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


def get_orgs_and_spaces(cf_api_url, token_manager, verify_ssl, ca_bundle_path, suppress_console_output=False):
    """
    Function to get Organizations and Spaces with threading
    """
    if not suppress_console_output:
        print("\n--- Collecting Organization and Space Information ---")

    # Use threading for parallel fetching of organizations and spaces
    with ThreadPoolExecutor(max_workers=2) as executor:
        start_time = time.time()

        # Submit both tasks
        orgs_future = executor.submit(
            fetch_all_paginated_resources,
            f"{cf_api_url}/v3/organizations",
            token_manager,
            verify_ssl,
            ca_bundle_path,
            "organizations",
            show_progress=not suppress_console_output
        )

        spaces_future = executor.submit(
            fetch_all_paginated_resources,
            f"{cf_api_url}/v3/spaces",
            token_manager,
            verify_ssl,
            ca_bundle_path,
            "spaces",
            show_progress=not suppress_console_output
        )

        # Get results
        organizations = orgs_future.result()
        spaces = spaces_future.result()

        total_time = time.time() - start_time

    if not suppress_console_output:
        print(f"  Org/Space data complete: {len(organizations)} organizations, {len(spaces)} spaces")
        print(f"  Collection time: {total_time:.2f}s")

    return organizations, spaces


def extract_guid_from_href(href):
    """Extract GUID from a CF API href URL"""
    if not href:
        return None
    # href format: https://api.example.com/v3/spaces/{guid}
    parts = href.rstrip('/').split('/')
    return parts[-1] if parts else None

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
        main_executor_workers = 3 if SKIP_AUDIT_EVENTS else 4

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

            # Add orgs and spaces collection
            orgs_spaces_future = main_executor.submit(
                get_orgs_and_spaces,
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
            service_offerings_list, service_instances_list, service_brokers_list = services_future.result()
            organizations_list, spaces_list = orgs_spaces_future.result()

            # Only get audit events if we collected them
            if not SKIP_AUDIT_EVENTS:
                events = audit_future.result()
            else:
                events = []
                if not suppress_console_output:
                    print("Audit events collection skipped per --skip-audit-events flag")


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
        total_running_instances_agg = sum(app_info.get('running_instances', 0) for app_info in detailed_apps_info)
        total_desired_instances_agg = sum(app_info.get('desired_instances', 0) for app_info in detailed_apps_info)
        num_service_offerings = len(service_offerings_list)
        num_service_instances = len(service_instances_list)
        num_service_brokers = len(service_brokers_list)
        num_organizations = len(organizations_list)
        num_spaces = len(spaces_list)
        num_audit_events = len(events)

        # Prepare minimal org/space data with only GUIDs
        orgs_minimal = [{"guid": org["guid"], "name": org.get("name", "unknown")} for org in organizations_list]
        spaces_minimal = []
        for space in spaces_list:
            org_guid = None
            # Try to get org_guid from relationships
            if "relationships" in space and "organization" in space["relationships"]:
                org_guid = space["relationships"]["organization"]["data"]["guid"]

            spaces_minimal.append({
                "guid": space["guid"],
                "org_guid": org_guid
            })

        # Prepare minimal service offerings data (only guid and relationships)
        service_offerings_minimal = []
        for offering in service_offerings_list:
            service_offerings_minimal.append({
                "guid": offering["guid"],
                "relationships": offering.get("relationships", {})
            })

        # Prepare minimal service instances data (only guid, type, and relationships)
        service_instances_minimal = []
        for instance in service_instances_list:
            service_instances_minimal.append({
                "guid": instance["guid"],
                "type": instance.get("type", "unknown"),
                "relationships": instance.get("relationships", {})
            })

        # Prepare minimal service brokers data (only guid and relationships/space)
        service_brokers_minimal = []
        for broker in service_brokers_list:
            broker_data = {
                "guid": broker["guid"]
            }

            # Extract space guid from relationships if it exists (for space-scoped brokers)
            if "relationships" in broker and "space" in broker["relationships"]:
                space_data = broker["relationships"]["space"].get("data")
                if space_data:
                    broker_data["space_guid"] = space_data.get("guid")

            service_brokers_minimal.append(broker_data)

        # Prepare output data
        output_data = {
            "summary": {
                "total_apps": num_apps,
                "total_running_app_instances": total_running_instances_agg,
                "total_desired_app_instances": total_desired_instances_agg,
                "total_service_offerings": num_service_offerings,
                "total_provisioned_service_instances": num_service_instances,
                "total_service_brokers": num_service_brokers,
                "total_organizations": num_organizations,
                "total_spaces": num_spaces,
                "total_audit_events": num_audit_events,
                "execution_time_seconds": round(execution_time, 2),
                "threads_used": MAX_WORKERS
            },
            "detailed_data": {
                "apps": detailed_apps_info,
                "service_offerings": service_offerings_minimal,
                "service_instances": service_instances_minimal,
                "service_brokers": service_brokers_minimal,
                "organizations": orgs_minimal,  # Only GUID and name
                "spaces": spaces_minimal,        # Only GUID and name
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
                print(f"  - Organizations: {num_organizations}")
                print(f"  - Spaces: {num_spaces}")
                print(f"  - Service offerings: {num_service_offerings}")
                print(f"  - Service instances: {num_service_instances}")
                print(f"  - Service brokers: {num_service_brokers}")
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
            print(f"Overall Organizations: {num_organizations}")
            print(f"Overall Spaces: {num_spaces}")
            print(f"Overall Apps: {num_apps}")
            print(f"Overall Running App Instances: {total_running_instances_agg}")
            print(f"Overall Desired App Instances: {total_desired_instances_agg}")
            print(f"Overall Service Offerings (marketplace services): {num_service_offerings}")
            print(f"Overall Provisioned Service Instances: {num_service_instances}")
            print(f"Overall Service Brokers: {num_service_brokers}")
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

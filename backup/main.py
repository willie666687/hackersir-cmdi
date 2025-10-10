from flask import Flask, request, render_template, redirect, url_for
import docker
import sys
import signal
import secrets
import requests
import urllib.parse

app = Flask(__name__)
client = docker.from_env()
IMAGE_NAME = "ctf-ping-vuln"
global port_now
port_now = 9999
global containers
containers = []
CADDY_API_URL = "http://localhost:2019"

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        password = create_user_container()
        global port_now
        base_url = request.url_root.rstrip('/')
        encoded_password = urllib.parse.quote(password)
        full_url = f"{base_url}/cmdi-{port_now}/?password={encoded_password}"
        return render_template("index.html", url=full_url)
    else:
        return render_template("index.html")

def add_caddy_route(port):
    """Add reverse proxy route using Caddy API"""
    try:
        # Get current routes
        server_key = "srv0"
        routes_url = f"{CADDY_API_URL}/config/apps/http/servers/{server_key}/routes"
        response = requests.get(routes_url)
        
        if response.status_code != 200:
            print(f"Failed to get routes: {response.status_code}")
            return
            
        current_routes = response.json()
        
        # Define the new route
        new_route = {
            "@id": f"cmdi-{port}",
            "match": [{"path": [f"/cmdi-{port}/*"]}],
            "handle": [
                {
                    "handler": "subroute",
                    "routes": [
                        {
                            "handle": [
                                {
                                    "handler": "rewrite",
                                    "strip_path_prefix": f"/cmdi-{port}"
                                },
                                {
                                    "handler": "reverse_proxy",
                                    "upstreams": [{"dial": f"localhost:{port}"}]
                                }
                            ]
                        }
                    ]
                }
            ]
        }
        
        # Insert at the beginning (before the catch-all reverse proxy)
        updated_routes = [new_route] + current_routes
        
        # Use PATCH to update the routes array
        patch_data = updated_routes
        response = requests.patch(routes_url, json=patch_data)
        
        if response.status_code in [200, 201]:
            # Verify it was added
            verify_response = requests.get(routes_url)
            if verify_response.status_code == 200:
                routes = verify_response.json()
        else:
            print(f"Failed to add Caddy route: {response.status_code} - {response.text}")
            
    except Exception as e:
        print(f"Error adding Caddy route: {e}")
        import traceback
        traceback.print_exc()
    
def remove_caddy_route(port):
    """Remove reverse proxy route using Caddy API"""
    try:
        # Remove the route by ID
        api_url = f"{CADDY_API_URL}/id/cmdi-{port}"
        response = requests.delete(api_url)
        
        if response.status_code in [200, 404]:  # 404 is OK if route doesn't exist
            print(f"Removed Caddy route for port {port}")
        else:
            print(f"Failed to remove Caddy route: {response.status_code} - {response.text}")
            
    except Exception as e:
        print(f"Error removing Caddy route: {e}")

def create_user_container():
    global port_now
    port_now += 1
    secure_password = secrets.token_urlsafe(16)
    container = client.containers.run(
        IMAGE_NAME,
        detach=True,
        ports={'80/tcp': port_now},
        name=f"ctf_{port_now}",
        environment={"CMDI_PASSWORD": secure_password},
        auto_remove=True,
        mem_limit="50m",
        mem_reservation="35m",
        cpu_percent=10,
        cpu_rt_runtime=900000
    )
    global containers
    containers.append(container)

    add_caddy_route(port_now)

    return secure_password

def signal_handler(signum, frame):
    stop_containers()
    sys.exit(0)

def stop_containers():
    global containers
    print("\nStopping all containers...")
    for container in containers:
        try:
            port = int(container.name.split('_')[1])
            remove_caddy_route(port)
            
            container.stop()
            print(f"Stopped container: {container.name}")
        except Exception as e:
            print(f"Error stopping container {container.name}: {e}")
    containers.clear()
    print("All containers stopped.")

if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)
    app.run(host="0.0.0.0", port=81)
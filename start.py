import subprocess
import sys
import time

def start_services():
    # Start the FastAPI server
    api_process = subprocess.Popen(
        [sys.executable, "main.py"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    
    # Start the scan simulation service
    simulation_process = subprocess.Popen(
        [sys.executable, "simulate_scans.py"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    
    print("Services started!")
    print("API server running at http://localhost:8000")
    print("API documentation available at http://localhost:8000/docs")
    print("\nPress Ctrl+C to stop all services")
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping services...")
        api_process.terminate()
        simulation_process.terminate()
        print("Services stopped!")

if __name__ == "__main__":
    start_services()
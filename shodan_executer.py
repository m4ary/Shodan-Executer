import shodan
import threading
import os
import json
import subprocess
import argparse
import multiprocessing
from termcolor import colored
from tqdm import tqdm
import datetime
import shutil

# Load configuration from JSON
with open('config.json', 'r') as f:
    config = json.load(f)

api = shodan.Shodan(config['SHODAN_API_KEY'])

# Define the log filenames and other files
success_log_file = 'success_log.txt'
fail_log_file = 'fail_log.txt'
subprocess_output_log_file = 'subprocess_output_log.txt'
shodan_results_file = 'shodan_results.json'
progress_tracker_file = 'progress_tracker.txt'

# Global exit signal for threads
exit_signal = False

# Determine the number of threads to use
num_threads = config.get('num_threads', multiprocessing.cpu_count())

def test_command(ip, port, pbar, smoke=False):
    global exit_signal
    
    # Construct the command from the config
    cmd = config['remote_code_on_target'].format(ip=ip, port=port)
    
    if smoke:
        print(f"Executing command: {cmd}")
    
    # Capture the subprocess output
    process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = process.communicate()

    # Append the subprocess output to the log file
    with open(subprocess_output_log_file, 'a') as f:
        f.write(f"Output for {ip}:{port}\\n")
        f.write(stdout.decode('utf-8') + "\\n")
        f.write(stderr.decode('utf-8') + "\\n")

    log_entry = f"{ip}:{port}\\n"
    
    # Check the output for matching text
    if config['success_text'] in stdout.decode('utf-8'):
        print(colored(f"[GOOD] Remote is verified exploitable {ip}:{port}", 'green'))
        with open(success_log_file, 'a') as f:
            f.write(log_entry + "\\n")
    elif config['error_text'] in stdout.decode('utf-8'):
        print(colored(f"[FAIL] Remote is not vulnerable {ip}:{port}", 'red'))
        with open(fail_log_file, 'a') as f:
            f.write(log_entry + "\\n")
    
    # Update the progress tracker with the last IP processed
    with open(progress_tracker_file, 'w') as f:
        f.write(ip)
    
    # Update the progress bar after the test is done
    pbar.update(1)

def search_and_test(search, port, limit, smoke=False, reset=False):
    global exit_signal

    # Load previous Shodan results or fetch new results based on the reset flag
    if os.path.exists(shodan_results_file) and not reset:
        with open(shodan_results_file, 'r') as f:
            results = json.load(f)
    else:
        results = api.search(search, limit=limit)
        with open(shodan_results_file, 'w') as f:
            json.dump(results, f)

    threads = []

    # Determine the starting point based on the progress tracker
    last_processed_ip = None
    if os.path.exists(progress_tracker_file) and not reset:
        with open(progress_tracker_file, 'r') as f:
            last_processed_ip = f.read().strip()
    
    start_processing = False if last_processed_ip else True

    # Initialize the progress bar
    with tqdm(total=len(results['matches']), desc='Testing', unit='device', dynamic_ncols=True) as pbar:
        for result in results['matches']:
            if exit_signal:
                break

            ip = result['ip_str']

            # If starting point is identified, begin processing
            if start_processing or ip == last_processed_ip:
                start_processing = True
                t = threading.Thread(target=test_command, args=(ip, port, pbar, smoke))
                t.daemon = True  # Set thread as daemon
                threads.append(t)
                t.start()

                # If we've started the max number of threads, wait for one to finish
                while len(threading.enumerate()) > num_threads:
                    pass

        # Wait for all threads to complete with timeout
        for t in threads:
            try:
                t.join(timeout=config.get('thread_timeout', 60))
            except:
                pass

def smoke_test():
    print("Running smoke test...")
    search_query = config['search_query']
    target_port = config['target_port']
    limit = 10  # Default limit for smoke test
    search_and_test(search_query, target_port, limit, smoke=True)



def reset_logs_and_results():
    """Reset logs and results by moving them to a new folder with a timestamp."""
    current_time = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    backup_dir = os.path.join("backup", current_time)
    
    if not os.path.exists(backup_dir):
        os.makedirs(backup_dir)
    
    files_to_move = [success_log_file, fail_log_file, subprocess_output_log_file, shodan_results_file, progress_tracker_file]
    for file in files_to_move:
        if os.path.exists(file):
            shutil.move(file, backup_dir)


# Load configuration from JSON
def load_config(file_path):
    with open(file_path, 'r') as f:
        return json.load(f)

# Global file paths initialization
def initialize_file_paths(project_folder):
    global success_log_file, fail_log_file, subprocess_output_log_file, shodan_results_file, progress_tracker_file
    success_log_file = os.path.join(project_folder, 'success_log.txt')
    fail_log_file = os.path.join(project_folder, 'fail_log.txt')
    subprocess_output_log_file = os.path.join(project_folder, 'subprocess_output_log.txt')
    shodan_results_file = os.path.join(project_folder, 'shodan_results.json')
    progress_tracker_file = os.path.join(project_folder, 'progress_tracker.txt')

def main():
    parser = argparse.ArgumentParser(description='Remote Scanner Script: A tool that leverages the Shodan API to scan and test remote systems based on a given configuration.')

    parser.add_argument('-c', '--config',required=True, 
                        default='config.json',
                        help='Path to the configuration file. Default is "config.json".')
    
    parser.add_argument('-p', '--project',required=True, 
                        default='default_project',
                        help='Project folder for all outputs, logs, and results. Default is "default_project".')
    
    parser.add_argument('--smoke', 
                        action='store_true', 
                        help='Run a smoke test. This will perform a limited test run to verify the script functionality.')
    
    parser.add_argument('--reset', 
                        action='store_true', 
                        help='Start from scratch. This will move the existing logs/results to a backup directory with a timestamp and start processing from the beginning.')
    
    args = parser.parse_args()

    # Create the project directory if it doesn't exist
    if not os.path.exists(args.project):
        os.makedirs(args.project)

    # Initialize file paths based on the project folder
    initialize_file_paths(args.project)

    global config
    config = load_config(args.config)

    if args.reset:
        reset_logs_and_results()

    if args.smoke:
        smoke_test()
    else:
        try:
            search_and_test(config['search_query'], config['target_port'], config['limit'], reset=args.reset)
        except KeyboardInterrupt:
            print("\nCaught Ctrl+C. Shutting down...")
            exit_signal = True



if __name__ == "__main__":
    main()
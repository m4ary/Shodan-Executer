
# Shodan Executer

Shodan Executer is a tool designed to utilize the Shodan API to scan and test remote systems for specific vulnerabilities or configurations based on user-defined parameters.

## Features

- **Shodan Integration**: Leverage the power of the Shodan API to identify potential targets.
- **Custom Configurations**: Easily specify test configurations through a JSON file.
- **Multithreading**: Efficiently test multiple targets concurrently.
- **Progress Tracking**: Ability to resume testing from where it left off.
- **Output Management**: Organize logs and results in a specified project folder.
- **Smoke Testing**: Run limited tests to verify functionality.

## Installation

1. Clone the repository:
```
git clone <URL_of_your_GitHub_repository>
```

2. Navigate to the Shodan Executer directory:
```
cd <repository_name>
```

3. Install the required Python libraries:
```
pip install -r requirements.txt
```

## Configuration

Configuration parameters should be defined in a JSON file named `config.json`. A template (`config_template.json`) is provided in the repository. Rename this file to `config.json` and fill in the necessary details.

Here are the configuration parameters with examples:

- `SHODAN_API_KEY`: Your Shodan API key. (e.g., "YOUR_SHODAN_API_KEY_HERE")
- `remote_code_on_target`: The command you want to execute on the target. (e.g., "nc {ip} {port}")
- `success_text`: Text that indicates a successful test. (e.g., "Connection successful")
- `error_text`: Text that indicates a failed test. (e.g., "Connection failed")
- `search_query`: Your Shodan search query. (e.g., "apache")
- `target_port`: Target port for the test. (e.g., "80")
- `limit`: Limit for the Shodan search results. (e.g., "100")
- `num_threads`: Number of threads for testing. (e.g., "10")
- `thread_timeout`: Timeout for each thread in seconds. (e.g., "60")

## Usage

```
python Shodan_Executer.py -c <config_file> -p <project_folder> [--smoke] [--reset]
```

- `-c, --config`: Specify the path to the configuration file (Required).
- `-p, --project`: Specify the project folder for logs and results (Default: `default_project`).
- `--smoke`: Run a smoke test to verify functionality.
- `--reset`: Start from scratch, moving previous logs/results to a backup directory.

## Contributing

Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

## License

[MIT](https://choosealicense.com/licenses/mit/)

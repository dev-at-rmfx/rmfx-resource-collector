from prowler.lib.cli.parser import ProwlerArgumentParser
from prowler.lib.check.models import CheckMetadata
from prowler.lib.check.compliance_models import Compliance
from prowler.lib.check.compliance import update_checks_metadata_with_compliance
from prowler.lib.check.checks_loader import load_checks_to_execute
from prowler.providers.common.provider import Provider
import importlib
import sys
from prowler.providers.common.models import Audit_Metadata
import json
from collections import deque
from pydantic import BaseModel
from datetime import datetime
from tqdm import tqdm
import os
import shutil
import os

# Define the folder you want to compress
sys.setrecursionlimit(15000)


parser = ProwlerArgumentParser()
args = parser.parse()

args.provider = 'aws'

Provider.set_global_provider(args)

# Save Arguments
provider = args.provider

# Provider to scan
Provider.init_global_provider(args)
global_provider = Provider.get_global_provider()

global_provider.audit_metadata = Audit_Metadata(
    services_scanned=0,
    expected_checks=[],
    completed_checks=0,
    audit_progress=0,
)


if provider == "dashboard":
    from dashboard import DASHBOARD_ARGS
    from dashboard.__main__ import dashboard

    sys.exit(dashboard.run(**DASHBOARD_ARGS))

checks = args.check
excluded_checks = args.excluded_check
excluded_services = args.excluded_service
services = args.service
categories = args.category
checks_file = args.checks_file
checks_folder = args.checks_folder
severities = args.severity
compliance_framework = args.compliance
custom_checks_metadata_file = args.custom_checks_metadata_file
default_execution = (
    not checks
    and not services
    and not categories
    and not excluded_checks
    and not excluded_services
    and not severities
    and not checks_file
    and not checks_folder
)


# Load checks metadata
bulk_checks_metadata = CheckMetadata.get_bulk(provider)


bulk_compliance_frameworks = {}

bulk_compliance_frameworks = Compliance.get_bulk(provider)
# Complete checks metadata with the compliance framework specification
bulk_checks_metadata = update_checks_metadata_with_compliance(
    bulk_compliance_frameworks, bulk_checks_metadata
)

# Load checks to execute
checks_to_execute = load_checks_to_execute(
    bulk_checks_metadata,
    bulk_compliance_frameworks,
    checks_file,
    checks,
    services,
    severities,
    compliance_framework,
    categories,
    provider,
)

output_folder_path = './rmfx-scan'
meta_json_file = {}

os.makedirs(output_folder_path, exist_ok=True)

# Recursive function to handle serialization
def class_to_dict(obj, seen=None):
    if seen is None:
        seen = set()

    if isinstance(obj, dict):
        new_dict = {}
        for key, value in obj.items():
            if isinstance(key, tuple):
                key = str(key)  # Convert tuple to string
            new_dict[key] = class_to_dict(value)
        return new_dict
    if isinstance(obj, datetime):
        return obj.isoformat()
    elif isinstance(obj, deque):
        return list(class_to_dict(item, seen) for item in obj)
    elif isinstance(obj, BaseModel):
        return obj.dict()
    elif isinstance(obj, (list, tuple)):
        return [class_to_dict(item, seen) for item in obj]
    elif hasattr(obj, "__dict__") and id(obj) not in seen:
        seen.add(id(obj))
        return {key: class_to_dict(value, seen) for key, value in obj.__dict__.items()}
    else:
        return obj
        
service_set = set()

for check_name in tqdm(checks_to_execute):
    try:
        service = check_name.split("_")[0]
        
        if service in service_set:
            continue
        
        service_set.add(service)

        service_path = f'./prowler/providers/aws/services/{service}'

        # List to store all _client filenames
        client_files = []

        # Walk through the directory and find all files
        for root, dirs, files in os.walk(service_path):
            for file in files:
                if file.endswith('_client.py'):
                    # Append only the filename to the list (not the full path)
                    client_files.append(file)

        service_output_folder = f'{output_folder_path}/{service}'
        
        os.makedirs(service_output_folder, exist_ok=True)
            
        for service_client in client_files:
            
            service_client = service_client.split('.py')[0]
            check_module_path = f"prowler.providers.aws.services.{service}.{service_client}"

            try:
                lib = importlib.import_module(f"{check_module_path}")
            except ModuleNotFoundError as e:
                print(f"Module not found: {check_module_path}")
                break
            except Exception as e:
                print(f"Error while importing module {check_module_path}: {e}")
                break
            
            client_path = getattr(lib, f"{service_client}")
            
            if not meta_json_file.get(f'{service}'):
                meta_json_file[f'{service}'] = []

            # Convert to JSON
            output_file = service_client.split('_client')[0]
            
            meta_json_file[f'{service}'].append(f'./{service}/{output_file}_output.json')
            
            with open(f'{service_output_folder}/{output_file}_output.json', 'w+') as fp:
                output = client_path.__to_dict__()
                json.dump(output,fp=fp, default=str, indent=4)

    except Exception as e:
        print("Exception: ", e)



with open(f'{output_folder_path}/output_metadata.json', 'w+') as fp:
    json.dump(meta_json_file,fp=fp, default=str, indent=4)

# end of all things
folder_to_compress = f'{output_folder_path}'
output_zip_file = f'{output_folder_path}/rmfx-scan-compressed'  # The output file (without extension)

# Compress the folder into a zip file
shutil.make_archive(f'{output_zip_file}', 'zip', folder_to_compress)
# rmfx-resource-collector

The `rmfx-resource-collector` is a tool designed to scan cloud infrastructure resources (AWS, GCP, etc.) and generate a report of all resources found. This tool supports multiple cloud providers, but the following instructions are specific to AWS.

## Cloud Provider Setup

### AWS

To scan AWS resources, follow these steps:

1. **Retrieve AWS Credentials:**
   - Ensure you have your `aws_access_key_id`, `aws_secret_access_key`, and `aws_session_token`. These are required to access your AWS account.

2. **Configure AWS Credentials:**
   - Create a credentials file to provide access to AWS resources:
     1. Navigate to your home directory:
   
        ```bash
        cd ~
        ```

     2. Create or update the AWS credentials file at `~/.aws/credentials`:

        ```bash
        nano ~/.aws/credentials
        ```

     3. Save your AWS credentials in the following format:

        ```
        [default]
        aws_access_key_id=YOUR_ACCESS_KEY_ID
        aws_secret_access_key=YOUR_SECRET_ACCESS_KEY
        aws_session_token=YOUR_SESSION_TOKEN
        ```

## Running the Tool

1. **Navigate to the Tool Folder:**
   - Change to the `rmfx-resource-collector` directory:
   
     ```bash
     cd rmfx-resource-collector
     ```

2. **Run the AWS Service Scanner:**
   - Execute the scanner script for AWS:
   
     ```bash
     python rmfx_aws_service_scanner.py
     ```

   This will generate a folder called `rmfx-scan` and a zip file containing all scanned AWS resources, named `rmfx-scan-compressed.zip`.

3. **Upload the Scan Results:**
   - Once the folder and zip file are generated, upload the `rmfx-scan` folder to the Sources UI of your cloud management interface.

## Additional Cloud Providers

Support for additional cloud providers (e.g., GCP, Azure) will be documented here in future updates.

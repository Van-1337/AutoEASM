## Docker using

1. Go to the docker directory: `cd Docker`
2. *\[Optional\]* Specify available API keys to provider-config.yaml file. We advice specify at least securitytrails key. For example:
```
securitytrails:
  - AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
```
3. Build the docker container (use sudo on linux):
`docker build --no-cache -t easm-automate .`
4. Run the docker using the command below. If there will be a question about access to host files - allow this (it is required to copy the report to the host). If the container does not start after that - execute the command again.

**Windows:**  
`docker run --rm -it -v %cd%\Report:/app/output -v %cd%\provider-config.yaml:/root/.config/subfinder/provider-config.yaml -e LeakIX_API_key="CHANGEME" easm-automate -d domain.com`

**Linux:**  
`sudo docker run --rm -it -v "$(pwd)/Report":/app/output -v "$(pwd)/provider-config.yaml":/root/.config/subfinder/provider-config.yaml -e LeakIX_API_key="CHANGEME" easm-automate -d domain.com`

**Windows file scan:**  
`docker run --rm -it -v %cd%\Report:/app/output -v %cd%\provider-config.yaml:/root/.config/subfinder/provider-config.yaml -v %cd%:/src -e LeakIX_API_key="CHANGEME" easm-automate -f domains.txt`

**Linux file scan:**  
`sudo docker run --rm -it -v "$(pwd)/Report":/app/output -v "$(pwd)/provider-config.yaml":/root/.config/subfinder/provider-config.yaml -v "$(pwd):/src" -e LeakIX_API_key="CHANGEME" easm-automate -f domains.txt`

Parameter `-e LeakIX_API_key="CHANGEME"` can be deleted if you don't have a leakIX key.

### Qualys WAS integration (`-q`)

To push discovered live web services into Qualys WAS, add the `-q` flag and pass the Qualys settings as `-e` environment variables. See the main [README](../README.md#qualys-was-integration--q) for the full list of `QUALYS_*` / `SMTP_*` variables and what the flag does.

**Windows:**  
`docker run --rm -it -v %cd%\Report:/app/output -v %cd%\provider-config.yaml:/root/.config/subfinder/provider-config.yaml -v %cd%:/src -e QUALYS_API_URL="https://qualysapi.qualys.com" -e QUALYS_USERNAME="user" -e QUALYS_PASSWORD="pass" easm-automate -d domain.com -q`

**Linux:**  
`sudo docker run --rm -it -v "$(pwd)/Report":/app/output -v "$(pwd)/provider-config.yaml":/root/.config/subfinder/provider-config.yaml -v "$(pwd):/src" -e QUALYS_API_URL="https://qualysapi.qualys.com" -e QUALYS_USERNAME="user" -e QUALYS_PASSWORD="pass" easm-automate -d domain.com -q`

Add further parameters as needed, e.g. `-e QUALYS_SCHEDULE_RECIPIENTS="you@example.com"`, `-e SMTP_HOST="smtp.example.com"`, or for AWS SSM credentials `-e QUALYS_SSM_USER_PARAM=... -e QUALYS_SSM_PASSWORD_PARAM=... -e AWS_REGION=...` (the container then also needs `boto3` and AWS credentials).

**Excluding hosts in Docker:** either pass `-e QUALYS_IGNORE_HOSTS="dev.example.com,*.staging.example.com"`, or place a `qualys_exclude.txt` file in the directory you mount to `/src` (with `-v %cd%:/src`) — the container auto-detects `/src/qualys_exclude.txt`.
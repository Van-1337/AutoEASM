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
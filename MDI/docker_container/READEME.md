INSTALL SQUID PROXY
-------------------
https://github.com/thelebster/docker-squid-simple-proxy/tree/master

sudo apt-get install squid apache2-utils
sudo htpasswd -c /etc/squid/passwords [USERNAME]

Test the password store
/usr/lib/squid3/basic_ncsa_auth /etc/squid/passwords


# BUILD USING DOCKER
```console
docker build -t digitalkali/squid-proxy .
```
```console
docker push digitalkali/squid-proxy
```

# RUN IN DOCKER
```console
docker run -d --name squid-container -e TZ=UTC -p 3128:3128 digitalkali/squid-proxy
```

# RUN IN AZURE CONTAINER INSTANCE
```console
az container create --resource-group MIR --location eastus2 --name squid-proxy-container --image digitalkali/squid-proxy:latest --cpu 1 --memory 2 --vnet ZoADLab-VNET --subnet ContainerNet --ports 3128 --environment-variables http_proxy="http://localhost:3128" https_proxy="http://localhost:3128"
```

![image](https://github.com/user-attachments/assets/d003f1b4-bf1f-4033-a589-fbe7f33ee968)

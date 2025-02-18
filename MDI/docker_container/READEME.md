INSTALL SQUID PROXY
-------------------
https://github.com/thelebster/docker-squid-simple-proxy/tree/master

sudo apt-get install squid apache2-utils
sudo htpasswd -c /etc/squid/passwords [USERNAME]

Test the password store
/usr/lib/squid3/basic_ncsa_auth /etc/squid/passwords


# BUILD & RUN IN DOCKER
docker build -t digitalkali/squid-proxy .
docker push digitalkali/squid-proxy

# RUN IN DOCKER
docker run -d --name squid-container -e TZ=UTC -p 3128:3128 digitalkali/squid-proxy

# RUN IN AZURE CONTAINER INSTANCE
az container create --resource-group MIR --location eastus2 --name squid-proxy-container --image digitalkali/squid-proxy:latest --cpu 1 --memory 2 --vnet ZoADLab-VNET --subnet ContainerNet --ports 3128 --environment-variables http_proxy="http://localhost:3128" https_proxy="http://localhost:3128"

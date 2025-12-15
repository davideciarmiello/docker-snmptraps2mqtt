#docker buildx create --name mbuilder
#docker buildx use mbuilder
#docker login -u username -p password

docker buildx build \
--push \
--platform linux/arm/v7,linux/arm64/v8,linux/amd64 \
--tag davideciarmi/snmptraps2mqtt \
.

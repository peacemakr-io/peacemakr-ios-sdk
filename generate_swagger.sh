docker run --rm -v ${PWD}:/local swaggerapi/swagger-codegen-cli validate \
    -i /local/Resources/peacemakr-services.yml

docker run --rm -v ${PWD}:/local swaggerapi/swagger-codegen-cli generate \
    -i /local/Resources/peacemakr-services.yml \
    -l swift4 \
    -o /local/Generated

# find ./Generated -type f | xargs sed -i.bak "s/.urlPathAllowed/.urlHostAllowed/g"

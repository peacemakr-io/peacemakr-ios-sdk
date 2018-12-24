docker run --rm -v ${PWD}:/local swaggerapi/swagger-codegen-cli validate \
    -i /local/Resources/peacemakr-services.yml

docker run --rm -v ${PWD}:/local swaggerapi/swagger-codegen-cli generate \
    -i /local/Resources/peacemakr-services.yml \
    -l swift3 \
    -o /local/Generated
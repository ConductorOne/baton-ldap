FROM gcr.io/distroless/static-debian11:nonroot
ENTRYPOINT ["/baton-ldap"]
COPY baton-ldap /
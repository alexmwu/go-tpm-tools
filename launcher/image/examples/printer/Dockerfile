FROM golang:1.19
WORKDIR /bin
COPY printer.go /bin
RUN go build printer.go
ENTRYPOINT ["/bin/printer"]
CMD []
LABEL tee.launch_policy.allow_env_override="foo,bar"
LABEL tee.launch_policy.allow_cmd_override="true"
LABEL tee.launch_policy.log_redirect="always"

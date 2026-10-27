set dotenv-load

genbloom input:
    go run ./cmd/bloomgen -in "{{input}}" -out "{{env_var('BLOOM_PATH')}}"
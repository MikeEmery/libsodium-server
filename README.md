# libsodium-server

## What is it?

It's a golang program that communicates over `stdin`/`stdout` with a protobuf defined message
format and exposes libsodium operations for sealed boxes and digital signatures.

## But... why?

This was written as a solution to deal with an environment where I couldn't statically nor
dynamically link to libsodium, but I could spawn child processes.

## Using it

1. Compile your own version of libsodium (you shouldn't trust me to do something like that)
1. copy your platform `libsodium.a` file to the project root directory
1. `go run libsodium-server`
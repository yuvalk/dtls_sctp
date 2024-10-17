how to run:
------------
1. First, you'll need to generate SSL certificates:
```
openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout server.key -out server.crt
```
2. Compile the program:
```
gcc -o dtls_sctp_example dtls_sctp_example.c -lssl -lcrypto -Wall
```
3. Run the server:
```
./dtls_sctp_example -s 127.0.0.1
```
4. Run the client:
```
./dtls_sctp_example -c 127.0.0.1
```

prerequisite:
--------------
```
sudo apt-get install libsctp-dev
sudo dnf install kernel-modules-extra
sudo modprobe sctp
```


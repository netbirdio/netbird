### How to run

This will only work on Linux

1. Run netcat listening on the UDP port 51820. This is going to be our external process:
```bash
nc -kluvw 1 51820
```

2. Build and run the example Go code:

```bash
 go build -o sharedsock && sudo ./sharedsock
```

3. Test the logic by sending a STUN binding request

```bash
STUN_PACKET="000100002112A4425454" 
echo -n $STUN_PACKET | xxd -r -p | nc -u -w 1 localhost 51820
```

4. You should see a similar output of the Go program. Note that you'll see some binary output in the netcat server too. This is due to the fact that kernel copies packets to both processes.

```bash 
 read a STUN packet of size 18 from ...
```

5. Send a non-STUN packet

```bash
echo -n 'hello' |  nc -u -w 1 localhost 51820
```

6. The Go program won't print anything.
